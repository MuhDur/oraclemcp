# FREE TIER ONLY — NO COSTS. This operator-gated module must never provision a
# paid ADB shape or paid storage. Keep `is_free_tier = true` unchanged.
terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "= 8.19.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.9.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

variable "tenancy_ocid" {
  type      = string
  sensitive = true
}

variable "user_ocid" {
  type      = string
  sensitive = true
}

variable "fingerprint" {
  type      = string
  sensitive = true
}

variable "private_key_path" {
  type      = string
  sensitive = true
}

variable "region" {
  type      = string
  sensitive = true
}

variable "compartment_ocid" {
  type      = string
  sensitive = true
}

# The exact ADB version string, discovered per run from the free-tier-enabled
# entries of `oci db autonomous-db-versions list`. Required: the harness never
# lets the service pick a default version, so every result names its version.
variable "db_version" {
  type = string

  validation {
    condition     = can(regex("^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$", var.db_version))
    error_message = "db_version must be an exact OCI ADB version string."
  }
}

# The harness run id. Tagged on the ADB so ownership is provable: a run only
# ever asserts on, or tears down, the ADB carrying its own run id.
variable "run_id" {
  type = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{5,62}$", var.run_id))
    error_message = "run_id must be 6-63 lowercase alphanumerics or hyphens."
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
  numeric = true
}

# Oracle's Autonomous Database password policy requires upper, lower, and
# numeric characters; the deliberately small special-character alphabet avoids
# shell/TOML quoting ambiguity in the runtime-only harness.
resource "random_password" "admin" {
  length           = 20
  special          = true
  override_special = "!#%*+-_="
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "wallet" {
  length           = 20
  special          = true
  override_special = "!#%*+-_="
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "oci_database_autonomous_database" "signoff" {
  compartment_id              = var.compartment_ocid
  admin_password              = random_password.admin.result
  db_name                     = "OMCP${upper(random_string.suffix.result)}"
  display_name                = "oraclemcp-iam-acceptance-${random_string.suffix.result}"
  db_workload                 = "OLTP"
  db_version                  = var.db_version
  is_free_tier                = true
  is_mtls_connection_required = true
  license_model               = "LICENSE_INCLUDED"

  freeform_tags = {
    "oraclemcp-run-id" = var.run_id
  }
}

check "free_tier_only" {
  assert {
    condition     = oci_database_autonomous_database.signoff.is_free_tier == true
    error_message = "REFUSING: OCI harness is FREE TIER ONLY — no paid ADB may be provisioned"
  }
}

resource "oci_database_autonomous_database_wallet" "signoff" {
  autonomous_database_id = oci_database_autonomous_database.signoff.id
  password               = random_password.wallet.result
  base64_encode_content  = true
  generate_type          = "SINGLE"
}

output "adb_id" {
  value     = oci_database_autonomous_database.signoff.id
  sensitive = true
}

output "admin_connect_string" {
  # OCI returns the all_connection_strings map with uppercase service keys.
  # Keep the wallet-alias fallback in the harness for provider regressions, but
  # use the actual provider key here so a normal apply returns the HIGH service.
  value     = try(oci_database_autonomous_database.signoff.connection_strings[0].all_connection_strings["HIGH"], "")
  sensitive = true
}

output "admin_password" {
  value     = random_password.admin.result
  sensitive = true
}

output "wallet_base64" {
  value     = oci_database_autonomous_database_wallet.signoff.content
  sensitive = true
}

output "wallet_password" {
  value     = random_password.wallet.result
  sensitive = true
}

# A fresh database makes this fixed, scope-limited global username safe to
# create. Its mapping target is supplied only at manual-dispatch runtime.
output "iam_database_user" {
  value = "OMCP_IAM_ACCEPT"
}
