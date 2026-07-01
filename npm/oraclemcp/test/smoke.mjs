import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));

assert.equal(pkg.name, 'oraclemcp');
assert.equal(pkg.private, undefined);
assert.equal(pkg.publishConfig.provenance, true);
assert.deepEqual(pkg.bin, {
  oraclemcp: 'bin/oraclemcp.js',
  om: 'bin/oraclemcp.js',
});

for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
  assert.equal(pkg.scripts?.[lifecycle], undefined, `${lifecycle} must not mutate user machines`);
}

const wrapper = readFileSync(path.join(root, 'bin/oraclemcp.js'), 'utf8');
for (const needle of [
  '.sha256',
  '.sig',
  '.crt',
  '.attestation.sigstore.json',
  'verify-blob',
  'verify-blob-attestation',
  'sha256',
]) {
  assert.match(wrapper, new RegExp(needle.replace(/[.]/g, '\\.')));
}
assert.doesNotMatch(wrapper, /service install|clients issue/);

process.env.ORACLEMCP_NPM_RELEASE = '9.9.9-test.1';
process.env.ORACLEMCP_NPM_CACHE = path.join(root, '.dry-run-cache');
const { buildPlan } = require('../bin/oraclemcp.js');
const plan = buildPlan();
assert.equal(plan.package, 'oraclemcp');
assert.equal(plan.release, '9.9.9-test.1');
assert.match(plan.asset, /^oraclemcp-.+\.(tar\.gz|zip)$/);
assert.match(plan.archiveUrl, /github\.com\/MuhDur\/oraclemcp\/releases\/download\/v9\.9\.9-test\.1\/oraclemcp-/);
assert.equal(plan.serviceMutation, false);
assert.equal(plan.clientCredentialMutation, false);
assert.deepEqual(plan.verification, ['sha256', 'cosign verify-blob', 'cosign verify-blob-attestation']);
