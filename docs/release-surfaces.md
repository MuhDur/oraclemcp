# Release surfaces

[`release-surfaces.toml`](../release-surfaces.toml) is the authoritative
inventory of current release-version surfaces. It declares each canonical
source, the derived documentation fields that are regenerated from it, and
intentional non-lockstep values for the independent driver/runtime trains.

Use the manifest rather than hand-editing a version inventory:

```bash
# Rewrite only generated current-state fields after a deliberate version bump.
python3 scripts/release_surface_manifest.py --write

# Verify the generated fields and independent version pins have no drift.
python3 scripts/release_surface_manifest.py --check
```

`scripts/check_release_surface_versions.sh` is the stable CI entry point for
the check command. Historical release notes and qualification evidence are
intentionally outside this generator: they record the release that happened,
not the release currently being prepared.

The manifest explicitly records two intentional non-locksteps: the pinned
nightly toolchain follows asupersync language-feature compatibility, and the
oracledb driver follows its upstream release train. Neither should move merely
because the server version changes.
