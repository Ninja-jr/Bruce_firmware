# Build Logs

Automated build logs from the Bruce firmware (Ninja-Jr's fork) builds.

## Structure

- `logs/<branch>/<timestamp>/full/` — complete `platformio run` output per board
- `logs/<branch>/<timestamp>/issues/` — filtered errors and warnings only

Each timestamp folder is a single workflow run. Old folders can be pruned freely; only the latest matters for debugging.

## Notes

- Binary artifacts are not stored here — they live in the workflow's Artifacts section (30-day retention).
- Do not edit or commit to this branch manually. It is regenerated on every build.
