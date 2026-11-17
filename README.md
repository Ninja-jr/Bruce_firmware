# Build Logs

Automated build and sync logs from the Bruce firmware (Ninja-Jr's fork) builds.

## Structure

- `logs/<branch>/<timestamp>/full/` — complete `platformio run` output per board
- `logs/<branch>/<timestamp>/issues/` — filtered errors and warnings only
- `sync/<timestamp>.log` — per-run transcript of the dev/main sync with upstream

Each timestamp is a single workflow run. Old entries can be pruned freely; only the latest matters for debugging.

## Retention

- `sync/` logs older than 30 days are pruned automatically on each sync run.
- `logs/` entries are not pruned automatically and can be cleaned up manually.

## Notes

- Binary artifacts are not stored here — they live in the workflow's Artifacts section.
