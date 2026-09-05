# old_benchora

Archive of the original **Benchora** benchmark harness plus its legacy ground-truth data.

## Layout

| Path | Contents |
|---|---|
| `benchora/` | The harness: runner, scoring/reporting scripts, config, Claude skills |
| `benchora/config/` | Model list, prices, evaluation areas, rating scale |
| `benchora/scripts/` | Ground-truth build, scoring, comparison and report rendering |
| `benchora/output/` | Run artifacts — **intentionally empty** in this repo |
| `groundtruth_old/` | Legacy ground truth: `endpoints.json`, `vulns.json` |

`benchora/output/` is tracked as an empty directory (via `.gitkeep`); all generated
run data is excluded by `.gitignore`.

## Entry points

- `benchora/run_all.py` — orchestrates a full benchmark run
- `benchora/benchora.sh` — shell wrapper
- `benchora/CLAUDE.md` — harness usage notes
