#!/usr/bin/env bash
# benchora.sh — benchmark orchestrator launcher
#
# Usage:
#   benchora.sh <aegis_iq_path>                  # Interactive mode
#   benchora.sh <aegis_iq_path> --auto           # Full automated pipeline
#   benchora.sh <aegis_iq_path> --score-only     # Score all runs, stop
#   benchora.sh <aegis_iq_path> --compare-only   # Compare already-scored runs

set -euo pipefail

AEGIS_IQ="${1:?Usage: benchora.sh <path/to/AEGIS_IQ> [--auto|--score-only|--compare-only]}"
MODE="${2:---interactive}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHORA_ROOT="${SCRIPT_DIR}"
SESSION="benchora"

# Validate AEGIS_IQ path
[[ -d "$AEGIS_IQ" ]]           || { echo "ERROR: AEGIS_IQ not found: $AEGIS_IQ"; exit 1; }
[[ -d "$AEGIS_IQ/runs" ]]     || { echo "ERROR: No runs/ in AEGIS_IQ"; exit 1; }
[[ -d "$AEGIS_IQ/config" ]]   || { echo "ERROR: No config/ in AEGIS_IQ"; exit 1; }

# Count runs
RUN_COUNT=$(ls -d "$AEGIS_IQ/runs/"*/ 2>/dev/null | wc -l)
echo "AEGIS_IQ: $AEGIS_IQ"
echo "Runs found: $RUN_COUNT"

# Detect models
MODELS=$(python3 -c "
import json, os, glob
models = set()
for mf in glob.glob(os.path.join('$AEGIS_IQ', 'runs', '*', 'manifest.json')):
    with open(mf) as f:
        m = json.load(f)
    models.add(m.get('model', 'unknown'))
print(', '.join(sorted(models)))
" 2>/dev/null || echo "unknown")
echo "Models: $MODELS"
echo ""

# Prerequisites
command -v tmux  >/dev/null 2>&1 || { echo "ERROR: tmux required"; exit 1; }
command -v claude >/dev/null 2>&1 || { echo "ERROR: claude CLI required"; exit 1; }

# Kill existing session if present
if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "Existing benchora session found. Attaching..."
    exec tmux attach -t "$SESSION"
fi

# Create tmux session with benchora windows
tmux new-session -d -s "$SESSION" -n control  -c "$BENCHORA_ROOT"
tmux new-window     -t "$SESSION" -n scorer   -c "$BENCHORA_ROOT"
tmux new-window     -t "$SESSION" -n compare  -c "$BENCHORA_ROOT"
tmux new-window     -t "$SESSION" -n report   -c "$BENCHORA_ROOT"

# Set AEGIS_IQ path in session env so all claude sessions see it
tmux set-environment -t "$SESSION" BENCHORA_AEGIS_IQ "$AEGIS_IQ"
tmux set-environment -t "$SESSION" BENCHORA_ROOT "$BENCHORA_ROOT"

# Status bar
tmux set-option -t "$SESSION" status-left "[benchora | runs=${RUN_COUNT}] "
tmux set-option -t "$SESSION" status-left-length 50

case "$MODE" in
    --interactive)
        tmux send-keys -t "${SESSION}:control" \
            "export BENCHORA_AEGIS_IQ='${AEGIS_IQ}' && claude" C-m
        ;;
    --auto)
        tmux send-keys -t "${SESSION}:scorer" \
            "export BENCHORA_AEGIS_IQ='${AEGIS_IQ}' && claude -p '/score-batch'" C-m
        ;;
    --score-only)
        tmux send-keys -t "${SESSION}:scorer" \
            "export BENCHORA_AEGIS_IQ='${AEGIS_IQ}' && claude -p '/score-batch'" C-m
        ;;
    --compare-only)
        tmux send-keys -t "${SESSION}:compare" \
            "export BENCHORA_AEGIS_IQ='${AEGIS_IQ}' && claude -p '/compare'" C-m
        ;;
esac

tmux select-window -t "${SESSION}:0"
echo "Benchora session ready. Attaching..."
echo "Windows: 0:control  1:scorer  2:compare  3:report"
echo ""
echo "Available skills:"
echo "  /score-run      — Score a single run"
echo "  /score-batch    — Score all runs in AEGIS_IQ"
echo "  /compare        — Cross-model comparison"
echo "  /report         — Generate HTML comparison report"
echo "  /full-pipeline  — End-to-end (score → compare → report)"
echo "  /ground-truth   — Build/manage ground truth"
exec tmux attach -t "$SESSION"
