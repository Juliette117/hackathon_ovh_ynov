#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$ROOT_DIR/.tmp/port-forwards"

# Le script d'arret se limite aux PID enregistres par start-interfaces.sh. Cela
# evite de tuer des processus kubectl ou port-forward lances manuellement.
if [ ! -f "$STATE_DIR/pids" ]; then
  echo "Aucune interface lancee par scripts/start-interfaces.sh."
  exit 0
fi

while read -r pid; do
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    echo "Arret du process $pid"
  fi
done < "$STATE_DIR/pids"

: > "$STATE_DIR/pids"
echo "Interfaces arretees."
