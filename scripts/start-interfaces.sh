#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFIG_PATH="${KUBECONFIG:-$ROOT_DIR/infra/kubeconfig.yaml}"
STATE_DIR="$ROOT_DIR/.tmp/port-forwards"
OPEN_BROWSER="false"

if [ "${1:-}" = "--open" ]; then
  OPEN_BROWSER="true"
fi

if [ ! -f "$KUBECONFIG_PATH" ]; then
  echo "Kubeconfig introuvable: $KUBECONFIG_PATH"
  exit 1
fi

mkdir -p "$STATE_DIR"

stop_existing() {
  if [ -f "$STATE_DIR/pids" ]; then
    while read -r pid; do
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
      fi
    done < "$STATE_DIR/pids"
  fi

  : > "$STATE_DIR/pids"
}

wait_for_port() {
  local port="$1"
  local name="$2"

  for _ in $(seq 1 20); do
    if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
      echo "$name disponible sur http://127.0.0.1:$port"
      return 0
    fi
    sleep 0.5
  done

  echo "$name pas encore joignable sur le port $port. Voir les logs dans $STATE_DIR."
}

start_forward() {
  local name="$1"
  local namespace="$2"
  local target="$3"
  local mapping="$4"
  local port="${mapping%%:*}"
  local log_file="$STATE_DIR/$name.log"

  echo "Lancement $name..."
  kubectl --kubeconfig "$KUBECONFIG_PATH" \
    port-forward -n "$namespace" "$target" "$mapping" \
    > "$log_file" 2>&1 &

  echo "$!" >> "$STATE_DIR/pids"
  wait_for_port "$port" "$name"
}

open_url() {
  local url="$1"

  if [ "$OPEN_BROWSER" = "true" ] && command -v open >/dev/null 2>&1; then
    open "$url"
  fi
}

stop_existing

start_forward "grafana" "monitoring" "svc/kube-prometheus-stack-grafana" "3001:80"
start_forward "falco-ui" "falco" "svc/falco-falcosidekick-ui" "2803:2802"
start_forward "argo-rollouts" "argo-rollouts" "svc/argo-rollouts-dashboard" "3101:3100"
start_forward "demo-app" "demo" "svc/vulnerable-web" "8080:80"

open_url "http://127.0.0.1:3001"
open_url "http://127.0.0.1:2803"
open_url "http://127.0.0.1:3101"
open_url "http://127.0.0.1:8080"

cat <<EOF

Interfaces lancees :
- Argo CD          : https://51.210.2.115
- Grafana          : http://127.0.0.1:3001
- Falco UI         : http://127.0.0.1:2803
- Argo Rollouts    : http://127.0.0.1:3101
- Application demo : http://127.0.0.1:8080

Identifiants connus :
- Grafana : admin / hackathon2026
- Falco UI: admin / admin

Pour arreter les interfaces :
  scripts/stop-interfaces.sh

EOF
