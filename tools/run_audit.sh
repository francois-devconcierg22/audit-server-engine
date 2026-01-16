#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${1:-all}"

echo "=============================================="
echo " RUN AUDIT — COLLECT + APPLY PROFILE"
echo "=============================================="

# 1) Collecte
echo "[STEP] Collecte facts (all)…"
./collectors/collect_all_facts.sh

# Sanity JSON
if command -v jq >/dev/null 2>&1; then
  jq . facts/facts_all.json >/dev/null
  echo "[OK] facts_all.json valide"
fi

# 2) Apply profile(s)
apply_one () {
  local p="$1"
  echo "[STEP] Apply profile: $p"
  python3 engine/apply_audit_profile.py --facts facts/facts_all.json --profile "$p" --outdir reports
}

if [ "$PROFILE" = "all" ]; then
  apply_one grids/audit_server_v1.yaml
  apply_one grids/audit_web_security_v1.yaml
  apply_one grids/audit_wordpress_v1.yaml
  apply_one grids/audit_performance_resilience_v1.yaml
else
  apply_one "grids/${PROFILE}_v1.yaml"
fi

echo "=============================================="
echo "[OK] Terminé — voir reports/"
echo "=============================================="
