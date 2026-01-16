#!/bin/bash
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GRIDS_DIR="$ROOT/grids"

echo "=============================================="
echo " INIT AUDIT GRIDS — STRUCTURATION CANONIQUE"
echo "=============================================="
echo "Root: $ROOT"
echo "Grids: $GRIDS_DIR"
echo

mkdir -p "$GRIDS_DIR"

# ------------------------------------------------
# Nettoyage contrôlé (uniquement les grilles cibles)
# ------------------------------------------------
echo "[INFO] Nettoyage des anciennes grilles (si présentes)…"
rm -f \
  "$GRIDS_DIR/audit_server_v1.yaml" \
  "$GRIDS_DIR/audit_web_security_v1.yaml" \
  "$GRIDS_DIR/audit_wordpress_v1.yaml" \
  "$GRIDS_DIR/audit_performance_resilience_v1.yaml"

# ------------------------------------------------
# 1. Audit Serveur & Infrastructure
# ------------------------------------------------
cat > "$GRIDS_DIR/audit_server_v1.yaml" <<'EOF'
meta:
  name: Audit Serveur & Infrastructure
  version: 1.0
  scope: vps_dedicated
  requires_root: true

facts_required:
  system:
    os_name: required
    os_version: required
    uptime_hours: required
    cpu_load_15m: required
    ram_free_percent: required
    disk_used_percent: required

  security_infra:
    firewall_present: required
    fail2ban_present: optional
    ssh_root_login: required
    open_ports: required

  resilience:
    backups_present: required
    backups_location: optional     # same_disk / external / unknown
    snapshots_present: optional
    cron_system_active: optional

  logs:
    syslog_errors_recent: optional
    web_5xx_recent: optional

out_of_scope:
  - wordpress
  - php_version
  - database_analysis
EOF

# ------------------------------------------------
# 2. Audit Sécurité Web
# ------------------------------------------------
cat > "$GRIDS_DIR/audit_web_security_v1.yaml" <<'EOF'
meta:
  name: Audit Sécurité Web
  version: 1.0
  scope: web_application
  requires_root: false

facts_required:
  ssl:
    certificate_present: required
    certificate_expiry_days: required
    https_forced: required

  filesystem:
    web_root_permissions: required     # 755/644 attendu
    wp_config_permissions: optional

  headers:
    security_headers_present: optional

  malware:
    suspicious_files_detected: optional

out_of_scope:
  - server_firewall
  - wordpress_plugins
  - performance_metrics
EOF

# ------------------------------------------------
# 3. Audit WordPress
# ------------------------------------------------
cat > "$GRIDS_DIR/audit_wordpress_v1.yaml" <<'EOF'
meta:
  name: Audit WordPress
  version: 1.0
  scope: wordpress_only
  requires_root: false

facts_required:
  wordpress:
    core_version: required
    core_eol: required
    auto_updates_enabled: optional

  plugins:
    total_plugins: required
    outdated_plugins: required
    abandoned_plugins: optional

  users:
    admin_count: required
    dormant_admins: optional
    unknown_admins: optional

  database:
    db_size_mb: required
    orphan_tables_detected: optional

  cron:
    wp_cron_active: required

out_of_scope:
  - os
  - firewall
  - ssl_certificate
EOF

# ------------------------------------------------
# 4. Audit Performance & Résilience Avancée
# ------------------------------------------------
cat > "$GRIDS_DIR/audit_performance_resilience_v1.yaml" <<'EOF'
meta:
  name: Audit Performance & Résilience
  version: 1.0
  scope: advanced
  requires_root: true

facts_required:
  stack:
    php_version: required
    php_eol: required
    mysql_version: required
    mysql_eol: optional
    opcache_enabled: optional
    redis_enabled: optional

  performance:
    response_time_ms: optional
    slow_queries_detected: optional
    cpu_spikes_detected: optional

  backups:
    backups_externalized: required
    backup_retention_days: optional
    restore_tested: optional

  deployment:
    rollback_available: required   # snapshot / blue-green / none

out_of_scope:
  - wordpress_content_quality
EOF

# ------------------------------------------------
# Résumé
# ------------------------------------------------
echo
echo "[OK] Grilles d’audit initialisées :"
ls -1 "$GRIDS_DIR"/audit_*_v1.yaml

echo
echo "=============================================="
echo " STRUCTURATION TERMINÉE"
echo "=============================================="
