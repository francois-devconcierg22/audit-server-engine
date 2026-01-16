#!/usr/bin/env bash
set -u

OUT_DIR="facts"
OUT_FILE="$OUT_DIR/facts_all.json"
mkdir -p "$OUT_DIR"

NM="non_mesurable"

json_bool() {
  if [ "$1" = "true" ] || [ "$1" = "false" ]; then
    echo "$1"
  else
    echo "\"$NM\""
  fi
}

json_str() {
  if [ -n "$1" ]; then
    echo "\"$1\""
  else
    echo "\"$NM\""
  fi
}

json_int() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "$1"
  else
    echo "\"$NM\""
  fi
}

# ============================================================
# SYSTEM
# ============================================================
os_name="$NM"
os_version="$NM"
[ -f /etc/os-release ] && . /etc/os-release && os_name="${ID:-$NM}" && os_version="${VERSION_ID:-$NM}"

uptime_hours="$NM"
[ -r /proc/uptime ] && uptime_hours=$(awk '{print int($1/3600)}' /proc/uptime)

cpu_load_15m="$NM"
[ -r /proc/loadavg ] && cpu_load_15m=$(awk '{print $3}' /proc/loadavg)

ram_free_percent="$NM"
command -v free >/dev/null && ram_free_percent=$(free | awk '/Mem:/ {printf "%d", ($4/$2)*100}')

disk_used_percent="$NM"
command -v df >/dev/null && disk_used_percent=$(df / | awk 'NR==2 {gsub("%","",$5); print $5}')

# ============================================================
# SECURITY INFRA
# ============================================================
firewall_present="$NM"
command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi active && firewall_present=true || firewall_present=false

fail2ban_present="$NM"
command -v fail2ban-client >/dev/null && fail2ban_present=true

ssh_root_login="$NM"
[ -r /etc/ssh/sshd_config ] && grep -Eq '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config && ssh_root_login=true || ssh_root_login=false

open_ports="$NM"
if command -v ss >/dev/null && command -v jq >/dev/null; then
  open_ports=$(ss -ltn | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -n | uniq | jq -R . | jq -s .)
fi

# ============================================================
# RESILIENCE
# ============================================================
backups_present="$NM"
[ -d /var/backups ] && backups_present=true

backups_location="$NM"
snapshots_present="$NM"

cron_system_active="$NM"
command -v crontab >/dev/null && cron_system_active=true

# ============================================================
# LOGS
# ============================================================
syslog_errors_recent="$NM"
[ -r /var/log/syslog ] && syslog_errors_recent=$(grep -i error /var/log/syslog | tail -n 200 | wc -l)

web_5xx_recent="$NM"
[ -d /var/log/nginx ] && web_5xx_recent=$(grep -R " 5[0-9][0-9] " /var/log/nginx 2>/dev/null | tail -n 200 | wc -l)

# ============================================================
# WEB SECURITY
# ============================================================
ssl_certificate_present="$NM"
ssl_certificate_expiry_days="$NM"
https_forced="$NM"

if command -v openssl >/dev/null; then
  cert=$(echo | openssl s_client -servername localhost -connect localhost:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
  if echo "$cert" | grep -q notAfter; then
    ssl_certificate_present=true
    expiry=$(echo "$cert" | grep notAfter | cut -d= -f2)
    ssl_certificate_expiry_days=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
  fi
fi

web_root_permissions="$NM"
[ -d /var/www ] && web_root_permissions=$(stat -c "%a" /var/www | head -n1)

wp_config_permissions="$NM"
wp_cfg=$(find /var/www -name wp-config.php 2>/dev/null | head -n1)
[ -n "$wp_cfg" ] && wp_config_permissions=$(stat -c "%a" "$wp_cfg")

suspicious_files_detected="$NM"

# ============================================================
# WORDPRESS
# ============================================================
wp_core_version="$NM"
wp_core_eol="$NM"
wp_auto_updates="$NM"
wp_total_plugins="$NM"
wp_outdated_plugins="$NM"
wp_abandoned_plugins="$NM"
wp_admin_count="$NM"
wp_dormant_admins="$NM"
wp_unknown_admins="$NM"
wp_db_size="$NM"
wp_orphan_tables="$NM"
wp_cron_active="$NM"

# (WP-CLI non forcé ici – volontairement neutre)

# ============================================================
# STACK / PERFORMANCE
# ============================================================
php_version="$NM"
command -v php >/dev/null && php_version=$(php -r 'echo PHP_VERSION;')

php_eol="$NM"
mysql_version="$NM"
command -v mysql >/dev/null && mysql_version=$(mysql --version | awk '{print $5}' | tr -d ',')

opcache_enabled="$NM"
redis_enabled="$NM"

response_time_ms="$NM"
slow_queries_detected="$NM"
cpu_spikes_detected="$NM"

rollback_available="$NM"

# ============================================================
# OUTPUT JSON (100 % VALIDE)
# ============================================================
cat > "$OUT_FILE" <<EOF
{
  "system": {
    "os_name": $(json_str "$os_name"),
    "os_version": $(json_str "$os_version"),
    "uptime_hours": $(json_int "$uptime_hours"),
    "cpu_load_15m": $(json_int "$cpu_load_15m"),
    "ram_free_percent": $(json_int "$ram_free_percent"),
    "disk_used_percent": $(json_int "$disk_used_percent")
  },
  "security_infra": {
    "firewall_present": $(json_bool "$firewall_present"),
    "fail2ban_present": $(json_bool "$fail2ban_present"),
    "ssh_root_login": $(json_bool "$ssh_root_login"),
    "open_ports": ${open_ports:-"\"$NM\""}
  },
  "resilience": {
    "backups_present": $(json_bool "$backups_present"),
    "backups_location": $(json_str "$backups_location"),
    "snapshots_present": $(json_str "$snapshots_present"),
    "cron_system_active": $(json_bool "$cron_system_active")
  },
  "logs": {
    "syslog_errors_recent": $(json_int "$syslog_errors_recent"),
    "web_5xx_recent": $(json_int "$web_5xx_recent")
  },
  "web_security": {
    "ssl_certificate_present": $(json_bool "$ssl_certificate_present"),
    "ssl_certificate_expiry_days": $(json_int "$ssl_certificate_expiry_days"),
    "https_forced": $(json_bool "$https_forced"),
    "web_root_permissions": $(json_str "$web_root_permissions"),
    "wp_config_permissions": $(json_str "$wp_config_permissions"),
    "suspicious_files_detected": $(json_bool "$suspicious_files_detected")
  },
  "wordpress": {
    "core_version": $(json_str "$wp_core_version"),
    "core_eol": $(json_bool "$wp_core_eol"),
    "auto_updates_enabled": $(json_bool "$wp_auto_updates"),
    "total_plugins": $(json_int "$wp_total_plugins"),
    "outdated_plugins": $(json_int "$wp_outdated_plugins"),
    "abandoned_plugins": $(json_int "$wp_abandoned_plugins"),
    "admin_count": $(json_int "$wp_admin_count"),
    "dormant_admins": $(json_int "$wp_dormant_admins"),
    "unknown_admins": $(json_int "$wp_unknown_admins"),
    "db_size_mb": $(json_int "$wp_db_size"),
    "orphan_tables_detected": $(json_bool "$wp_orphan_tables"),
    "wp_cron_active": $(json_bool "$wp_cron_active")
  },
  "stack": {
    "php_version": $(json_str "$php_version"),
    "php_eol": $(json_bool "$php_eol"),
    "mysql_version": $(json_str "$mysql_version"),
    "mysql_eol": $(json_bool "$NM"),
    "opcache_enabled": $(json_bool "$opcache_enabled"),
    "redis_enabled": $(json_bool "$redis_enabled")
  },
  "performance": {
    "response_time_ms": $(json_int "$response_time_ms"),
    "slow_queries_detected": $(json_bool "$slow_queries_detected"),
    "cpu_spikes_detected": $(json_bool "$cpu_spikes_detected")
  },
  "deployment": {
    "rollback_available": $(json_str "$rollback_available")
  }
}
EOF

echo "[OK] facts_all.json généré : $OUT_FILE"
