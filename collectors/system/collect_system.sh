#!/usr/bin/env bash
set -e

OUT_DIR="facts"
OUT_FILE="$OUT_DIR/facts_system.json"

mkdir -p "$OUT_DIR"

non_mesurable="non_mesurable"

# ----------------------------
# SYSTEM
# ----------------------------
os_name="$non_mesurable"
os_version="$non_mesurable"

if [ -f /etc/os-release ]; then
  . /etc/os-release
  os_name="${ID:-$non_mesurable}"
  os_version="${VERSION_ID:-$non_mesurable}"
fi

uptime_hours="$non_mesurable"
if [ -r /proc/uptime ]; then
  uptime_hours=$(awk '{print int($1/3600)}' /proc/uptime)
fi

cpu_load_15m="$non_mesurable"
if [ -r /proc/loadavg ]; then
  cpu_load_15m=$(awk '{print $3}' /proc/loadavg)
fi

ram_free_percent="$non_mesurable"
if command -v free >/dev/null 2>&1; then
  ram_free_percent=$(free | awk '/Mem:/ {printf "%d", ($4/$2)*100}')
fi

disk_used_percent="$non_mesurable"
if command -v df >/dev/null 2>&1; then
  disk_used_percent=$(df / | awk 'NR==2 {gsub("%","",$5); print $5}')
fi

# ----------------------------
# SECURITY INFRA
# ----------------------------
firewall_present="$non_mesurable"
if command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -qi active; then
    firewall_present=true
  else
    firewall_present=false
  fi
fi

fail2ban_present="$non_mesurable"
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban_present=true
fi

ssh_root_login="$non_mesurable"
if [ -r /etc/ssh/sshd_config ]; then
  if grep -Eq '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config; then
    ssh_root_login=true
  else
    ssh_root_login=false
  fi
fi

open_ports="$non_mesurable"
if command -v ss >/dev/null 2>&1; then
  open_ports=$(ss -ltn | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -n | uniq | jq -R . | jq -s .)
fi

# ----------------------------
# RESILIENCE
# ----------------------------
backups_present="$non_mesurable"
if [ -d /var/backups ]; then
  backups_present=true
fi

backups_location="$non_mesurable"
snapshots_present="$non_mesurable"

cron_system_active="$non_mesurable"
if command -v crontab >/dev/null 2>&1; then
  cron_system_active=true
fi

# ----------------------------
# LOGS
# ----------------------------
syslog_errors_recent="$non_mesurable"
if [ -r /var/log/syslog ]; then
  syslog_errors_recent=$(grep -i error /var/log/syslog | tail -n 100 | wc -l)
fi

web_5xx_recent="$non_mesurable"
if [ -d /var/log/nginx ]; then
  web_5xx_recent=$(grep -R " 5[0-9][0-9] " /var/log/nginx 2>/dev/null | tail -n 100 | wc -l)
fi

# ----------------------------
# OUTPUT JSON (STRICT)
# ----------------------------
cat > "$OUT_FILE" <<EOF
{
  "system": {
    "os_name": "$os_name",
    "os_version": "$os_version",
    "uptime_hours": $uptime_hours,
    "cpu_load_15m": $cpu_load_15m,
    "ram_free_percent": $ram_free_percent,
    "disk_used_percent": $disk_used_percent
  },
  "security_infra": {
    "firewall_present": $firewall_present,
    "fail2ban_present": $fail2ban_present,
    "ssh_root_login": $ssh_root_login,
    "open_ports": ${open_ports:-"$non_mesurable"}
  },
  "resilience": {
    "backups_present": $backups_present,
    "backups_location": "$backups_location",
    "snapshots_present": $snapshots_present,
    "cron_system_active": $cron_system_active
  },
  "logs": {
    "syslog_errors_recent": $syslog_errors_recent,
    "web_5xx_recent": $web_5xx_recent
  }
}
EOF

echo "[OK] facts_system.json généré : $OUT_FILE"
