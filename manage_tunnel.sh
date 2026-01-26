#!/usr/bin/env bash
# manage_tunnel.sh
# 
# Purpose:
#   - IRAN:   migrate udp2raw -> backhaul, rollback backhaul -> udp2raw, remigrate udp2raw -> backhaul
#   - KHAREJ: apply tasks file to create backhaul clients that connect to IRAN (matching WEB_PORT)
#
# Notes:
#   - Does NOT delete udp2raw services. Only stop+disable during migration.
#   - Dedup rule: if multiple udp2raw units bind the same local port (-l ...:<LPORT>), keep the newest unit file.
#   - IRAN web_port allocation: starts from 2525 upward, ensures not listening and not already used in existing conf files.
#   - KHAREJ: WEB_PORT must match the IRAN one. If WEB_PORT already used/listening on foreign server -> WARN + SKIP.
#
# Usage examples:
#   IRAN migrate:
#     sudo ./manage_tunnel.sh --role iran --mode migrate --out /root/backhaul-foreign-tasks.txt
#     sudo ./manage_tunnel.sh --role iran --mode migrate --iran-ip 62.60.x.x --out /root/backhaul-foreign-tasks.txt
#   IRAN rollback:
#     sudo ./manage_tunnel.sh --role iran --mode rollback
#   IRAN remigrate:
#     sudo ./manage_tunnel.sh --role iran --mode remigrate
#   KHAREJ apply:
#     sudo ./manage_tunnel.sh --role kharej --mode foreign-apply --tasks /root/backhaul-foreign-tasks.txt
#
set -euo pipefail

# ===== Styling =====
cecho(){ printf "\033[1;36m%s\033[0m\n" "$*" >&2; }
gecho(){ printf "\033[1;32m%s\033[0m\n" "$*" >&2; }
recho(){ printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
yecho(){ printf "\033[1;33m%s\033[0m\n" "$*" >&2; }

# ===== Globals / Defaults =====
ROLE=""                 # iran|kharej
MODE=""                 # migrate|rollback|remigrate|foreign-apply
OUT_FILE="/root/backhaul-foreign-tasks.txt"
TASKS_FILE=""
IRAN_IP_OVERRIDE=""
FOREIGN_IP_CHECK="on"   # on|off
BACKHAUL_VERSION="v0.7.1"

BACKHAUL_BIN="/root/backhaul"
CONF_DIR="/root"
SYSTEMD_DIR="/etc/systemd/system"

# Runtime accumulators
declare -a OK FAIL WARN_SKIPS
declare -A ALLOC_WEBPORTS

# ===== Helpers =====
die(){ recho "ERROR: $*"; exit 1; }
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root (sudo)."
  fi
}

# Best-effort IPv4 detection:
# 1) Override via --iran-ip (used for both roles as "best IPv4")
# 2) External public IP services (curl/wget)
# 3) Route-based src IP (ip route get ...)
# 4) First global IPv4 from ip addr
# 5) hostname -I first IPv4
get_public_ipv4() {
  local ip=""

  # 1) explicit override
  if [ -n "${IRAN_IP_OVERRIDE}" ]; then
    printf "%s" "${IRAN_IP_OVERRIDE}"
    return 0
  fi

  # 2) true public IP via external services
  if have_cmd curl; then
    ip="$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi
    ip="$(curl -4 -fsS --max-time 4 https://ifconfig.me/ip 2>/dev/null || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi
  fi

  if have_cmd wget; then
    ip="$(wget -qO- --timeout=4 https://api.ipify.org 2>/dev/null || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi
    ip="$(wget -qO- --timeout=4 https://ifconfig.me/ip 2>/dev/null || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi
  fi

  # 3) route-based src IPv4 (works without outbound internet)
  if have_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi

    # 4) first global IPv4 address
    ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n 1 || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi
  fi

  # 5) hostname -I fallback
  ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {print; exit}' || true)"
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf "%s" "$ip"; return 0; fi

  printf "%s" ""
}

is_tcp_listening() {
  local port="$1"
  if have_cmd ss; then
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "(:|\\])${port}\$"; then
      return 0
    else
      return 1
    fi
  fi
  if have_cmd lsof; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    else
      return 1
    fi
  fi
  return 2
}

get_unit_execstart() {
  local unit="$1"
  local line=""
  line="$(systemctl cat "$unit" --no-pager 2>/dev/null | awk -F= '/^[[:space:]]*ExecStart=/ {x=$0} END{print x}' || true)"
  [ -z "$line" ] && { printf "%s" ""; return 0; }
  line="${line#*=}"
  printf "%s" "$line"
}

# Parse udp2raw ExecStart for:
# -l 0.0.0.0:LPORT
# -r FOREIGN_IP:INTER_PORT
# Outputs: LPORT|FOREIGN_IP|INTER_PORT  (or empty on failure)
parse_udp2raw_cmd() {
  local cmd="$1"
  local laddr="" lport="" foreign_ip="" inter_port=""

  if [[ "$cmd" =~ -l[[:space:]]*([^[:space:]]+) ]]; then
    laddr="${BASH_REMATCH[1]}"
    if [[ "$laddr" =~ :([0-9]{1,5})$ ]]; then
      lport="${BASH_REMATCH[1]}"
    fi
  fi

  if [[ "$cmd" =~ -r[[:space:]]*\"?([0-9]{1,3}(\.[0-9]{1,3}){3})\"?:([0-9]{1,5}) ]]; then
    foreign_ip="${BASH_REMATCH[1]}"
    inter_port="${BASH_REMATCH[3]}"
  elif [[ "$cmd" =~ -r[[:space:]]*\"?([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})\"? ]]; then
    foreign_ip="${BASH_REMATCH[1]}"
    inter_port="${BASH_REMATCH[3]}"
  fi

  if [ -z "$lport" ] || [ -z "$foreign_ip" ] || [ -z "$inter_port" ]; then
    printf "%s" ""
    return 0
  fi

  printf "%s|%s|%s" "$lport" "$foreign_ip" "$inter_port"
}

get_unit_fragment_path() {
  systemctl show -p FragmentPath --value "$1" 2>/dev/null || true
}
get_file_mtime() {
  local path="$1"
  if [ -n "$path" ] && [ -e "$path" ]; then
    stat -c %Y "$path" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

ensure_backhaul() {
  if [ -x "$BACKHAUL_BIN" ]; then
    gecho "✅ backhaul exists: $BACKHAUL_BIN"
    return 0
  fi

  cecho "backhaul not found at $BACKHAUL_BIN."
  cecho "Downloading backhaul from trusted storage..."

  #local url="https://borna.storage.c2.liara.space/temp/backhaul_linux_amd64.tar.gz"
  local url="https://github.com/Musixal/Backhaul/releases/download/v0.7.1/backhaul_linux_amd64.tar.gz"
  local tarball="/root/backhaul_linux_amd64.tar.gz"

  rm -f "$tarball" >/dev/null 2>&1 || true

  # ---- Download ----
  if have_cmd wget; then
    wget -q --timeout=20 --tries=3 -O "$tarball" "$url" \
      || die "Failed to download backhaul archive via wget."
  elif have_cmd curl; then
    curl -fL --max-time 30 -o "$tarball" "$url" \
      || die "Failed to download backhaul archive via curl."
  else
    die "Neither wget nor curl is available to download backhaul."
  fi

  # ---- Validate file ----
  if ! file "$tarball" | grep -qiE 'gzip compressed|tar archive'; then
    die "Downloaded file is not a valid tar.gz archive."
  fi

  # ---- Extract ----
  cecho "Extracting backhaul archive..."
  tar -xzf "$tarball" -C /root || die "Failed to extract backhaul archive."

  # ---- Validate binary ----
  if [ ! -f "/root/backhaul" ]; then
    die "backhaul binary not found after extraction."
  fi

  chmod +x /root/backhaul || true

  gecho "✅ backhaul installed successfully at /root/backhaul"
}



ensure_ip_forwarding() {
  local changed=0
  local v4_now v6_now
  v4_now="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
  v6_now="$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)"

  set_sysctl_conf() {
    local key="$1" value="$2" file="/etc/sysctl.conf"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
      sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|" "$file"
    else
      printf "%s=%s\n" "$key" "$value" >> "$file"
    fi
  }

  if [ "$v4_now" != "1" ]; then set_sysctl_conf "net.ipv4.ip_forward" "1"; changed=1; fi
  if [ "$v6_now" != "1" ]; then set_sysctl_conf "net.ipv6.conf.all.forwarding" "1"; changed=1; fi
  if [ "$changed" -eq 1 ]; then sysctl -p >/dev/null 2>&1 || true; fi
}

systemd_reload() { systemctl daemon-reload >/dev/null 2>&1 || true; }
svc_exists() { systemctl status "$1" >/dev/null 2>&1; }
svc_is_active() { [ "$(systemctl is-active "$1" 2>/dev/null || true)" = "active" ]; }

svc_enable_start() {
  local unit="$1"
  systemctl enable "$unit" >/dev/null 2>&1 || true
  if ! systemctl start "$unit" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

svc_stop_disable() {
  local unit="$1"
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
}

print_last_logs() {
  local unit="$1"
  yecho "---- last logs for $unit ----"
  journalctl -u "$unit" -n 80 --no-pager -l 2>/dev/null || true
  yecho "-----------------------------"
}

# ===== web_port allocation (IRAN) =====
choose_web_port() {
  local start=2525
  local port="$start"
  local used_file_glob="${CONF_DIR}/conf-*.toml"

  while :; do
    # must not be listening
    if is_tcp_listening "$port"; then port=$((port+1)); continue; fi

    # must not already be written in existing confs
    if grep -R --no-messages -nE "^[[:space:]]*web_port[[:space:]]*=[[:space:]]*${port}[[:space:]]*$" $used_file_glob >/dev/null 2>&1; then
      port=$((port+1)); continue
    fi

    # must not be allocated during this run
    if [[ -n "${ALLOC_WEBPORTS["$port"]+x}" ]]; then
      port=$((port+1)); continue
    fi

    ALLOC_WEBPORTS["$port"]=1
    printf "%s" "$port"
    return 0
  done
}

create_server_conf() {
  local lport="$1" inter_port="$2" web_port="$3"
  local conf_path="${CONF_DIR}/conf-${lport}.toml"
  cat > "$conf_path" <<EOF
[server]
bind_addr = "0.0.0.0:${inter_port}"
transport = "tcp"
accept_udp = true
token = "mehdi"
keepalive_period = 10
nodelay = true
heartbeat = 40
channel_size = 2048
sniffer = false
web_port = ${web_port}
sniffer_log = "${CONF_DIR}/backhaul.json"
log_level = "info"
ports = ["${lport}=${lport}"]
EOF
  printf "%s" "$conf_path"
}

create_client_conf() {
  local lport="$1" iran_ip="$2" inter_port="$3" web_port="$4"
  local iran_digits="${iran_ip//./}"
  local conf_path="${CONF_DIR}/conf-${lport}-${iran_digits}.toml"
  cat > "$conf_path" <<EOF
[client]
remote_addr = "${iran_ip}:${inter_port}"
transport = "tcp"
token = "mehdi"
connection_pool = 128
aggressive_pool = false
keepalive_period = 10
dial_timeout = 10
nodelay = true
retry_interval = 3
sniffer = false
web_port = ${web_port}
sniffer_log = "${CONF_DIR}/backhaul.json"
log_level = "info"
EOF
  printf "%s" "$conf_path"
}

create_service_file() {
  local svc_name="$1" conf_path="$2"
  local svc_file="${SYSTEMD_DIR}/${svc_name}.service"

  # If exists, keep it as-is (safer)
  if [ -e "$svc_file" ]; then
    printf "%s" "$svc_file"
    return 0
  fi

  cat > "$svc_file" <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=${BACKHAUL_BIN} -c ${conf_path}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  printf "%s" "$svc_file"
}

# ===== Discovery & Dedup =====
# Build SELECTED_UNITS by LPORT, keeping the newest unit file when duplicates exist.
discover_udp2raw_active_dedup() {
  cecho "Discovering ACTIVE udp2raw*.service units..."
  local units=()
  mapfile -t units < <(systemctl list-units --type=service 'udp2raw*.service' --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)

  if [ "${#units[@]}" -eq 0 ]; then
    yecho "No udp2raw*.service units found."
    return 0
  fi

  declare -gA BEST_UNIT_BY_LPORT=()
  declare -gA BEST_MTIME_BY_LPORT=()
  declare -gA META_FOREIGN_IP=()
  declare -gA META_INTER_PORT=()

  local unit exec parsed lport foreign_ip inter_port frag mtime
  for unit in "${units[@]}"; do
    if ! svc_is_active "$unit"; then
      continue
    fi

    exec="$(get_unit_execstart "$unit")"
    if [ -z "$exec" ]; then
      WARN_SKIPS+=("unit=$unit reason=NoExecStart")
      continue
    fi

    parsed="$(parse_udp2raw_cmd "$exec")"
    if [ -z "$parsed" ]; then
      WARN_SKIPS+=("unit=$unit reason=ParseFailed")
      continue
    fi

    IFS="|" read -r lport foreign_ip inter_port <<< "$parsed"
    frag="$(get_unit_fragment_path "$unit")"
    mtime="$(get_file_mtime "$frag")"

    if [ -z "${BEST_UNIT_BY_LPORT[$lport]+x}" ]; then
      BEST_UNIT_BY_LPORT["$lport"]="$unit"
      BEST_MTIME_BY_LPORT["$lport"]="$mtime"
      META_FOREIGN_IP["$lport"]="$foreign_ip"
      META_INTER_PORT["$lport"]="$inter_port"
    else
      if [ "$mtime" -ge "${BEST_MTIME_BY_LPORT[$lport]}" ]; then
        WARN_SKIPS+=("unit=${BEST_UNIT_BY_LPORT[$lport]} reason=DedupReplacedByNewer lport=$lport newer=$unit")
        BEST_UNIT_BY_LPORT["$lport"]="$unit"
        BEST_MTIME_BY_LPORT["$lport"]="$mtime"
        META_FOREIGN_IP["$lport"]="$foreign_ip"
        META_INTER_PORT["$lport"]="$inter_port"
      else
        WARN_SKIPS+=("unit=$unit reason=DedupSkippedOlder lport=$lport kept=${BEST_UNIT_BY_LPORT[$lport]}")
      fi
    fi
  done

  declare -gA SELECTED_UNITS=()
  local key
  for key in "${!BEST_UNIT_BY_LPORT[@]}"; do
    SELECTED_UNITS["$key"]="${BEST_UNIT_BY_LPORT[$key]}"
  done

  cecho "Selected ${#SELECTED_UNITS[@]} unique ACTIVE udp2raw unit(s) after dedup."
}

# ===== Modes: IRAN =====
mode_migrate_iran() {
  require_root
  ensure_backhaul
  ensure_ip_forwarding

  OK=(); FAIL=(); WARN_SKIPS=()
  ALLOC_WEBPORTS=()

  discover_udp2raw_active_dedup
  if [ "${#SELECTED_UNITS[@]}" -eq 0 ]; then
    yecho "Nothing to migrate."
    return 0
  fi

  local iran_ip
  iran_ip="$(get_public_ipv4)"
  [ -n "$iran_ip" ] || die "Could not detect IRAN IPv4. Re-run with: --iran-ip x.x.x.x"
  cecho "IRAN IPv4: ${iran_ip}"

  cecho "Writing tasks output to: ${OUT_FILE}"
  : > "${OUT_FILE}"

  systemd_reload

  local lport unit inter_port foreign_ip web_port conf_path svc_name svc_unit
  for lport in $(printf "%s\n" "${!SELECTED_UNITS[@]}" | sort -n); do
    unit="${SELECTED_UNITS[$lport]}"
    inter_port="${META_INTER_PORT[$lport]}"
    foreign_ip="${META_FOREIGN_IP[$lport]}"

    svc_name="backhaul${lport}"
    svc_unit="${svc_name}.service"

    cecho "---- MIGRATE lport=${lport} unit=${unit} foreign=${foreign_ip} inter_port=${inter_port} ----"

    web_port="$(choose_web_port)"
    if [ -z "$web_port" ]; then
      FAIL+=("lport=$lport unit=$unit reason=WebPortAllocationFailed")
      continue
    fi

    conf_path="$(create_server_conf "$lport" "$inter_port" "$web_port")"
    create_service_file "$svc_name" "$conf_path" >/dev/null
    systemd_reload

    # Requested order: stop+disable udp2raw first, then start backhaul
    svc_stop_disable "$unit"

    if ! svc_enable_start "$svc_unit"; then
      FAIL+=("lport=$lport unit=$unit backhaul=$svc_unit reason=BackhaulStartFailed")
      print_last_logs "$svc_unit"
      continue
    fi

    printf "FOREIGN_IP=%s INTER_PORT=%s IRAN_IP=%s LPORT=%s WEB_PORT=%s\n" \
      "$foreign_ip" "$inter_port" "$iran_ip" "$lport" "$web_port" >> "${OUT_FILE}"

    OK+=("lport=$lport udp2raw=$unit -> backhaul=$svc_unit web_port=$web_port inter_port=$inter_port foreign=$foreign_ip")
    gecho "✅ migrated lport=$lport (web_port=$web_port)"
  done

  cecho ""
  cecho "========== MIGRATION SUMMARY (IRAN) =========="
  printf "OK   : %s\n" "${#OK[@]}"
  printf "FAIL : %s\n" "${#FAIL[@]}"
  printf "SKIP : %s\n" "${#WARN_SKIPS[@]}"
  cecho "---------------------------------------------"
  [ "${#WARN_SKIPS[@]}" -gt 0 ] && { yecho "SKIP/WARN details:"; printf "  - %s\n" "${WARN_SKIPS[@]}" >&2; }
  [ "${#FAIL[@]}" -gt 0 ] && { recho "FAIL details:"; printf "  - %s\n" "${FAIL[@]}" >&2; }
  cecho "Tasks file created: ${OUT_FILE}"
  cecho "============================================="
}

mode_rollback_iran() {
  require_root
  OK=(); FAIL=(); WARN_SKIPS=()

  cecho "Rolling back: backhaul -> udp2raw (IRAN)"
  systemd_reload

  local units=()
  mapfile -t units < <(systemctl list-units --type=service 'backhaul*.service' --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)
  if [ "${#units[@]}" -eq 0 ]; then
    yecho "No backhaul*.service units found."
    return 0
  fi

  local unit lport udp_unit
  for unit in "${units[@]}"; do
    if [[ "$unit" =~ ^backhaul([0-9]+)\.service$ ]]; then
      lport="${BASH_REMATCH[1]}"
    else
      WARN_SKIPS+=("unit=$unit reason=NameNotMatchBackhaulPort")
      continue
    fi

    udp_unit="udp2raw${lport}.service"
    cecho "---- ROLLBACK lport=${lport} backhaul=${unit} -> udp2raw=${udp_unit} ----"

    svc_stop_disable "$unit"

    if svc_exists "$udp_unit"; then
      if ! svc_enable_start "$udp_unit"; then
        FAIL+=("lport=$lport backhaul=$unit udp2raw=$udp_unit reason=Udp2rawStartFailed")
        print_last_logs "$udp_unit"
        continue
      fi
      OK+=("lport=$lport backhaul=$unit -> udp2raw=$udp_unit")
      gecho "✅ rolled back lport=$lport"
    else
      WARN_SKIPS+=("lport=$lport backhaul=$unit reason=Udp2rawServiceNotFound expected=$udp_unit")
    fi
  done

  cecho ""
  cecho "========== ROLLBACK SUMMARY (IRAN) =========="
  printf "OK   : %s\n" "${#OK[@]}"
  printf "FAIL : %s\n" "${#FAIL[@]}"
  printf "SKIP : %s\n" "${#WARN_SKIPS[@]}"
  cecho "--------------------------------------------"
  [ "${#WARN_SKIPS[@]}" -gt 0 ] && { yecho "SKIP/WARN details:"; printf "  - %s\n" "${WARN_SKIPS[@]}" >&2; }
  [ "${#FAIL[@]}" -gt 0 ] && { recho "FAIL details:"; printf "  - %s\n" "${FAIL[@]}" >&2; }
  cecho "============================================"
}

mode_remigrate_iran() {
  require_root
  ensure_backhaul
  ensure_ip_forwarding

  OK=(); FAIL=(); WARN_SKIPS=()

  discover_udp2raw_active_dedup
  if [ "${#SELECTED_UNITS[@]}" -eq 0 ]; then
    yecho "No ACTIVE udp2raw units to re-migrate."
    return 0
  fi

  systemd_reload

  local lport unit svc_unit conf_path
  for lport in $(printf "%s\n" "${!SELECTED_UNITS[@]}" | sort -n); do
    unit="${SELECTED_UNITS[$lport]}"
    svc_unit="backhaul${lport}.service"
    conf_path="${CONF_DIR}/conf-${lport}.toml"

    cecho "---- RE-MIGRATE lport=${lport} udp2raw=${unit} -> ${svc_unit} ----"

    if ! svc_exists "$svc_unit"; then
      WARN_SKIPS+=("lport=$lport unit=$unit reason=BackhaulServiceNotFound expected=$svc_unit")
      continue
    fi
    if [ ! -f "$conf_path" ]; then
      WARN_SKIPS+=("lport=$lport unit=$unit reason=BackhaulConfNotFound expected=$conf_path")
      continue
    fi

    svc_stop_disable "$unit"

    if ! svc_enable_start "$svc_unit"; then
      FAIL+=("lport=$lport unit=$unit reason=BackhaulStartFailed backhaul=$svc_unit")
      print_last_logs "$svc_unit"
      continue
    fi

    OK+=("lport=$lport udp2raw=$unit -> backhaul=$svc_unit")
    gecho "✅ re-migrated lport=$lport"
  done

  cecho ""
  cecho "========== RE-MIGRATION SUMMARY (IRAN) =========="
  printf "OK   : %s\n" "${#OK[@]}"
  printf "FAIL : %s\n" "${#FAIL[@]}"
  printf "SKIP : %s\n" "${#WARN_SKIPS[@]}"
  cecho "-----------------------------------------------"
  [ "${#WARN_SKIPS[@]}" -gt 0 ] && { yecho "SKIP/WARN details:"; printf "  - %s\n" "${WARN_SKIPS[@]}" >&2; }
  [ "${#FAIL[@]}" -gt 0 ] && { recho "FAIL details:"; printf "  - %s\n" "${FAIL[@]}" >&2; }
  cecho "================================================"
}

# ===== Mode: KHAREJ apply =====
mode_foreign_apply() {
  require_root
  ensure_backhaul

  [ -n "$TASKS_FILE" ] || die "foreign-apply requires --tasks /path/to/file"
  [ -f "$TASKS_FILE" ] || die "tasks file not found: $TASKS_FILE"

  OK=(); FAIL=(); WARN_SKIPS=()

  local my_ipv4=""
  if [ "$FOREIGN_IP_CHECK" = "on" ]; then
    my_ipv4="$(get_public_ipv4)"
    [ -n "$my_ipv4" ] || die "Could not detect this server IPv4. Use: --foreign-ip-check off"
    cecho "KHAREJ IPv4: ${my_ipv4} (FOREIGN_IP check: ON)"
  else
    yecho "FOREIGN_IP check: OFF"
  fi

  systemd_reload

  local line foreign_ip inter_port iran_ip lport web_port iran_digits svc_name svc_unit conf_path
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    foreign_ip=""; inter_port=""; iran_ip=""; lport=""; web_port=""
    for kv in $line; do
      case "$kv" in
        FOREIGN_IP=*) foreign_ip="${kv#FOREIGN_IP=}" ;;
        INTER_PORT=*) inter_port="${kv#INTER_PORT=}" ;;
        IRAN_IP=*) iran_ip="${kv#IRAN_IP=}" ;;
        LPORT=*) lport="${kv#LPORT=}" ;;
        WEB_PORT=*) web_port="${kv#WEB_PORT=}" ;;
      esac
    done

    if [ -z "$foreign_ip" ] || [ -z "$inter_port" ] || [ -z "$iran_ip" ] || [ -z "$lport" ] || [ -z "$web_port" ]; then
      WARN_SKIPS+=("line=$(printf "%q" "$line") reason=MissingFields")
      continue
    fi

    if [ "$FOREIGN_IP_CHECK" = "on" ] && [ "$foreign_ip" != "$my_ipv4" ]; then
      WARN_SKIPS+=("foreign_ip=$foreign_ip my_ip=$my_ipv4 lport=$lport inter_port=$inter_port iran_ip=$iran_ip web_port=$web_port reason=ForeignIPMismatch")
      continue
    fi

    # Service name rule requested:
    # backhaul_<LPORT>_<IRANIPdigits>  e.g. backhaul_5302_626014729  (dots removed)
    iran_digits="${iran_ip//./}"
    svc_name="backhaul_${lport}_${iran_digits}"
    svc_unit="${svc_name}.service"

    cecho "---- APPLY (KHAREJ) lport=${lport} connect=${iran_ip}:${inter_port} web_port=${web_port} svc=${svc_unit} ----"

    # web_port must match IRAN; if in use => WARN + SKIP
    if is_tcp_listening "$web_port"; then
      WARN_SKIPS+=("lport=$lport iran_ip=$iran_ip inter_port=$inter_port web_port=$web_port reason=WebPortAlreadyListening")
      continue
    fi
    if grep -R --no-messages -nE "^[[:space:]]*web_port[[:space:]]*=[[:space:]]*${web_port}[[:space:]]*$" "${CONF_DIR}/conf-"*.toml >/dev/null 2>&1; then
      WARN_SKIPS+=("lport=$lport iran_ip=$iran_ip inter_port=$inter_port web_port=$web_port reason=WebPortAlreadyInConfs")
      continue
    fi

    conf_path="$(create_client_conf "$lport" "$iran_ip" "$inter_port" "$web_port")"
    create_service_file "$svc_name" "$conf_path" >/dev/null
    systemd_reload

    if ! svc_enable_start "$svc_unit"; then
      FAIL+=("lport=$lport iran_ip=$iran_ip inter_port=$inter_port web_port=$web_port svc=$svc_unit reason=BackhaulClientStartFailed")
      print_last_logs "$svc_unit"
      continue
    fi

    OK+=("svc=$svc_unit lport=$lport iran=${iran_ip}:${inter_port} web_port=$web_port")
    gecho "✅ applied lport=$lport (web_port=$web_port)"
  done < "$TASKS_FILE"

  cecho ""
  cecho "========== FOREIGN APPLY SUMMARY (KHAREJ) =========="
  printf "OK   : %s\n" "${#OK[@]}"
  printf "FAIL : %s\n" "${#FAIL[@]}"
  printf "SKIP : %s\n" "${#WARN_SKIPS[@]}"
  cecho "---------------------------------------------------"
  [ "${#WARN_SKIPS[@]}" -gt 0 ] && { yecho "SKIP/WARN details (manual action may be required):"; printf "  - %s\n" "${WARN_SKIPS[@]}" >&2; }
  [ "${#FAIL[@]}" -gt 0 ] && { recho "FAIL details:"; printf "  - %s\n" "${FAIL[@]}" >&2; }
  cecho "==================================================="
}

# ===== Interactive prompts (English only) =====
prompt_role_if_needed() {
  if [ -n "$ROLE" ]; then return 0; fi
  cecho "Where are you running this script?"
  printf "  [1] IRAN server\n  [2] KHAREJ (foreign) server\n" >&2
  printf "Select [1/2]: " >&2
  local c; read -r c
  case "$c" in
    1) ROLE="iran" ;;
    2) ROLE="kharej" ;;
    *) die "Invalid selection." ;;
  esac
}

prompt_mode_if_needed() {
  if [ -n "$MODE" ]; then return 0; fi
  if [ "$ROLE" = "iran" ]; then
    cecho "Select operation (IRAN):"
    printf "  [1] Migration  udp2raw -> backhaul\n  [2] Rollback   backhaul -> udp2raw\n  [3] Re-Migrate udp2raw -> backhaul (only if backhaul already exists)\n" >&2
    printf "Select [1/2/3]: " >&2
    local c; read -r c
    case "$c" in
      1) MODE="migrate" ;;
      2) MODE="rollback" ;;
      3) MODE="remigrate" ;;
      *) die "Invalid selection." ;;
    esac
  else
    cecho "Select operation (KHAREJ):"
    printf "  [1] Apply tasks file (client setup)\n" >&2
    printf "Select [1]: " >&2
    local c; read -r c
    [ "${c:-1}" = "1" ] || die "Invalid selection."
    MODE="foreign-apply"
  fi
}

prompt_tasks_file_if_needed() {
  if [ "$ROLE" = "kharej" ] && [ "$MODE" = "foreign-apply" ] && [ -z "$TASKS_FILE" ]; then
    printf "Enter tasks file path (default: %s): " "$OUT_FILE" >&2
    read -r TASKS_FILE
    TASKS_FILE="${TASKS_FILE:-$OUT_FILE}"
  fi
}

# ===== CLI =====
usage() {
  cat >&2 <<EOF
Usage:
  sudo bash $0 [--role iran|kharej] [--mode ...] [options]

Roles:
  iran   : migrate | rollback | remigrate
  kharej : foreign-apply

Options:
  --role <iran|kharej>              If omitted, interactive prompt will ask
  --mode <migrate|rollback|remigrate|foreign-apply>  If omitted, interactive prompt will ask
  --out <path>                      Output tasks file on IRAN (default: ${OUT_FILE})
  --tasks <path>                    Tasks file for foreign-apply
  --iran-ip <x.x.x.x>               Override IPv4 detection (recommended if servers have restricted outbound)
  --foreign-ip-check <on|off>       Default: on (only meaningful on kharej)
  --backhaul-version <vX.Y.Z>       Default: ${BACKHAUL_VERSION}

Examples (non-interactive):
  sudo ./manage_tunnel.sh --role iran --mode migrate --iran-ip 62.60.x.x --out /root/backhaul-foreign-tasks.txt
  sudo ./manage_tunnel.sh --role iran --mode rollback
  sudo ./manage_tunnel.sh --role iran --mode remigrate
  sudo ./manage_tunnel.sh --role kharej --mode foreign-apply --tasks /root/backhaul-foreign-tasks.txt
EOF
  exit 1
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --role) ROLE="${2:-}"; shift 2 ;;
      --mode) MODE="${2:-}"; shift 2 ;;
      --out) OUT_FILE="${2:-}"; shift 2 ;;
      --tasks) TASKS_FILE="${2:-}"; shift 2 ;;
      --iran-ip) IRAN_IP_OVERRIDE="${2:-}"; shift 2 ;;
      --foreign-ip-check) FOREIGN_IP_CHECK="${2:-}"; shift 2 ;;
      --backhaul-version) BACKHAUL_VERSION="${2:-}"; shift 2 ;;
      -h|--help) usage ;;
      *) recho "Unknown arg: $1"; usage ;;
    esac
  done

  if [ -n "$ROLE" ]; then
    case "$ROLE" in iran|kharej) ;; *) die "Invalid --role: $ROLE (use iran|kharej)";; esac
  fi

  if [ -n "$MODE" ]; then
    case "$MODE" in migrate|rollback|remigrate|foreign-apply) ;; *) die "Invalid --mode: $MODE";; esac
  fi

  case "$FOREIGN_IP_CHECK" in on|off) ;; *) die "Invalid --foreign-ip-check: $FOREIGN_IP_CHECK (use on/off)";; esac

  # Validate compatibility when both provided
  if [ -n "$ROLE" ] && [ -n "$MODE" ]; then
    if [ "$ROLE" = "iran" ] && [ "$MODE" = "foreign-apply" ]; then
      die "foreign-apply is only for KHAREJ. Use: --role kharej"
    fi
    if [ "$ROLE" = "kharej" ] && [[ "$MODE" =~ ^(migrate|rollback|remigrate)$ ]]; then
      die "migrate/rollback/remigrate are only for IRAN. Use: --role iran"
    fi
  fi
}

main() {
  parse_args "$@"

  # Interactive prompts if missing
  prompt_role_if_needed
  prompt_mode_if_needed
  prompt_tasks_file_if_needed

  case "$ROLE:$MODE" in
    iran:migrate) mode_migrate_iran ;;
    iran:rollback) mode_rollback_iran ;;
    iran:remigrate) mode_remigrate_iran ;;
    kharej:foreign-apply) mode_foreign_apply ;;
    *) die "Internal: unsupported ROLE:MODE -> $ROLE:$MODE" ;;
  esac
}

main "$@"
