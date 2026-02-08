#!/usr/bin/env bash

set +e
set +u
export LC_ALL=C

LOG_LINES=()
LOG_MIN=3
LOG_MAX=10

############################################
# Banner (BERNO / BAZI KONIM?)
############################################
banner() {
  cat <<'EOF'
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗                                  │
│   ██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗                                 │
│   ██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║                                 │
│   ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║                                 │
│   ██████╔╝███████╗██║  ██║██║ ╚████║╚██████╔╝                                 │
│   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝                                  │
│                                                                              │
│                               BAZI KONIM?                                    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
EOF
}

############################################
# Logging helpers
############################################
add_log() {
  local msg="$1"
  local ts
  ts="$(date +"%H:%M:%S")"
  LOG_LINES+=("[$ts] $msg")
  if ((${#LOG_LINES[@]} > LOG_MAX)); then
    LOG_LINES=("${LOG_LINES[@]: -$LOG_MAX}")
  fi
}

render() {
  clear
  banner
  echo

  local shown_count="${#LOG_LINES[@]}"
  local height=$shown_count
  ((height < LOG_MIN)) && height=$LOG_MIN
  ((height > LOG_MAX)) && height=$LOG_MAX

  echo "┌───────────────────────────── ACTION LOG ─────────────────────────────┐"
  local start_index=0
  if ((${#LOG_LINES[@]} > height)); then
    start_index=$((${#LOG_LINES[@]} - height))
  fi

  local i line
  for ((i=start_index; i<${#LOG_LINES[@]}; i++)); do
    line="${LOG_LINES[$i]}"
    printf "│ %-68s │\n" "$line"
  done

  local missing=$((height - (${#LOG_LINES[@]} - start_index)))
  for ((i=0; i<missing; i++)); do
    printf "│ %-68s │\n" ""
  done

  echo "└──────────────────────────────────────────────────────────────────────┘"
  echo
}

# فقط برای منوی اصلی: بنر + دو ستون (منو چپ / لاگ راست)
render_main_with_log_panel() {
  clear
  banner
  echo

  # --- LEFT: main menu box lines ---
  local MENU_LINES=(
"┌──────────────────── MAIN MENU ────────────────────┐"
"│  1 > IRAN SETUP                                   │"
"│  2 > KHAREJ SETUP                                 │"
"│  3 > Services Management                          │"
"│  4 > Uninstall & Clean                            │"
"│  5 > Add tunnel port                              │"
"│  0 > Exit                                         │"
"└───────────────────────────────────────────────────┘"
  )

  local menu_h=${#MENU_LINES[@]}

  # --- RIGHT: action log box lines (matched height with menu) ---
  local LOG_TOP="┌──────────────────── ACTION LOG ────────────────────┐"
  local LOG_BOTTOM="└────────────────────────────────────────────────────┘"
  local log_box_width=${#LOG_TOP}
  local log_inner_width=$((log_box_width - 4))

  local content_rows=$((menu_h - 2))
  ((content_rows < 1)) && content_rows=1

  local total_logs=${#LOG_LINES[@]}
  local start_index=0
  if (( total_logs > content_rows )); then
    start_index=$((total_logs - content_rows))
  fi

  local -a LOG_BOX_LINES=()
  LOG_BOX_LINES+=("$LOG_TOP")

  local i idx text line
  for ((i=0; i<content_rows; i++)); do
    idx=$((start_index + i))
    if (( idx < total_logs )); then
      text="${LOG_LINES[$idx]}"
    else
      text=""
    fi
    printf -v line "│ %-*s │" "$log_inner_width" "$text"
    LOG_BOX_LINES+=("$line")
  done

  LOG_BOX_LINES+=("$LOG_BOTTOM")

  # حالا دو ستون را کنار هم چاپ می‌کنیم
  local rows=$menu_h
  for ((i=0; i<rows; i++)); do
    local left="${MENU_LINES[$i]}"
    local right="${LOG_BOX_LINES[$i]}"
    printf "  %-51s  %s\n" "$left" "$right"
  done

  echo
}

pause_enter() {
  echo
  read -r -p "Press ENTER to return to menu..." _
}

die_soft() {
  add_log "ERROR: $1"
  render
  pause_enter
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Re-running with sudo..."
    exec sudo -E bash "$0" "$@"
  fi
}

trim() { sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$1"; }
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

valid_octet() {
  local o="$1"
  [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255))
}

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}

valid_port() {
  local p="$1"
  is_int "$p" || return 1
  ((p>=1 && p<=65535))
}

valid_gre_base() {
  local ip="$1"
  valid_ipv4 "$ip" || return 1
  [[ "$ip" =~ \.0$ ]] || return 1
  return 0
}

ipv4_set_last_octet() {
  local ip="$1" last="$2"
  IFS='.' read -r a b c d <<<"$ip"
  echo "${a}.${b}.${c}.${last}"
}

ask_until_valid() {
  local prompt="$1" validator="$2" __var="$3"
  local ans=""
  while true; do
    render
    read -r -e -p "$prompt " ans
    ans="$(trim "$ans")"
    if [[ -z "$ans" ]]; then
      add_log "Empty input. Please try again."
      continue
    fi
    if "$validator" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      add_log "OK: $prompt $ans"
      return 0
    else
      add_log "Invalid: $prompt $ans"
      add_log "Please enter a valid value."
    fi
  done
}

ask_ports() {
  local prompt="ForWard PORT (80 | 80,2053 | 2050-2060):"
  local raw=""
  while true; do
    render
    read -r -e -p "$prompt " raw
    raw="$(trim "$raw")"
    raw="${raw// /}"

    if [[ -z "$raw" ]]; then
      add_log "Empty ports. Please try again."
      continue
    fi

    local -a ports=()
    local ok=1

    if [[ "$raw" =~ ^[0-9]+$ ]]; then
      valid_port "$raw" && ports+=("$raw") || ok=0

    elif [[ "$raw" =~ ^[0-9]+-[0-9]+$ ]]; then
      local s="${raw%-*}"
      local e="${raw#*-}"
      if valid_port "$s" && valid_port "$e" && ((s<=e)); then
        local p
        for ((p=s; p<=e; p++)); do ports+=("$p"); done
      else
        ok=0
      fi

    elif [[ "$raw" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
      IFS=',' read -r -a parts <<<"$raw"
      local part
      for part in "${parts[@]}"; do
        valid_port "$part" && ports+=("$part") || { ok=0; break; }
      done
    else
      ok=0
    fi

    if ((ok==0)); then
      add_log "Invalid ports: $raw"
      add_log "Examples: 80 | 80,2053 | 2050-2060"
      continue
    fi

    mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
    add_log "Ports accepted: ${PORT_LIST[*]}"
    return 0
  done
}

ensure_iproute_only() {
  add_log "Checking required package: iproute2"
  render

  if command -v ip >/dev/null 2>&1; then
    add_log "iproute2 is already installed."
    return 0
  fi

  add_log "Installing missing package: iproute2"
  render
  apt-get update -y >/dev/null 2>&1
  apt-get install -y iproute2 >/dev/null 2>&1 && add_log "iproute2 installed successfully." || return 1
  return 0
}

ensure_packages() {
  add_log "Checking required packages: iproute2, haproxy"
  render
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=("iproute2")
  command -v haproxy >/dev/null 2>&1 || missing+=("haproxy")

  if ((${#missing[@]}==0)); then
    add_log "All required packages are installed."
    return 0
  fi

  add_log "Installing missing packages: ${missing[*]}"
  render
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "${missing[@]}" >/dev/null 2>&1 && add_log "Packages installed successfully." || return 1
  return 0
}

systemd_reload() { systemctl daemon-reload >/dev/null 2>&1; }
unit_exists() { [[ -f "/etc/systemd/system/$1" ]]; }
enable_now() { systemctl enable --now "$1" >/dev/null 2>&1; }

show_unit_status_brief() {
  systemctl --no-pager --full status "$1" 2>&1 | sed -n '1,12p'
}

make_gre_service() {
  local id="$1" local_ip="$2" remote_ip="$3" local_gre_ip="$4" key="$5"
  local unit="gre${id}.service"
  local path="/etc/systemd/system/${unit}"

  if unit_exists "$unit"; then
    add_log "Service already exists: $unit"
    return 2
  fi

  add_log "Creating: $path"
  render

  cat >"$path" <<EOF
[Unit]
Description=GRE Tunnel to (${remote_ip})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip tunnel add gre${id} mode gre local ${local_ip} remote ${remote_ip} ttl 255 key ${key}
ExecStart=/sbin/ip addr add ${local_gre_ip}/30 dev gre${id}
ExecStart=/sbin/ip link set gre${id} up
ExecStop=/sbin/ip link set gre${id} down
ExecStop=/sbin/ip tunnel del gre${id}

[Install]
WantedBy=multi-user.target
EOF

  [[ $? -eq 0 ]] && add_log "GRE service created: $unit" || return 1
  return 0
}

haproxy_unit_exists() {
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx 'haproxy.service'
}

haproxy_write_main_cfg() {
  add_log "Rebuilding /etc/haproxy/haproxy.cfg (no include)"
  render

  rm -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1 || true

  cat >/etc/haproxy/haproxy.cfg <<'EOF'
#HAPROXY-FOR-GRE
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon
    maxconn 200000

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client  1m
    timeout server  1m

EOF
}

haproxy_write_gre_cfg() {
  local id="$1" target_ip="$2"
  shift 2
  local -a ports=("$@")

  mkdir -p /etc/haproxy/conf.d >/dev/null 2>&1 || true
  local cfg="/etc/haproxy/conf.d/haproxy-gre${id}.cfg"

  if [[ -f "$cfg" ]]; then
    add_log "ERROR: haproxy-gre${id}.cfg already exists."
    return 2
  fi

  add_log "Creating HAProxy config: $cfg"
  render

  : >"$cfg" || return 1

  local p
  for p in "${ports[@]}"; do
    cat >>"$cfg" <<EOF
frontend gre${id}_fe_${p}
    bind 0.0.0.0:${p}
    default_backend gre${id}_be_${p}

backend gre${id}_be_${p}
    option tcp-check
    server gre${id}_b_${p} ${target_ip}:${p} check

EOF
  done

  return 0
}

haproxy_patch_systemd() {
  local dir="/etc/systemd/system/haproxy.service.d"
  local override="${dir}/override.conf"

  if ! haproxy_unit_exists; then
    add_log "ERROR: not found haproxy service"
    return 1
  fi

  add_log "Patching systemd for haproxy to load /etc/haproxy/conf.d/ (drop-in override)"
  render

  mkdir -p "$dir" >/dev/null 2>&1 || return 1

  cat >"$override" <<'EOF'
[Service]
Environment="CONFIG=/etc/haproxy/haproxy.cfg"
Environment="PIDFILE=/run/haproxy.pid"
Environment="EXTRAOPTS=-S /run/haproxy-master.sock"
ExecStart=
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f /etc/haproxy/conf.d/ -p $PIDFILE $EXTRAOPTS
ExecReload=
ExecReload=/usr/sbin/haproxy -Ws -f $CONFIG -f /etc/haproxy/conf.d/ -c -q $EXTRAOPTS
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  return 0
}

haproxy_apply_and_show() {
  haproxy_patch_systemd || return 1

  add_log "Enabling HAProxy..."
  render
  systemctl enable --now haproxy >/dev/null 2>&1 || true

  add_log "Restarting HAProxy..."
  render
  systemctl restart haproxy >/dev/null 2>&1 || true

  render
  echo "---- STATUS (haproxy.service) ----"
  systemctl status haproxy --no-pager 2>&1 | sed -n '1,18p'
  echo "---------------------------------"
}

iran_setup() {
  local ID IRANIP KHAREJIP GREBASE
  local -a PORT_LIST=()

  ask_until_valid "GRE Number :" is_int ID
  ask_until_valid "IRAN IP :" valid_ipv4 IRANIP
  ask_until_valid "KHAREJ IP :" valid_ipv4 KHAREJIP
  ask_until_valid "GRE IP RANG (Example : 10.80.70.0):" valid_gre_base GREBASE
  ask_ports

  local key=$((ID*100))
  local local_gre_ip peer_gre_ip
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  add_log "KEY=${key} | IRAN=${local_gre_ip} | KHAREJ=${peer_gre_ip}"

  ensure_packages || { die_soft "Package installation failed."; return 0; }

  make_gre_service "$ID" "$IRANIP" "$KHAREJIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && return 0
  [[ $rc -ne 0 ]] && { die_soft "Failed creating GRE service."; return 0; }

  add_log "Reloading systemd..."
  systemd_reload

  add_log "Starting gre${ID}..."
  enable_now "gre${ID}.service"

  add_log "Writing HAProxy configs for GRE${ID}..."
  haproxy_write_gre_cfg "$ID" "$peer_gre_ip" "${PORT_LIST[@]}"
  local hrc=$?
  if [[ $hrc -eq 2 ]]; then
    die_soft "haproxy-gre${ID}.cfg already exists."
    return 0
  elif [[ $hrc -ne 0 ]]; then
    die_soft "Failed writing haproxy-gre${ID}.cfg"
    return 0
  fi

  haproxy_write_main_cfg

  if command -v haproxy >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d/ >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      die_soft "HAProxy config validation failed (haproxy -c)."
      return 0
    fi
  fi

  haproxy_apply_and_show || { die_soft "Failed applying HAProxy systemd override."; return 0; }

  render
  echo "GRE IPs:"
  echo "  IRAN  : ${local_gre_ip}"
  echo "  KHAREJ: ${peer_gre_ip}"
  echo
  echo "Status:"
  show_unit_status_brief "gre${ID}.service"
  pause_enter
}

kharej_setup() {
  local ID KHAREJIP IRANIP GREBASE

  ask_until_valid "GRE Number(Like IRAN PLEASE) :" is_int ID
  ask_until_valid "KHAREJ IP :" valid_ipv4 KHAREJIP
  ask_until_valid "IRAN IP :" valid_ipv4 IRANIP
  ask_until_valid "GRE IP RANG (Example : 10.80.70.0) Like IRAN PLEASE:" valid_gre_base GREBASE

  local key=$((ID*100))
  local local_gre_ip peer_gre_ip
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  add_log "KEY=${key} | KHAREJ=${local_gre_ip} | IRAN=${peer_gre_ip}"

  ensure_iproute_only || { die_soft "Package installation failed (iproute2)."; return 0; }

  make_gre_service "$ID" "$KHAREJIP" "$IRANIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && return 0
  [[ $rc -ne 0 ]] && { die_soft "Failed creating GRE service."; return 0; }

  add_log "Reloading systemd..."
  systemd_reload

  add_log "Starting gre${ID}..."
  enable_now "gre${ID}.service"

  render
  echo "GRE IPs:"
  echo "  KHAREJ: ${local_gre_ip}"
  echo "  IRAN  : ${peer_gre_ip}"
  echo
  show_unit_status_brief "gre${ID}.service"
  pause_enter
}

get_gre_ids() {
  local ids=()

  while IFS= read -r u; do
    [[ "$u" =~ ^gre([0-9]+)\.service$ ]] && ids+=("${BASH_REMATCH[1]}")
  done < <(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^gre[0-9]+\.service$' || true)

  while IFS= read -r f; do
    f="$(basename "$f")"
    [[ "$f" =~ ^gre([0-9]+)\.service$ ]] && ids+=("${BASH_REMATCH[1]}")
  done < <(find /etc/systemd/system -maxdepth 1 -type f -name 'gre*.service' 2>/dev/null || true)

  printf "%s\n" "${ids[@]}" | awk 'NF{a[$0]=1} END{for(k in a) print k}' | sort -n
}

MENU_SELECTED=-1

menu_select_index() {
  local title="$1"
  local prompt="$2"
  shift 2
  local -a items=("$@")
  local choice=""

  while true; do
    render
    echo "$title"
    echo

    if ((${#items[@]} == 0)); then
      echo "No service found."
      echo
      read -r -p "Press ENTER to go back..." _
      MENU_SELECTED=-1
      return 1
    fi

    local i
    for ((i=0; i<${#items[@]}; i++)); do
      printf "%d) %s\n" $((i+1)) "${items[$i]}"
    done
    echo "0) Back"
    echo

    read -r -e -p "$prompt " choice
    choice="$(trim "$choice")"

    if [[ "$choice" == "0" ]]; then
      MENU_SELECTED=-1
      return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#items[@]})); then
      MENU_SELECTED=$((choice-1))
      return 0
    fi

    add_log "Invalid selection: $choice"
  done
}

service_action_menu() {
  local unit="$1"
  local action=""

  while true; do
    render
    echo "Selected: $unit"
    echo
    echo "1) Enable & Start"
    echo "2) Restart"
    echo "3) Stop & Disable"
    echo "4) Status"
    echo "0) Back"
    echo

    read -r -e -p "Select action: " action
    action="$(trim "$action")"

    case "$action" in
      1)
        add_log "Enable & Start: $unit"
        systemctl enable "$unit" >/dev/null 2>&1 && add_log "Enabled: $unit" || add_log "Enable failed: $unit"
        systemctl start "$unit"  >/dev/null 2>&1 && add_log "Started: $unit" || add_log "Start failed: $unit"
        ;;
      2)
        add_log "Restart: $unit"
        systemctl restart "$unit" >/dev/null 2>&1 && add_log "Restarted: $unit" || add_log "Restart failed: $unit"
        ;;
      3)
        add_log "Stop & Disable: $unit"
        systemctl stop "$unit"    >/dev/null 2>&1 && add_log "Stopped: $unit" || add_log "Stop failed: $unit"
        systemctl disable "$unit" >/dev/null 2>&1 && add_log "Disabled: $unit" || add_log "Disable failed: $unit"
        ;;
      4)
        render
        echo "---- STATUS ($unit) ----"
        systemctl --no-pager --full status "$unit" 2>&1 | sed -n '1,16p'
        echo "------------------------"
        pause_enter
        ;;
      0) return 0 ;;
      *) add_log "Invalid action: $action" ;;
    esac
  done
}

services_management() {
  local sel=""

  while true; do
    render
    echo "Services ManageMent"
    echo
    echo "1) GRE"
    echo "2) HAPROXY"
    echo "0) Back"
    echo
    read -r -e -p "Select: " sel
    sel="$(trim "$sel")"

    case "$sel" in
      1)
        mapfile -t GRE_IDS < <(get_gre_ids)
        local -a GRE_LABELS=()
        local id
        for id in "${GRE_IDS[@]}"; do
          GRE_LABELS+=("GRE${id}")
        done

        if menu_select_index "GRE Services" "Select GRE:" "${GRE_LABELS[@]}"; then
          local idx="$MENU_SELECTED"
          id="${GRE_IDS[$idx]}"
          add_log "GRE selected: GRE${id}"
          service_action_menu "gre${id}.service"
        fi
        ;;
      2)
        if ! haproxy_unit_exists; then
          add_log "ERROR: not found haproxy service"
          render
          pause_enter
          continue
        fi
        add_log "HAProxy selected"
        service_action_menu "haproxy.service"
        ;;
      0) return 0 ;;
      *) add_log "Invalid selection: $sel" ;;
    esac
  done
}

uninstall_clean() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=()
  local id
  for id in "${GRE_IDS[@]}"; do
    GRE_LABELS+=("GRE${id}")
  done

  if ! menu_select_index "Uninstall & Clean" "Select GRE to uninstall:" "${GRE_LABELS[@]}"; then
    return 0
  fi

  local idx="$MENU_SELECTED"
  id="${GRE_IDS[$idx]}"

  while true; do
    render
    echo "Uninstall & Clean"
    echo
    echo "Target: GRE${id}"
    echo "This will remove:"
    echo "  - gre${id}.service"
    echo "  - /etc/haproxy/conf.d/haproxy-gre${id}.cfg"
    echo
    echo "Type: YES (confirm)  or  NO (cancel)"
    echo
    local confirm=""
    read -r -e -p "Confirm: " confirm
    confirm="$(trim "$confirm")"

    if [[ "$confirm" == "NO" || "$confirm" == "no" ]]; then
      add_log "Uninstall cancelled for GRE${id}"
      return 0
    fi
    if [[ "$confirm" == "YES" ]]; then
      break
    fi
    add_log "Please type YES or NO."
  done

  add_log "Stopping gre${id}.service"
  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  add_log "Disabling gre${id}.service"
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true

  add_log "Removing unit file..."
  rm -f "/etc/systemd/system/gre${id}.service" >/dev/null 2>&1 || true

  add_log "Removing HAProxy GRE config..."
  rm -f "/etc/haproxy/conf.d/haproxy-gre${id}.cfg" >/dev/null 2>&1 || true

  add_log "Reloading systemd..."
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed  >/dev/null 2>&1 || true

  if haproxy_unit_exists; then
    add_log "Restarting haproxy (no disable)..."
    systemctl restart haproxy >/dev/null 2>&1 || true
  else
    add_log "haproxy service not found; skip restart."
  fi

  add_log "Uninstall completed for GRE${id}"
  render
  pause_enter
}

get_gre_local_ip_cidr() {
  local id="$1"
  ip -4 -o addr show dev "gre${id}" 2>/dev/null | awk '{print $4}' | head -n1
}

get_peer_ip_from_local_cidr() {
  local cidr="$1"
  local ip="${cidr%/*}"
  local mask="${cidr#*/}"

  IFS='.' read -r a b c d <<<"$ip"

  local peer_d
  if [[ "$d" == "1" ]]; then
    peer_d="2"
  elif [[ "$d" == "2" ]]; then
    peer_d="1"
  else
    peer_d="2"
  fi

  echo "${a}.${b}.${c}.${peer_d}"
}

haproxy_add_ports_to_gre_cfg() {
  local id="$1" target_ip="$2"
  shift 2
  local -a ports=("$@")
  local cfg="/etc/haproxy/conf.d/haproxy-gre${id}.cfg"

  if [[ ! -f "$cfg" ]]; then
    add_log "ERROR: Not found: $cfg"
    return 1
  fi

  add_log "Editing HAProxy config: $cfg"
  render

  local p added=0 skipped=0
  for p in "${ports[@]}"; do
    if grep -qE "^frontend[[:space:]]+gre${id}_fe_${p}\b" "$cfg" 2>/dev/null; then
      add_log "Skip (exists): GRE${id} port ${p}"
      ((skipped++))
      continue
    fi

    cat >>"$cfg" <<EOF

frontend gre${id}_fe_${p}
    bind 0.0.0.0:${p}
    default_backend gre${id}_be_${p}

backend gre${id}_be_${p}
    option tcp-check
    server gre${id}_b_${p} ${target_ip}:${p} check
EOF

    add_log "Added: GRE${id} port ${p} -> ${target_ip}:${p}"
    ((added++))
  done

  add_log "Done. Added=${added}, Skipped=${skipped}"
  return 0
}

add_tunnel_port() {
  render
  add_log "Selected: add tunnel port"
  render

  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=()
  local id
  for id in "${GRE_IDS[@]}"; do
    GRE_LABELS+=("GRE${id}")
  done

  if ! menu_select_index "Add Tunnel Port" "Select GRE:" "${GRE_LABELS[@]}"; then
    return 0
  fi

  local idx="$MENU_SELECTED"
  id="${GRE_IDS[$idx]}"
  add_log "GRE selected: GRE${id}"
  render

  local cidr
  cidr="$(get_gre_local_ip_cidr "$id")"
  if [[ -z "$cidr" ]]; then
    die_soft "Could not detect IP on gre${id}. Is it up and has an IP?"
    return 0
  fi

  local peer_ip
  peer_ip="$(get_peer_ip_from_local_cidr "$cidr")"
  add_log "Detected: gre${id} local=${cidr} | peer=${peer_ip}"
  render

  PORT_LIST=()
  ask_ports

  haproxy_add_ports_to_gre_cfg "$id" "$peer_ip" "${PORT_LIST[@]}" || { die_soft "Failed editing haproxy-gre${id}.cfg"; return 0; }

  if command -v haproxy >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d/ >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      die_soft "HAProxy config validation failed (haproxy -c)."
      return 0
    fi
  fi

  if haproxy_unit_exists; then
    add_log "Restarting HAProxy..."
    render
    systemctl restart haproxy >/dev/null 2>&1 || true
    add_log "HAProxy restarted."
  else
    add_log "WARNING: haproxy.service not found; skipped restart."
  fi

  render
  echo "GRE${id} updated."
  echo "Local CIDR : ${cidr}"
  echo "Peer IP    : ${peer_ip}"
  echo "Ports added: ${PORT_LIST[*]}"
  echo
  echo "---- STATUS (haproxy.service) ----"
  systemctl status haproxy --no-pager 2>&1 | sed -n '1,16p'
  echo "---------------------------------"
  pause_enter
}

############################################
# Main menu (new layout: left menu + right log)
############################################
main_menu() {
  local choice=""
  while true; do
    render_main_with_log_panel
    read -r -e -p "Select option: " choice
    choice="$(trim "$choice")"

    case "$choice" in
      1) add_log "Selected: IRAN SETUP"; iran_setup ;;
      2) add_log "Selected: KHAREJ SETUP"; kharej_setup ;;
      3) add_log "Selected: Services Management"; services_management ;;
      4) add_log "Selected: Uninstall & Clean"; uninstall_clean ;;
      5) add_log "Selected: add tunnel port"; add_tunnel_port ;;
      0)
        add_log "Bye!"
        render
        exit 0
        ;;
      *)
        add_log "Invalid option: $choice"
        ;;
    esac
  done
}

############################################
# Entry
############################################
ensure_root "$@"
add_log "GRE + HAProxy forwarder (refactored version)."
main_menu
