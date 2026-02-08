#!/usr/bin/env bash
# BERNO GRE + HAProxy forwarder (refactored)

set +e
set +u
export LC_ALL=C

############################################
# Colors (2-tone: accent + neutral)
############################################
CLR_RESET="\033[0m"
CLR_ACCENT="\033[96m"   # cyan-ish
CLR_DIM="\033[90m"      # dim gray

############################################
# Logging
############################################
LOG_LINES=()
LOG_MIN=5
LOG_MAX=12

add_log() {
  local msg="$1"
  local ts
  ts="$(date +"%H:%M:%S")"
  LOG_LINES+=("[$ts] $msg")
  if ((${#LOG_LINES[@]} > LOG_MAX)); then
    LOG_LINES=("${LOG_LINES[@]: -$LOG_MAX}")
  fi
}

############################################
# Banner + layout
############################################
banner() {
  cat <<'EOF'
 ############################################################
 #                                                          #
 #  BBBBB   EEEEE  RRRR   N   N  OOOOO                      #
 #  B   B   E      R   R  NN  N  O   O                      #
 #  BBBBB   EEEE   RRRR   N N N  O   O                      #
 #  B   B   E      R  R   N  NN  O   O                      #
 #  BBBBB   EEEEE  R   R  N   N  OOOOO                      #
 #                                                          #
 ############################################################
EOF
  printf "                  %bBAZI KONIM?%b\n" "$CLR_ACCENT" "$CLR_RESET"
}

render_log_box() {
  local height shown_count start_index i line
  shown_count="${#LOG_LINES[@]}"
  height="$shown_count"
  ((height < LOG_MIN)) && height=$LOG_MIN
  ((height > LOG_MAX)) && height=$LOG_MAX

  echo
  printf "%b----------------------------- ACTION LOG ----------------------------- %b\n" "$CLR_ACCENT" "$CLR_RESET"

  start_index=0
  if ((${#LOG_LINES[@]} > height)); then
    start_index=$((${#LOG_LINES[@]} - height))
  fi

  for ((i=start_index; i<${#LOG_LINES[@]}; i++)); do
    line="${LOG_LINES[$i]}"
    printf "%s\n" "$line"
  done

  local missing=$((height - (${#LOG_LINES[@]} - start_index)))
  for ((i=0; i<missing; i++)); do
    echo
  done

  printf "%b---------------------------------------------------------------------%b\n" "$CLR_ACCENT" "$CLR_RESET"
  echo
}

render_header() {
  clear
  banner
  render_log_box
}

pause_enter() {
  echo
  read -r -p "Press ENTER to return to menu..." _
}

die_soft() {
  add_log "ERROR: $1"
  render_header
  pause_enter
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Re-running with sudo..."
    exec sudo -E bash "$0" "$@"
  fi
}

############################################
# Small helpers
############################################
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

############################################
# Auto-detect public IPv4
############################################
detect_local_ipv4() {
  local ip

  # Try ip route get 1.1.1.1
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
  if [[ -n "$ip" && "$ip" != 127.* ]]; then
    echo "$ip"
    return 0
  fi

  # Try hostname -I
  ip=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\./ && $i !~ /^127\./){print $i; exit}}')
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi

  # Try ip -4 addr show scope global
  ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi

  return 1
}

ask_public_ip_with_autodetect() {
  local side_label="$1" __var="$2"
  local detected choice value

  detected="$(detect_local_ipv4 || true)"
  if [[ -n "$detected" ]]; then
    while true; do
      render_header
      printf "%b>>> %s public IPv4 auto-detection%b\n\n" "$CLR_ACCENT" "$side_label" "$CLR_RESET"
      echo "Detected IPv4 address: $detected"
      echo "[1] Use detected value"
      echo "[2] Enter manually"
      echo
      read -r -p "Choice [1/2]: " choice
      choice="$(trim "$choice")"

      case "$choice" in
        1)
          if valid_ipv4 "$detected"; then
            printf -v "$__var" '%s' "$detected"
            add_log "$side_label IPv4 auto-detected: $detected"
            return 0
          fi
          add_log "Auto-detected IPv4 for $side_label is invalid, falling back to manual."
          break
          ;;
        2)
          break
          ;;
        *)
          add_log "Invalid selection for $side_label IPv4: $choice"
          ;;
      esac
    done
  fi

  # Manual path
  ask_until_valid "$side_label IP :" valid_ipv4 "$__var"
}

############################################
# Input helpers
############################################
ask_until_valid() {
  local prompt="$1" validator="$2" __var="$3"
  local ans=""
  while true; do
    render_header
    printf "%b%s%b " "$CLR_ACCENT" "$prompt" "$CLR_RESET"
    read -r -e ans
    ans="$(trim "$ans")"
    if [[ -z "$ans" ]]; then
      add_log "Empty input for '$prompt'."
      continue
    fi
    if "$validator" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      add_log "OK: $prompt $ans"
      return 0
    else
      add_log "Invalid value for '$prompt': $ans"
    fi
  done
}

PORT_LIST=()

ask_ports() {
  local prompt="Forward PORT (80 | 80,2053 | 2050-2060):"
  local raw=""
  while true; do
    render_header
    printf "%b%s%b " "$CLR_ACCENT" "$prompt" "$CLR_RESET"
    read -r -e raw
    raw="$(trim "$raw")"
    raw="${raw// /}"

    if [[ -z "$raw" ]]; then
      add_log "Empty ports."
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
      add_log "Invalid ports syntax: $raw"
      continue
    fi

    mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
    add_log "Ports accepted: ${PORT_LIST[*]}"
    return 0
  done
}

############################################
# Package helpers
############################################
ensure_iproute_only() {
  add_log "Checking required package: iproute2"
  render_header

  if command -v ip >/dev/null 2>&1; then
    add_log "iproute2 is already installed."
    return 0
  fi

  add_log "Installing iproute2..."
  render_header
  apt-get update -y >/dev/null 2>&1
  apt-get install -y iproute2 >/dev/null 2>&1 && add_log "iproute2 installed." || return 1
  return 0
}

ensure_packages() {
  add_log "Checking required packages: iproute2, haproxy"
  render_header
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=("iproute2")
  command -v haproxy >/dev/null 2>&1 || missing+=("haproxy")

  if ((${#missing[@]}==0)); then
    add_log "All required packages present."
    return 0
  fi

  add_log "Installing: ${missing[*]}"
  render_header
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "${missing[@]}" >/dev/null 2>&1 && add_log "Packages installed." || return 1
  return 0
}

systemd_reload() { systemctl daemon-reload >/dev/null 2>&1; }
unit_exists() { [[ -f "/etc/systemd/system/$1" ]]; }
enable_now() { systemctl enable --now "$1" >/dev/null 2>&1; }

show_unit_status_brief() {
  systemctl --no-pager --full status "$1" 2>&1 | sed -n '1,14p'
}

############################################
# GRE systemd unit
############################################
make_gre_service() {
  local id="$1" local_ip="$2" remote_ip="$3" local_gre_ip="$4" key="$5"
  local unit="gre${id}.service"
  local path="/etc/systemd/system/${unit}"

  if unit_exists "$unit"; then
    add_log "GRE service already exists: $unit"
    return 2
  fi

  add_log "Creating: $path"
  render_header

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

############################################
# HAProxy helpers
############################################
haproxy_unit_exists() {
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx 'haproxy.service'
}

haproxy_write_main_cfg() {
  add_log "Writing base /etc/haproxy/haproxy.cfg"
  render_header

  cat >/etc/haproxy/haproxy.cfg <<'EOF'
# BERNO GRE HAProxy base config
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
    add_log "haproxy-gre${id}.cfg already exists."
    return 2
  fi

  add_log "Creating HAProxy GRE config: $cfg"
  render_header

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
    add_log "haproxy.service not found."
    return 1
  fi

  add_log "Configuring haproxy.service to load conf.d/"
  render_header

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
  render_header
  systemctl enable --now haproxy >/dev/null 2>&1 || true

  add_log "Restarting HAProxy..."
  render_header
  systemctl restart haproxy >/dev/null 2>&1 || true

  render_header
  echo "---- STATUS (haproxy.service) ----"
  systemctl status haproxy --no-pager 2>&1 | sed -n '1,18p'
  echo "---------------------------------"
}

############################################
# IRAN SETUP
############################################
iran_setup() {
  local ID IRANIP KHAREJIP GREBASE
  local key local_gre_ip peer_gre_ip

  # GRE Number
  ask_until_valid "GRE Number :" is_int ID

  # Local public IP (Iran) auto-detect
  ask_public_ip_with_autodetect "IRAN" IRANIP

  # Remote public IP (Kharej)
  ask_until_valid "KHAREJ IP :" valid_ipv4 KHAREJIP

  # GRE range
  ask_until_valid "GRE IP RANGE (Example: 10.80.70.0):" valid_gre_base GREBASE

  # Ports
  ask_ports

  key=$((ID*100))
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"

  add_log "IRAN side: KEY=${key} | IRAN_GRE=${local_gre_ip} | KHAREJ_GRE=${peer_gre_ip}"

  ensure_packages || { die_soft "Package installation failed."; return; }

  make_gre_service "$ID" "$IRANIP" "$KHAREJIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && { die_soft "gre${ID}.service already exists."; return; }
  [[ $rc -ne 0 ]] && { die_soft "Failed creating gre${ID}.service."; return; }

  add_log "Reloading systemd..."
  systemd_reload

  add_log "Enabling gre${ID}.service..."
  enable_now "gre${ID}.service"

  add_log "Writing HAProxy GRE config..."
  haproxy_write_gre_cfg "$ID" "$peer_gre_ip" "${PORT_LIST[@]}"
  local hrc=$?
  if [[ $hrc -eq 2 ]]; then
    die_soft "haproxy-gre${ID}.cfg already exists."
    return
  elif [[ $hrc -ne 0 ]]; then
    die_soft "Failed writing haproxy-gre${ID}.cfg"
    return
  fi

  haproxy_write_main_cfg

  if command -v haproxy >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d/ >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      die_soft "HAProxy config validation failed (haproxy -c)."
      return
    fi
  fi

  haproxy_apply_and_show || { die_soft "Failed applying HAProxy override."; return; }

  # Summary
  render_header
  printf "%b========== IRAN SIDE GRE SUMMARY ==========%b\n\n" "$CLR_ACCENT" "$CLR_RESET"
  echo "Role            : IRAN (GRE forwarder + HAProxy)"
  echo "GRE Number      : $ID"
  echo "Shared key      : $key"
  echo
  echo "Public IP (this server) : $IRANIP"
  echo "Remote public IP        : $KHAREJIP"
  echo
  echo "GRE IPv4 range  : $GREBASE/30"
  echo "Local GRE IP    : $local_gre_ip"
  echo "Remote GRE IP   : $peer_gre_ip"
  echo
  echo "Forwarded ports : ${PORT_LIST[*]}"
  echo "Systemd unit    : gre${ID}.service"
  echo "HAProxy config  : /etc/haproxy/conf.d/haproxy-gre${ID}.cfg"
  echo
  printf "%bRemote (KHAREJ) side must match:%b\n" "$CLR_ACCENT" "$CLR_RESET"
  echo "  - GRE Number        : $ID"
  echo "  - Shared key        : $key"
  echo "  - KHAREJ public IP  : (its own external IP)"
  echo "  - IRAN public IP    : $IRANIP"
  echo "  - GRE range         : $GREBASE"
  echo "  - On KHAREJ side, local GRE IP should be: $peer_gre_ip"
  echo "                         peer GRE IP (IRAN) should be : $local_gre_ip"
  echo

  echo "---- STATUS (gre${ID}.service) ----"
  show_unit_status_brief "gre${ID}.service"
  echo "----------------------------------"
  pause_enter
}

############################################
# KHAREJ SETUP
############################################
kharej_setup() {
  local ID KHAREJIP IRANIP GREBASE
  local key local_gre_ip peer_gre_ip

  ask_until_valid "GRE Number (same as IRAN) :" is_int ID

  # Local public IP (Kharej) auto-detect
  ask_public_ip_with_autodetect "KHAREJ" KHAREJIP

  # Remote public IP (Iran)
  ask_until_valid "IRAN IP :" valid_ipv4 IRANIP

  ask_until_valid "GRE IP RANGE (Example: 10.80.70.0) same as IRAN:" valid_gre_base GREBASE

  key=$((ID*100))
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"

  add_log "KHAREJ side: KEY=${key} | KHAREJ_GRE=${local_gre_ip} | IRAN_GRE=${peer_gre_ip}"

  ensure_iproute_only || { die_soft "Package installation failed (iproute2)."; return; }

  make_gre_service "$ID" "$KHAREJIP" "$IRANIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && { die_soft "gre${ID}.service already exists."; return; }
  [[ $rc -ne 0 ]] && { die_soft "Failed creating gre${ID}.service."; return; }

  add_log "Reloading systemd..."
  systemd_reload

  add_log "Enabling gre${ID}.service..."
  enable_now "gre${ID}.service"

  # Summary
  render_header
  printf "%b========== KHAREJ SIDE GRE SUMMARY ==========%b\n\n" "$CLR_ACCENT" "$CLR_RESET"
  echo "Role            : KHAREJ (GRE endpoint only)"
  echo "GRE Number      : $ID"
  echo "Shared key      : $key"
  echo
  echo "Public IP (this server) : $KHAREJIP"
  echo "Remote public IP        : $IRANIP"
  echo
  echo "GRE IPv4 range  : $GREBASE/30"
  echo "Local GRE IP    : $local_gre_ip"
  echo "Remote GRE IP   : $peer_gre_ip"
  echo
  printf "%bIRAN side must match:%b\n" "$CLR_ACCENT" "$CLR_RESET"
  echo "  - GRE Number        : $ID"
  echo "  - Shared key        : $key"
  echo "  - IRAN public IP    : $IRANIP"
  echo "  - KHAREJ public IP  : $KHAREJIP"
  echo "  - GRE range         : $GREBASE"
  echo "  - On IRAN side, local GRE IP should be: $peer_gre_ip"
  echo "                        peer GRE IP (KHAREJ) should be : $local_gre_ip"
  echo
  echo "---- STATUS (gre${ID}.service) ----"
  show_unit_status_brief "gre${ID}.service"
  echo "----------------------------------"
  pause_enter
}

############################################
# Introspection helpers
############################################
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
    render_header
    printf "%b%s%b\n\n" "$CLR_ACCENT" "$title" "$CLR_RESET"

    if ((${#items[@]} == 0)); then
      echo "No items found."
      echo
      read -r -p "Press ENTER to go back..." _
      MENU_SELECTED=-1
      return 1
    fi

    local i
    for ((i=0; i<${#items[@]}; i++)); do
      printf "%2d) %s\n" $((i+1)) "${items[$i]}"
    done
    echo " 0) Back"
    echo

    read -r -p "$prompt " choice
    choice="$(trim "$choice")"

    if [[ "$choice" == "0" ]]; then
      MENU_SELECTED=-1
      return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#items[@]})); then
      MENU_SELECTED=$((choice-1))
      return 0
    fi

    add_log "Invalid menu selection: $choice"
  done
}

service_action_menu() {
  local unit="$1"
  local action=""

  while true; do
    render_header
    printf "%bService:%b %s\n\n" "$CLR_ACCENT" "$CLR_RESET" "$unit"
    echo "1) Enable & Start"
    echo "2) Restart"
    echo "3) Stop & Disable"
    echo "4) Status"
    echo "0) Back"
    echo

    read -r -p "Select action: " action
    action="$(trim "$action")"

    case "$action" in
      1)
        add_log "Enable & Start: $unit"
        systemctl enable "$unit" >/dev/null 2>&1 && add_log "Enabled: $unit"
        systemctl start "$unit"  >/dev/null 2>&1 && add_log "Started: $unit"
        ;;
      2)
        add_log "Restart: $unit"
        systemctl restart "$unit" >/dev/null 2>&1 && add_log "Restarted: $unit"
        ;;
      3)
        add_log "Stop & Disable: $unit"
        systemctl stop "$unit"    >/dev/null 2>&1 || true
        systemctl disable "$unit" >/dev/null 2>&1 || true
        ;;
      4)
        render_header
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
    render_header
    printf "%bServices Management%b\n\n" "$CLR_ACCENT" "$CLR_RESET"
    echo "1) GRE services"
    echo "2) HAProxy service"
    echo "0) Back"
    echo
    read -r -p "Select: " sel
    sel="$(trim "$sel")"

    case "$sel" in
      1)
        mapfile -t GRE_IDS < <(get_gre_ids)
        local -a GRE_LABELS=()
        local id
        for id in "${GRE_IDS[@]}"; do
          GRE_LABELS+=("gre${id}.service")
        done

        if menu_select_index "GRE Services" "Select GRE:" "${GRE_LABELS[@]}"; then
          local idx="$MENU_SELECTED"
          id="${GRE_IDS[$idx]}"
          service_action_menu "gre${id}.service"
        fi
        ;;
      2)
        if ! haproxy_unit_exists; then
          add_log "haproxy.service not found."
          pause_enter
          continue
        fi
        service_action_menu "haproxy.service"
        ;;
      0) return 0 ;;
      *) add_log "Invalid selection: $sel" ;;
    esac
  done
}

############################################
# Delete GRE tunnel (config + HAProxy)
############################################
uninstall_clean() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=()
  local id
  for id in "${GRE_IDS[@]}"; do
    GRE_LABELS+=("GRE${id}")
  done

  if ! menu_select_index "Delete GRE tunnel" "Select GRE to delete:" "${GRE_LABELS[@]}"; then
    return
  fi

  local idx="$MENU_SELECTED"
  id="${GRE_IDS[$idx]}"

  while true; do
    render_header
    echo "You are about to delete GRE${id} configuration:"
    echo "  - /etc/systemd/system/gre${id}.service"
    echo "  - /etc/haproxy/conf.d/haproxy-gre${id}.cfg (if exists)"
    echo
    read -r -p "Type YES to confirm, NO to cancel: " confirm
    confirm="$(trim "$confirm")"

    case "$confirm" in
      NO|no)
        add_log "Delete cancelled for GRE${id}"
        return
        ;;
      YES)
        break
        ;;
      *)
        add_log "Please type YES or NO."
        ;;
    esac
  done

  add_log "Stopping gre${id}.service"
  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  add_log "Disabling gre${id}.service"
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true

  add_log "Removing systemd unit for GRE${id}"
  rm -f "/etc/systemd/system/gre${id}.service" >/dev/null 2>&1 || true

  add_log "Removing HAProxy GRE config for GRE${id}"
  rm -f "/etc/haproxy/conf.d/haproxy-gre${id}.cfg" >/dev/null 2>&1 || true

  add_log "Reloading systemd & resetting failed units"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed  >/dev/null 2>&1 || true

  if haproxy_unit_exists; then
    add_log "Restarting haproxy..."
    systemctl restart haproxy >/dev/null 2>&1 || true
  fi

  add_log "GRE${id} fully removed."
  render_header
  echo "GRE${id} has been deleted (as if it never existed)."
  pause_enter
}

############################################
# Add extra tunnel ports to existing GRE
############################################
get_gre_local_ip_cidr() {
  local id="$1"
  ip -4 -o addr show dev "gre${id}" 2>/dev/null | awk '{print $4}' | head -n1
}

get_peer_ip_from_local_cidr() {
  local cidr="$1"
  local ip="${cidr%/*}"
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
    add_log "Config not found: $cfg"
    return 1
  fi

  add_log "Editing HAProxy config: $cfg"
  render_header

  local p added=0 skipped=0
  for p in "${ports[@]}"; do
    if grep -qE "^frontend[[:space:]]+gre${id}_fe_${p}\b" "$cfg" 2>/dev/null; then
      add_log "Skip existing port $p for GRE${id}"
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

    add_log "Added port $p for GRE${id} -> ${target_ip}:${p}"
    ((added++))
  done

  add_log "HAProxy update finished: added=${added}, skipped=${skipped}"
  return 0
}

add_tunnel_port() {
  render_header
  add_log "Selected: add tunnel port"

  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=()
  local id
  for id in "${GRE_IDS[@]}"; do
    GRE_LABELS+=("GRE${id}")
  done

  if ! menu_select_index "Add Tunnel Port" "Select GRE:" "${GRE_LABELS[@]}"; then
    return
  fi

  local idx="$MENU_SELECTED"
  id="${GRE_IDS[$idx]}"

  local cidr peer_ip
  cidr="$(get_gre_local_ip_cidr "$id")"
  if [[ -z "$cidr" ]]; then
    die_soft "Could not detect IPv4 address on gre${id}. Is it up?"
    return
  fi

  peer_ip="$(get_peer_ip_from_local_cidr "$cidr")"
  add_log "gre${id}: local=${cidr}, peer=${peer_ip}"

  PORT_LIST=()
  ask_ports

  haproxy_add_ports_to_gre_cfg "$id" "$peer_ip" "${PORT_LIST[@]}" || {
    die_soft "Failed editing haproxy-gre${id}.cfg"
    return
  }

  if command -v haproxy >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d/ >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      die_soft "HAProxy config validation failed (haproxy -c)."
      return
    fi
  fi

  if haproxy_unit_exists; then
    add_log "Restarting haproxy..."
    systemctl restart haproxy >/dev/null 2>&1 || true
    add_log "haproxy restarted."
  fi

  render_header
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
# Main menu
############################################
main_menu() {
  local choice=""
  while true; do
    render_header
    printf "%bMAIN MENU%b\n\n" "$CLR_ACCENT" "$CLR_RESET"
    echo "1 > IRAN SETUP       (GRE + HAProxy forwarder)"
    echo "2 > KHAREJ SETUP     (GRE endpoint only)"
    echo "3 > Services Management"
    echo "4 > Delete GRE tunnel (config + ports)"
    echo "5 > Add tunnel port to existing GRE"
    echo "0 > Exit"
    echo
    read -r -p "Select option: " choice
    choice="$(trim "$choice")"

    case "$choice" in
      1) add_log "Selected: IRAN SETUP"; iran_setup ;;
      2) add_log "Selected: KHAREJ SETUP"; kharej_setup ;;
      3) add_log "Selected: Services Management"; services_management ;;
      4) add_log "Selected: Delete GRE tunnel"; uninstall_clean ;;
      5) add_log "Selected: Add tunnel port"; add_tunnel_port ;;
      0)
        add_log "Exiting."
        render_header
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
add_log "BERNO GRE + HAProxy forwarder (refactored version)."
main_menu
