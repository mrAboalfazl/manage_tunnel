#!/bin/bash
# gre.sh - GRE Tunnel & Port Forwarding Manager
# Creates GRE tunnels and forwards ports via kernel-level iptables DNAT (no socat)

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── Print Helpers ────────────────────────────────────────────────────────────
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error()   { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
print_header()  { echo -e "${BOLD}${CYAN}$1${NC}"; }
print_step()    { echo -e "${PURPLE}→${NC} $1"; }

# ─── Constants ────────────────────────────────────────────────────────────────
GRE_DIR=/opt/gre

# ─── Name-based path helpers ─────────────────────────────────────────────────
get_config_dir()   { echo "${GRE_DIR}/$1"; }
get_config_file()  { echo "${GRE_DIR}/$1/config.env"; }
get_service_name() { echo "gre-$1"; }
get_start_script() { echo "${GRE_DIR}/$1/start.sh"; }
get_stop_script()  { echo "${GRE_DIR}/$1/stop.sh"; }

# Generate a GRE interface name that fits the 15-char Linux limit.
# Uses "gre-" prefix (4 chars) + up to 11 chars from the name.
# If the name is too long, it gets truncated and a short hash suffix is added for uniqueness.
get_gre_iface() {
    local name="$1"
    local prefix="gre-"
    local max_len=15
    local avail=$((max_len - ${#prefix}))  # 11 chars available

    if [ ${#name} -le $avail ]; then
        echo "${prefix}${name}"
    else
        # Truncate + append 4-char hash for uniqueness
        local hash
        hash=$(echo -n "$name" | md5sum | cut -c1-4)
        local trunc=$((avail - 5))  # 5 = dash + 4 hash chars
        local short="${name:0:$trunc}"
        short="${short%-}"  # strip trailing dash to avoid double dash
        echo "${prefix}${short}-${hash}"
    fi
}

validate_tunnel_name() {
    local name="$1"
    if [[ "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
        return 0
    fi
    return 1
}

# ─── Utility Functions ────────────────────────────────────────────────────────
get_public_ip() {
    local ip tmpdir
    print_step "Detecting public IP address..." >&2

    tmpdir=$(mktemp -d)

    # Race Cloudflare trace endpoints in parallel — first valid IP wins (3s timeout)
    local endpoints=(
        "https://one.one.one.one/cdn-cgi/trace"
        "https://1.0.0.1/cdn-cgi/trace"
        "https://cloudflare-dns.com/cdn-cgi/trace"
        "https://cloudflare-eth.com/cdn-cgi/trace"
        "https://workers.dev/cdn-cgi/trace"
        "https://pages.dev/cdn-cgi/trace"
        "https://cloudflare.tv/cdn-cgi/trace"
        "https://icanhazip.com/cdn-cgi/trace"
    )

    local i=0
    for endpoint in "${endpoints[@]}"; do
        i=$((i + 1))
        (curl -s --max-time 3 "$endpoint" 2>/dev/null | grep "^ip=" | cut -d'=' -f2 | tr -d '[:space:]' > "$tmpdir/$i") &
    done
    wait

    for f in "$tmpdir"/*; do
        ip=$(<"$f")
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            rm -rf "$tmpdir"
            print_success "Public IP detected: ${BOLD}$ip${NC}" >&2
            echo "$ip"
            return 0
        fi
    done

    rm -rf "$tmpdir"
    print_warning "Could not detect public IP automatically." >&2
    return 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then return 1; fi
        done
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

validate_gre_network() {
    # Must be x.x.x.0
    local ip="$1"
    if validate_ip "$ip" && [[ "$ip" =~ \.0$ ]]; then
        return 0
    fi
    return 1
}

validate_mtu() {
    local m="$1"
    if [[ "$m" =~ ^[0-9]+$ ]] && [ "$m" -ge 576 ] && [ "$m" -le 1500 ]; then
        return 0
    fi
    return 1
}

command_exists() {
    command -v "$1" &>/dev/null
}

# Parse port spec: "80" or "80,443,2053" or "2050-2060" into a sorted unique list
# Port format: "local:remote" or just "port" (same on both sides)
# Examples: "7000:20820,443,80:8080" or "2050-2060" (range, same ports both sides)
# Stored as: "7000:20820,443:443,80:8080,2050:2050,...,2060:2060"
parse_ports() {
    local raw="$1"
    local -a result=()

    # Remove spaces
    raw="${raw// /}"

    IFS=',' read -r -a parts <<< "$raw"
    for part in "${parts[@]}"; do
        if [[ "$part" =~ ^([0-9]+):([0-9]+)$ ]]; then
            # Explicit mapping: local_port:remote_port
            local lp="${BASH_REMATCH[1]}" rp="${BASH_REMATCH[2]}"
            if ! validate_port "$lp"; then print_error "Invalid local port: ${lp}"; return 1; fi
            if ! validate_port "$rp"; then print_error "Invalid remote port: ${rp}"; return 1; fi
            result+=("${lp}:${rp}")
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            # Range: expands to same:same for each port
            local start="${BASH_REMATCH[1]}" end="${BASH_REMATCH[2]}"
            if validate_port "$start" && validate_port "$end" && [ "$start" -le "$end" ]; then
                for ((p=start; p<=end; p++)); do
                    result+=("${p}:${p}")
                done
            else
                print_error "Invalid port range: ${part}"
                return 1
            fi
        elif validate_port "$part"; then
            # Single port: same on both sides
            result+=("${part}:${part}")
        else
            print_error "Invalid port spec: ${part}"
            return 1
        fi
    done

    # Deduplicate by local port, keep order
    local -A seen
    local -a unique=()
    for entry in "${result[@]}"; do
        local lp="${entry%%:*}"
        if [ -z "${seen[$lp]:-}" ]; then
            seen[$lp]=1
            unique+=("$entry")
        fi
    done

    printf '%s\n' "${unique[@]}" | tr '\n' ',' | sed 's/,$//'
}

# Pretty-print port mappings for display
format_ports() {
    local ports="$1"
    [ -z "$ports" ] && echo "none" && return
    local -a out=()
    IFS=',' read -r -a entries <<< "$ports"
    for entry in "${entries[@]}"; do
        local lp="${entry%%:*}" rp="${entry##*:}"
        if [ "$lp" = "$rp" ]; then
            out+=("$lp")
        else
            out+=("${lp}->${rp}")
        fi
    done
    echo "${out[*]}" | tr ' ' ','
}

# ─── Config Storage ──────────────────────────────────────────────────────────
save_config() {
    local config_dir
    config_dir=$(get_config_dir "$TUNNEL_NAME")
    local config_file
    config_file=$(get_config_file "$TUNNEL_NAME")

    mkdir -p "$config_dir"
    cat > "$config_file" << EOF
# GRE Tunnel - ${TUNNEL_NAME} - Generated $(date)
ROLE=${ROLE}
LOCAL_IP=${LOCAL_IP}
REMOTE_IP=${REMOTE_IP}
GRE_NETWORK=${GRE_NETWORK}
LOCAL_GRE_IP=${LOCAL_GRE_IP}
PEER_GRE_IP=${PEER_GRE_IP}
GRE_KEY=${GRE_KEY}
MTU=${MTU:-}
PORTS=${PORTS:-}
EOF
    print_success "Configuration saved to ${config_file}"
}

load_config() {
    local config_file
    config_file=$(get_config_file "$TUNNEL_NAME")
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    # shellcheck disable=SC1090
    source "$config_file"
    return 0
}

# ─── Script Generators ───────────────────────────────────────────────────────
generate_start_script() {
    local script
    script=$(get_start_script "$TUNNEL_NAME")
    local gre_iface
    gre_iface=$(get_gre_iface "$TUNNEL_NAME")

    cat > "$script" << 'SCRIPT_HEAD'
#!/bin/bash
set -e
SCRIPT_HEAD

    cat >> "$script" << EOF
GRE_IFACE="${gre_iface}"
LOCAL_IP="${LOCAL_IP}"
REMOTE_IP="${REMOTE_IP}"
LOCAL_GRE_IP="${LOCAL_GRE_IP}"
GRE_KEY="${GRE_KEY}"
MTU="${MTU:-}"
ROLE="${ROLE}"
PEER_GRE_IP="${PEER_GRE_IP}"
PORTS="${PORTS:-}"
EOF

    cat >> "$script" << 'SCRIPT_BODY'

# Remove old tunnel if exists
ip tunnel del "$GRE_IFACE" 2>/dev/null || true

# Create GRE tunnel
ip tunnel add "$GRE_IFACE" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" key "$GRE_KEY" nopmtudisc
ip addr add "${LOCAL_GRE_IP}/30" dev "$GRE_IFACE"
[ -n "$MTU" ] && ip link set "$GRE_IFACE" mtu "$MTU"
ip link set "$GRE_IFACE" up

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Iran side: set up iptables DNAT forwarding for all ports
# Port format: local_port:remote_port (e.g. 7000:20820)
if [ "$ROLE" = "iran" ] && [ -n "$PORTS" ]; then
    IFS=',' read -r -a port_list <<< "$PORTS"
    for mapping in "${port_list[@]}"; do
        local_port="${mapping%%:*}"
        remote_port="${mapping##*:}"
        # DNAT incoming traffic on local_port to peer's remote_port (TCP + UDP)
        iptables -t nat -A PREROUTING -p tcp --dport "$local_port" -j DNAT --to-destination "${PEER_GRE_IP}:${remote_port}" 2>/dev/null || true
        iptables -t nat -A PREROUTING -p udp --dport "$local_port" -j DNAT --to-destination "${PEER_GRE_IP}:${remote_port}" 2>/dev/null || true
    done

    # MASQUERADE so return traffic comes back through us
    iptables -t nat -C POSTROUTING -o "$GRE_IFACE" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -o "$GRE_IFACE" -j MASQUERADE 2>/dev/null || true

    # Allow forwarding through the tunnel
    iptables -C FORWARD -o "$GRE_IFACE" -j ACCEPT 2>/dev/null ||
        iptables -A FORWARD -o "$GRE_IFACE" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -i "$GRE_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
        iptables -A FORWARD -i "$GRE_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi

echo "GRE tunnel $GRE_IFACE is up"
SCRIPT_BODY

    chmod +x "$script"
}

generate_stop_script() {
    local script
    script=$(get_stop_script "$TUNNEL_NAME")
    local gre_iface
    gre_iface=$(get_gre_iface "$TUNNEL_NAME")

    cat > "$script" << 'SCRIPT_HEAD'
#!/bin/bash
SCRIPT_HEAD

    cat >> "$script" << EOF
GRE_IFACE="${gre_iface}"
ROLE="${ROLE}"
PEER_GRE_IP="${PEER_GRE_IP}"
PORTS="${PORTS:-}"
EOF

    cat >> "$script" << 'SCRIPT_BODY'

# Remove iptables rules (Iran side)
if [ "$ROLE" = "iran" ] && [ -n "$PORTS" ]; then
    IFS=',' read -r -a port_list <<< "$PORTS"
    for mapping in "${port_list[@]}"; do
        local_port="${mapping%%:*}"
        remote_port="${mapping##*:}"
        iptables -t nat -D PREROUTING -p tcp --dport "$local_port" -j DNAT --to-destination "${PEER_GRE_IP}:${remote_port}" 2>/dev/null || true
        iptables -t nat -D PREROUTING -p udp --dport "$local_port" -j DNAT --to-destination "${PEER_GRE_IP}:${remote_port}" 2>/dev/null || true
    done
    iptables -t nat -D POSTROUTING -o "$GRE_IFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -o "$GRE_IFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$GRE_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi

# Tear down tunnel
ip link set "$GRE_IFACE" down 2>/dev/null || true
ip tunnel del "$GRE_IFACE" 2>/dev/null || true

echo "GRE tunnel $GRE_IFACE is down"
SCRIPT_BODY

    chmod +x "$script"
}

# ─── Systemd Service ─────────────────────────────────────────────────────────
create_service() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    local start_script
    start_script=$(get_start_script "$TUNNEL_NAME")
    local stop_script
    stop_script=$(get_stop_script "$TUNNEL_NAME")

    generate_start_script
    generate_stop_script

    print_step "Creating systemd service ${svc_name}..."
    cat > "/etc/systemd/system/${svc_name}.service" << EOF
[Unit]
Description=GRE tunnel ${ROLE} - ${TUNNEL_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${start_script}
ExecStop=${stop_script}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${svc_name}" 2>/dev/null
    print_success "Service ${svc_name} created and started"
    echo
}

# ─── List Tunnels ────────────────────────────────────────────────────────────
list_tunnels() {
    local found=false
    if [ ! -d "$GRE_DIR" ]; then
        print_warning "No tunnels configured"
        return
    fi

    echo
    print_header "Configured GRE Tunnels"
    echo
    printf "  ${BOLD}%-18s %-8s %-10s %-16s %-16s %s${NC}\n" "NAME" "ROLE" "STATUS" "GRE IPs" "REMOTE" "PORTS"
    printf "  %-18s %-8s %-10s %-16s %-16s %s\n" "──────────────────" "────────" "──────────" "────────────────" "────────────────" "────────────────"

    for config_dir in "${GRE_DIR}"/*/; do
        [ -d "$config_dir" ] || continue
        local cf="${config_dir}config.env"
        [ -f "$cf" ] || continue
        found=true

        local name
        name=$(basename "$config_dir")
        local svc_name
        svc_name=$(get_service_name "$name")

        local role local_gre peer_gre remote ports
        role=$(grep '^ROLE=' "$cf" 2>/dev/null | cut -d= -f2)
        local_gre=$(grep '^LOCAL_GRE_IP=' "$cf" 2>/dev/null | cut -d= -f2)
        peer_gre=$(grep '^PEER_GRE_IP=' "$cf" 2>/dev/null | cut -d= -f2)
        remote=$(grep '^REMOTE_IP=' "$cf" 2>/dev/null | cut -d= -f2)
        ports=$(grep '^PORTS=' "$cf" 2>/dev/null | cut -d= -f2)

        local gre_ips="${local_gre:-?}<>${peer_gre:-?}"

        local status_text status_color
        if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
            status_text="active"
            status_color="${GREEN}"
        else
            status_text="inactive"
            status_color="${RED}"
        fi

        # Format and truncate ports for display
        local ports_display
        ports_display=$(format_ports "${ports:-}")
        [ ${#ports_display} -gt 16 ] && ports_display="${ports_display:0:13}..."

        printf "  %-18s %-8s ${status_color}%-10s${NC} %-16s %-16s %s\n" \
            "$name" "${role:-?}" "$status_text" "$gre_ips" "${remote:-?}" "$ports_display"
    done

    if [ "$found" = "false" ]; then
        print_warning "No tunnels configured"
    fi
    echo
}

pick_tunnel_name() {
    local prompt="${1:-Select tunnel}"
    local names=()

    for config_dir in "${GRE_DIR}"/*/; do
        [ -d "$config_dir" ] || continue
        [ -f "${config_dir}config.env" ] || continue
        names+=("$(basename "$config_dir")")
    done

    if [ ${#names[@]} -eq 0 ]; then
        print_warning "No tunnels configured"
        return 1
    fi

    if [ ${#names[@]} -eq 1 ]; then
        TUNNEL_NAME="${names[0]}"
        print_info "Using tunnel: ${TUNNEL_NAME}"
        return 0
    fi

    echo
    print_header "$prompt"
    local i=1
    for name in "${names[@]}"; do
        echo -e "  ${GREEN}${i})${NC} ${name}"
        i=$((i + 1))
    done
    read -r -p "Select [1-${#names[@]}]: " idx

    if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le ${#names[@]} ]; then
        TUNNEL_NAME="${names[$((idx - 1))]}"
        return 0
    else
        print_error "Invalid selection"
        return 1
    fi
}

# ─── Management Functions ────────────────────────────────────────────────────
show_status() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")

    echo
    print_header "GRE Status: ${TUNNEL_NAME}"
    echo
    systemctl status "${svc_name}" --no-pager 2>/dev/null || print_warning "Service ${svc_name} not found or not running"
    echo

    if load_config; then
        print_header "Configuration: ${TUNNEL_NAME}"
        echo
        print_info "Role: ${ROLE}"
        print_info "Local IP: ${LOCAL_IP}"
        print_info "Remote IP: ${REMOTE_IP}"
        print_info "GRE network: ${GRE_NETWORK}"
        print_info "Local GRE IP: ${LOCAL_GRE_IP}"
        print_info "Peer GRE IP: ${PEER_GRE_IP}"
        print_info "GRE key: ${GRE_KEY}"
        [ -n "${MTU:-}" ] && print_info "MTU: ${MTU}"
        [ -n "${PORTS:-}" ] && print_info "Forwarded ports: $(format_ports "$PORTS")"

        # Show interface status
        local gre_iface
        gre_iface=$(get_gre_iface "$TUNNEL_NAME")
        if ip link show "$gre_iface" &>/dev/null; then
            print_info "Interface ${gre_iface}: UP"
        else
            print_warning "Interface ${gre_iface}: DOWN"
        fi
    else
        print_warning "No configuration found for ${TUNNEL_NAME}"
    fi
    echo
}

restart_service() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    print_step "Restarting ${svc_name}..."
    if systemctl restart "${svc_name}" 2>/dev/null; then
        print_success "Service ${svc_name} restarted"
    else
        print_error "Failed to restart ${svc_name}"
    fi
}

stop_service() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    print_step "Stopping ${svc_name}..."
    if systemctl stop "${svc_name}" 2>/dev/null; then
        print_success "Service ${svc_name} stopped"
    else
        print_error "Failed to stop ${svc_name} (may not be running)"
    fi
}

view_logs() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    print_header "Logs: ${svc_name} (Ctrl+C to exit)"
    echo
    journalctl -u "${svc_name}" -f --no-pager -n 50
}

# ─── Add/Remove Ports ────────────────────────────────────────────────────────
add_ports() {
    local new_ports="$1"

    if ! load_config; then
        print_error "No configuration found for ${TUNNEL_NAME}"
        return 1
    fi

    if [ "$ROLE" != "iran" ]; then
        print_error "Port forwarding is only configured on the Iran side"
        return 1
    fi

    local parsed
    parsed=$(parse_ports "$new_ports") || return 1

    # Merge: new entries override existing by local port
    if [ -n "${PORTS:-}" ]; then
        # Build map of new local ports
        local -A new_map
        IFS=',' read -r -a new_entries <<< "$parsed"
        for entry in "${new_entries[@]}"; do
            local lp="${entry%%:*}"
            new_map[$lp]="$entry"
        done

        # Keep old entries that don't conflict, then append new
        local -a merged=()
        IFS=',' read -r -a old_entries <<< "$PORTS"
        for entry in "${old_entries[@]}"; do
            local lp="${entry%%:*}"
            if [ -z "${new_map[$lp]:-}" ]; then
                merged+=("$entry")
            fi
        done
        for entry in "${new_entries[@]}"; do
            merged+=("$entry")
        done
        PORTS=$(printf '%s\n' "${merged[@]}" | tr '\n' ',' | sed 's/,$//')
    else
        PORTS="$parsed"
    fi

    save_config
    generate_start_script
    generate_stop_script

    # Restart to apply new rules
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    systemctl restart "${svc_name}" 2>/dev/null
    print_success "Ports updated: $(format_ports "$PORTS")"
}

remove_ports() {
    local rm_ports="$1"

    if ! load_config; then
        print_error "No configuration found for ${TUNNEL_NAME}"
        return 1
    fi

    # Parse removal specs - extract just the local ports to remove
    local -A remove_set
    local raw="${rm_ports// /}"
    IFS=',' read -r -a rm_parts <<< "$raw"
    for part in "${rm_parts[@]}"; do
        # Accept "7000:20820" or just "7000" - we match by local port
        local lp="${part%%:*}"
        if validate_port "$lp"; then
            remove_set[$lp]=1
        else
            print_error "Invalid port: ${lp}"
            return 1
        fi
    done

    # Keep entries whose local port is not in the removal set
    local -a remaining=()
    IFS=',' read -r -a current <<< "$PORTS"
    for entry in "${current[@]}"; do
        local lp="${entry%%:*}"
        if [ -z "${remove_set[$lp]:-}" ]; then
            remaining+=("$entry")
        fi
    done

    if [ ${#remaining[@]} -gt 0 ]; then
        PORTS=$(printf '%s\n' "${remaining[@]}" | tr '\n' ',' | sed 's/,$//')
    else
        PORTS=""
    fi

    save_config
    generate_start_script
    generate_stop_script

    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    systemctl restart "${svc_name}" 2>/dev/null
    print_success "Ports updated: $(format_ports "${PORTS:-}")"
}

# ─── Change MTU ──────────────────────────────────────────────────────────────
change_mtu() {
    local new_mtu="$1"

    if ! load_config; then
        print_error "No configuration found for ${TUNNEL_NAME}"
        return 1
    fi

    MTU="$new_mtu"
    save_config
    generate_start_script

    # Apply live
    local gre_iface
    gre_iface=$(get_gre_iface "$TUNNEL_NAME")
    ip link set "$gre_iface" mtu "$new_mtu" 2>/dev/null || true
    print_success "MTU changed to ${new_mtu} for ${TUNNEL_NAME}"
}

# ─── Uninstall ───────────────────────────────────────────────────────────────
uninstall_tunnel() {
    local svc_name
    svc_name=$(get_service_name "$TUNNEL_NAME")
    local config_dir
    config_dir=$(get_config_dir "$TUNNEL_NAME")

    echo
    print_warning "This will remove tunnel '${TUNNEL_NAME}' (service ${svc_name})."
    if [ "${FORCE_YES:-}" != "true" ]; then
        read -r -p "Are you sure? (y/n) [n]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "Cancelled"
            return
        fi
    fi
    echo

    print_step "Stopping ${svc_name}..."
    systemctl stop "${svc_name}" 2>/dev/null || true

    print_step "Disabling ${svc_name}..."
    systemctl disable "${svc_name}" 2>/dev/null || true

    print_step "Removing service file..."
    rm -f "/etc/systemd/system/${svc_name}.service"
    systemctl daemon-reload

    # Clean up tunnel interface
    local gre_iface
    gre_iface=$(get_gre_iface "$TUNNEL_NAME")
    ip link set "$gre_iface" down 2>/dev/null || true
    ip tunnel del "$gre_iface" 2>/dev/null || true

    print_step "Removing configuration..."
    rm -rf "$config_dir"

    print_success "Tunnel '${TUNNEL_NAME}' removed"
    echo
}

uninstall_all() {
    echo
    print_warning "This will remove ALL GRE tunnels and configurations."
    if [ "${FORCE_YES:-}" != "true" ]; then
        read -r -p "Are you sure? (y/n) [n]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "Cancelled"
            return
        fi
    fi
    echo

    if [ -d "$GRE_DIR" ]; then
        for config_dir in "${GRE_DIR}"/*/; do
            [ -d "$config_dir" ] || continue
            [ -f "${config_dir}config.env" ] || continue
            local name
            name=$(basename "$config_dir")
            local svc_name
            svc_name=$(get_service_name "$name")

            print_step "Stopping ${svc_name}..."
            systemctl stop "${svc_name}" 2>/dev/null || true
            systemctl disable "${svc_name}" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc_name}.service"

            local gre_iface
            gre_iface=$(get_gre_iface "$name")
            ip link set "$gre_iface" down 2>/dev/null || true
            ip tunnel del "$gre_iface" 2>/dev/null || true
        done
    fi

    systemctl daemon-reload
    print_step "Removing all configurations..."
    rm -rf "$GRE_DIR"
    print_success "All GRE tunnels removed"
    echo
}

# ─── Interactive Mode ─────────────────────────────────────────────────────────
interactive_menu() {
    while true; do
        echo
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║       GRE Tunnel Manager         ║${NC}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════╝${NC}"
        echo
        echo -e "  ${GREEN}1)${NC}  Configure tunnel (Iran)"
        echo -e "  ${GREEN}2)${NC}  Configure tunnel (Kharej)"
        echo -e "  ${GREEN}3)${NC}  List tunnels"
        echo -e "  ${GREEN}4)${NC}  Show status"
        echo -e "  ${GREEN}5)${NC}  Restart tunnel"
        echo -e "  ${GREEN}6)${NC}  Stop tunnel"
        echo -e "  ${GREEN}7)${NC}  Add ports"
        echo -e "  ${GREEN}8)${NC}  Remove ports"
        echo -e "  ${GREEN}9)${NC}  Change MTU"
        echo -e "  ${GREEN}10)${NC} Uninstall tunnel"
        echo -e "  ${GREEN}11)${NC} Uninstall all"
        echo -e "  ${GREEN}12)${NC} View logs"
        echo -e "  ${RED}0)${NC}  Exit"
        echo
        read -r -p "Select an option [0-12]: " choice

        case "$choice" in
            1)  interactive_setup "iran" ;;
            2)  interactive_setup "kharej" ;;
            3)  list_tunnels ;;
            4)
                if pick_tunnel_name "Select tunnel to view status"; then
                    show_status
                fi
                ;;
            5)
                if pick_tunnel_name "Select tunnel to restart"; then
                    restart_service
                fi
                ;;
            6)
                if pick_tunnel_name "Select tunnel to stop"; then
                    stop_service
                fi
                ;;
            7)
                if pick_tunnel_name "Select tunnel to add ports"; then
                    echo
                    read -r -p "Ports to add (e.g. 80,443,7000:20820 or 2050-2060): " new_ports
                    add_ports "$new_ports"
                fi
                ;;
            8)
                if pick_tunnel_name "Select tunnel to remove ports"; then
                    load_config
                    print_info "Current ports: $(format_ports "${PORTS:-}")"
                    read -r -p "Ports to remove: " rm_ports
                    remove_ports "$rm_ports"
                fi
                ;;
            9)
                if pick_tunnel_name "Select tunnel to change MTU"; then
                    read -r -p "New MTU (576-1500): " new_mtu
                    if validate_mtu "$new_mtu"; then
                        change_mtu "$new_mtu"
                    else
                        print_error "Invalid MTU: ${new_mtu}"
                    fi
                fi
                ;;
            10)
                if pick_tunnel_name "Select tunnel to uninstall"; then
                    uninstall_tunnel
                fi
                ;;
            11) uninstall_all ;;
            12)
                if pick_tunnel_name "Select tunnel to view logs"; then
                    view_logs
                fi
                ;;
            0) echo; print_info "Goodbye!"; exit 0 ;;
            *) print_error "Invalid option" ;;
        esac
    done
}

interactive_setup() {
    ROLE="$1"
    echo

    # Tunnel name
    read -r -p "Enter a name for this tunnel (e.g. melbi-1, virak-1): " TUNNEL_NAME
    if [ -z "$TUNNEL_NAME" ]; then
        print_error "Tunnel name is required"
        return
    fi
    if ! validate_tunnel_name "$TUNNEL_NAME"; then
        print_error "Invalid name. Use letters, numbers, dots, hyphens, underscores."
        return
    fi

    # Warn if overwriting
    local config_file
    config_file=$(get_config_file "$TUNNEL_NAME")
    if [ -f "$config_file" ]; then
        print_warning "Tunnel '${TUNNEL_NAME}' already exists. This will overwrite it."
        read -r -p "Continue? (y/n) [n]: " overwrite
        overwrite="${overwrite:-n}"
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then return; fi
        local svc_name
        svc_name=$(get_service_name "$TUNNEL_NAME")
        systemctl stop "${svc_name}" 2>/dev/null || true
    fi

    echo
    print_header "═══ GRE ${ROLE^} Setup ═══"
    echo

    # Auto-detect local public IP
    local detected_ip
    detected_ip=$(get_public_ip) || detected_ip=""

    if [ "$ROLE" = "iran" ]; then
        if [ -n "$detected_ip" ]; then
            read -r -p "Iran (this server) public IP [${detected_ip}]: " LOCAL_IP
            LOCAL_IP="${LOCAL_IP:-$detected_ip}"
        else
            read -r -p "Iran (this server) public IP: " LOCAL_IP
        fi
        read -r -p "Kharej (remote server) public IP: " REMOTE_IP
    else
        if [ -n "$detected_ip" ]; then
            read -r -p "Kharej (this server) public IP [${detected_ip}]: " LOCAL_IP
            LOCAL_IP="${LOCAL_IP:-$detected_ip}"
        else
            read -r -p "Kharej (this server) public IP: " LOCAL_IP
        fi
        read -r -p "Iran (remote server) public IP: " REMOTE_IP
    fi

    if ! validate_ip "$LOCAL_IP"; then
        print_error "Invalid local IP: ${LOCAL_IP}"; return
    fi
    if ! validate_ip "$REMOTE_IP"; then
        print_error "Invalid remote IP: ${REMOTE_IP}"; return
    fi

    # GRE network
    read -r -p "GRE network base (e.g. 10.80.70.0): " GRE_NETWORK
    if ! validate_gre_network "$GRE_NETWORK"; then
        print_error "Invalid GRE network (must end with .0): ${GRE_NETWORK}"; return
    fi

    # Compute GRE IPs: Iran=.1, Kharej=.2
    local base="${GRE_NETWORK%.0}"
    if [ "$ROLE" = "iran" ]; then
        LOCAL_GRE_IP="${base}.1"
        PEER_GRE_IP="${base}.2"
    else
        LOCAL_GRE_IP="${base}.2"
        PEER_GRE_IP="${base}.1"
    fi
    print_info "Local GRE IP: ${LOCAL_GRE_IP}"
    print_info "Peer GRE IP: ${PEER_GRE_IP}"

    # GRE key
    read -r -p "GRE key (numeric) [100]: " GRE_KEY
    GRE_KEY="${GRE_KEY:-100}"

    # MTU
    MTU=""
    read -r -p "Custom MTU? (leave empty for default): " MTU
    if [ -n "$MTU" ] && ! validate_mtu "$MTU"; then
        print_error "Invalid MTU: ${MTU}"; return
    fi

    # Ports (Iran side only)
    PORTS=""
    if [ "$ROLE" = "iran" ]; then
        echo
        read -r -p "Ports to forward (e.g. 443,7000:20820 or 2050-2060): " port_input
        if [ -n "$port_input" ]; then
            PORTS=$(parse_ports "$port_input") || return
        fi
    fi

    # Summary
    echo
    print_header "═══ Configuration Summary ═══"
    print_info "Tunnel name: ${TUNNEL_NAME}"
    print_info "Role: ${ROLE}"
    print_info "Local IP: ${LOCAL_IP}"
    print_info "Remote IP: ${REMOTE_IP}"
    print_info "GRE network: ${GRE_NETWORK}"
    print_info "Local GRE IP: ${LOCAL_GRE_IP}"
    print_info "Peer GRE IP: ${PEER_GRE_IP}"
    print_info "GRE key: ${GRE_KEY}"
    [ -n "$MTU" ] && print_info "MTU: ${MTU}"
    [ -n "$PORTS" ] && print_info "Forwarded ports (TCP+UDP): $(format_ports "$PORTS")"
    [ "$ROLE" = "kharej" ] && print_info "Ports: N/A (Kharej side, no forwarding)"
    echo

    read -r -p "Apply this configuration and start? (y/n) [y]: " confirm
    confirm="${confirm:-y}"
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        return
    fi

    save_config
    create_service
}

# ─── CLI Mode ────────────────────────────────────────────────────────────────
show_usage() {
    cat << 'EOF'
Usage: gre.sh [COMMAND] [OPTIONS]

Commands:
  iran                       Configure Iran side (with port forwarding)
  kharej                     Configure Kharej side (tunnel only)
  list                       List all configured tunnels
  status NAME                Show tunnel status
  restart NAME               Restart tunnel
  stop NAME                  Stop tunnel
  add-ports NAME             Add forwarded ports
  remove-ports NAME          Remove forwarded ports
  mtu NAME                   Change MTU
  uninstall NAME|--all       Remove tunnel(s)
  logs NAME                  View logs

Tunnel Options:
  --name NAME                Tunnel name (required)
  --local-ip IP              This server's public IP (auto-detected if omitted)
  --remote-ip IP             Remote server's public IP
  --network NET              GRE network base (e.g. 10.80.70.0)
  --key NUM                  GRE key (default: 100)
  --mtu NUM                  MTU (576-1500)
  --ports PORTS              Ports to forward (Iran only, e.g. 80,443,7000:20820)

Port format: "local_port:remote_port" or just "port" (same both sides).
Port forwarding uses kernel iptables DNAT (TCP+UDP), no socat needed.

Examples:
  gre.sh iran --name melbi-1 --remote-ip 2.2.2.2 \
    --network 10.80.70.0 --ports 443,7000:20820,51820
  gre.sh kharej --name melbi-1 --remote-ip 1.1.1.1 \
    --network 10.80.70.0
  gre.sh add-ports melbi-1 --ports 8080,9000:3000
  gre.sh remove-ports melbi-1 --ports 8080
  gre.sh mtu melbi-1 --mtu 1400
  gre.sh list
  gre.sh status melbi-1
  gre.sh uninstall --all
EOF
}

cli_setup() {
    ROLE="$1"
    shift
    TUNNEL_NAME=""
    LOCAL_IP=""
    REMOTE_IP=""
    GRE_NETWORK=""
    GRE_KEY="100"
    MTU=""
    PORTS=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)       TUNNEL_NAME="$2"; shift 2 ;;
            --local-ip)   LOCAL_IP="$2"; shift 2 ;;
            --remote-ip)  REMOTE_IP="$2"; shift 2 ;;
            --network)    GRE_NETWORK="$2"; shift 2 ;;
            --key)        GRE_KEY="$2"; shift 2 ;;
            --mtu)        MTU="$2"; shift 2 ;;
            --ports)      PORTS="$2"; shift 2 ;;
            *)
                print_error "Unknown option: $1"
                show_usage; exit 1
                ;;
        esac
    done

    # Validation
    if [ -z "$TUNNEL_NAME" ]; then print_error "--name is required"; show_usage; exit 1; fi
    if ! validate_tunnel_name "$TUNNEL_NAME"; then print_error "Invalid tunnel name"; exit 1; fi
    # Auto-detect local IP if not provided
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP=$(get_public_ip) || { print_error "Could not detect public IP. Use --local-ip to set manually."; exit 1; }
    fi
    if [ -z "$REMOTE_IP" ]; then print_error "--remote-ip is required"; exit 1; fi
    if [ -z "$GRE_NETWORK" ]; then print_error "--network is required"; exit 1; fi
    if ! validate_ip "$LOCAL_IP"; then print_error "Invalid local IP"; exit 1; fi
    if ! validate_ip "$REMOTE_IP"; then print_error "Invalid remote IP"; exit 1; fi
    if ! validate_gre_network "$GRE_NETWORK"; then print_error "Invalid GRE network (must end with .0)"; exit 1; fi
    if [ -n "$MTU" ] && ! validate_mtu "$MTU"; then print_error "Invalid MTU"; exit 1; fi

    # Parse ports
    if [ -n "$PORTS" ]; then
        PORTS=$(parse_ports "$PORTS") || exit 1
    fi

    # Compute GRE IPs
    local base="${GRE_NETWORK%.0}"
    if [ "$ROLE" = "iran" ]; then
        LOCAL_GRE_IP="${base}.1"
        PEER_GRE_IP="${base}.2"
    else
        LOCAL_GRE_IP="${base}.2"
        PEER_GRE_IP="${base}.1"
    fi

    print_header "Configuring GRE ${ROLE}: ${TUNNEL_NAME}"
    echo
    print_info "Local IP: ${LOCAL_IP} | Remote IP: ${REMOTE_IP}"
    print_info "GRE: ${LOCAL_GRE_IP} <-> ${PEER_GRE_IP} (key: ${GRE_KEY})"
    [ -n "$MTU" ] && print_info "MTU: ${MTU}"
    [ -n "$PORTS" ] && print_info "Forwarded ports: $(format_ports "$PORTS")"
    echo

    save_config
    create_service
}

# ─── Main Entry Point ────────────────────────────────────────────────────────
main() {
    if [ $# -eq 0 ]; then
        check_root
        interactive_menu
        exit 0
    fi

    local command="$1"
    shift

    case "$command" in
        iran)
            check_root
            cli_setup "iran" "$@"
            ;;
        kharej)
            check_root
            cli_setup "kharej" "$@"
            ;;
        list)
            check_root
            list_tunnels
            ;;
        status)
            check_root
            if [ $# -ge 1 ]; then TUNNEL_NAME="$1"
            else print_error "Usage: gre.sh status NAME"; exit 1; fi
            show_status
            ;;
        restart)
            check_root
            if [ $# -ge 1 ]; then TUNNEL_NAME="$1"
            else print_error "Usage: gre.sh restart NAME"; exit 1; fi
            restart_service
            ;;
        stop)
            check_root
            if [ $# -ge 1 ]; then TUNNEL_NAME="$1"
            else print_error "Usage: gre.sh stop NAME"; exit 1; fi
            stop_service
            ;;
        add-ports)
            check_root
            if [ $# -lt 1 ]; then print_error "Usage: gre.sh add-ports NAME --ports PORTS"; exit 1; fi
            TUNNEL_NAME="$1"; shift
            local ports_val=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --ports) ports_val="$2"; shift 2 ;;
                    *) print_error "Unknown option: $1"; exit 1 ;;
                esac
            done
            if [ -z "$ports_val" ]; then print_error "--ports is required"; exit 1; fi
            add_ports "$ports_val"
            ;;
        remove-ports)
            check_root
            if [ $# -lt 1 ]; then print_error "Usage: gre.sh remove-ports NAME --ports PORTS"; exit 1; fi
            TUNNEL_NAME="$1"; shift
            local rm_val=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --ports) rm_val="$2"; shift 2 ;;
                    *) print_error "Unknown option: $1"; exit 1 ;;
                esac
            done
            if [ -z "$rm_val" ]; then print_error "--ports is required"; exit 1; fi
            remove_ports "$rm_val"
            ;;
        mtu)
            check_root
            if [ $# -lt 1 ]; then print_error "Usage: gre.sh mtu NAME --mtu VALUE"; exit 1; fi
            TUNNEL_NAME="$1"; shift
            local mtu_val=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --mtu) mtu_val="$2"; shift 2 ;;
                    *) print_error "Unknown option: $1"; exit 1 ;;
                esac
            done
            if [ -z "$mtu_val" ]; then print_error "--mtu is required"; exit 1; fi
            if ! validate_mtu "$mtu_val"; then print_error "Invalid MTU"; exit 1; fi
            change_mtu "$mtu_val"
            ;;
        uninstall)
            check_root
            if [ $# -ge 1 ]; then
                if [ "$1" = "--all" ]; then
                    FORCE_YES="true"
                    uninstall_all
                else
                    TUNNEL_NAME="$1"
                    FORCE_YES="true"
                    uninstall_tunnel
                fi
            else
                print_error "Usage: gre.sh uninstall NAME  or  gre.sh uninstall --all"
                exit 1
            fi
            ;;
        logs)
            check_root
            if [ $# -ge 1 ]; then TUNNEL_NAME="$1"
            else print_error "Usage: gre.sh logs NAME"; exit 1; fi
            view_logs
            ;;
        --help|-h|help)
            show_usage
            ;;
        *)
            print_error "Unknown command: ${command}"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
