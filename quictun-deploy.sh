#!/usr/bin/env bash
###############################################################################
# QuiCTun Deployment Script
# QUIC-based tunnel for censorship-resistant connectivity
# Handles compilation, PSK authentication, port hopping, and monitoring
###############################################################################
set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly INSTALL_DIR="/opt/quictun"
readonly BIN_DIR="${INSTALL_DIR}/bin"
readonly CONF_DIR="${INSTALL_DIR}/config"
readonly LOG_DIR="${INSTALL_DIR}/logs"
readonly SRC_DIR="${INSTALL_DIR}/src"
readonly LOCKFILE="/tmp/quictun-install.lock"
readonly QUICTUN_REPO="https://github.com/gnolizuh/quictun.git"
readonly GO_VERSION="1.21.6"
readonly GO_FALLBACK_VERSION="1.17.13"
readonly SYSTEMD_SERVICE="quictun"
readonly SYSCTL_CONF="/etc/sysctl.d/99-quictun.conf"
readonly CRON_FILE="/etc/cron.d/quictun-porthop"
readonly DEFAULT_HOP_INTERVAL=300

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Detected at runtime ---
OS_ID=""
OS_VERSION=""
PKG_MANAGER=""
FIREWALL_CMD=""
GO_ARCH=""
PUBLIC_IP=""

###############################################################################
# SECTION 1: UTILITY FUNCTIONS
###############################################################################

print_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
print_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
print_success() { echo -e "${GREEN}[OK]${NC} $*"; }

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}=== $* ===${NC}"
    echo ""
}

confirm_action() {
    local prompt="${1:-Continue?}"
    local reply
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]: ${NC}")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root."
        exit 1
    fi
}

acquire_lock() {
    if [[ -f "$LOCKFILE" ]]; then
        local pid
        pid=$(cat "$LOCKFILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            print_error "Another instance is running (PID $pid)."
            exit 1
        fi
        rm -f "$LOCKFILE"
    fi
    echo $$ > "$LOCKFILE"
}

release_lock() {
    rm -f "$LOCKFILE"
}

cleanup() {
    release_lock
    # Remove temp files
    rm -f /tmp/quictun_patch_*.go 2>/dev/null
}
trap cleanup EXIT INT TERM

check_disk_space() {
    local required_mb="${1:-500}"
    local avail_mb
    avail_mb=$(df -m /opt 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
    if [[ "$avail_mb" -lt "$required_mb" ]]; then
        print_error "Insufficient disk space: ${avail_mb}MB available, ${required_mb}MB required."
        return 1
    fi
    return 0
}

random_port() {
    local min="${1:-10000}"
    local max="${2:-60000}"
    echo $(( RANDOM % (max - min + 1) + min ))
}

###############################################################################
# SECTION 2: OS/ARCHITECTURE DETECTION
###############################################################################

detect_os() {
    print_info "Detecting operating system..."

    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot detect OS: /etc/os-release not found."
        exit 1
    fi

    # Parse os-release with grep+cut (not source) to avoid readonly variable conflicts
    OS_ID=$(grep '^ID=' /etc/os-release | head -1 | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
    OS_VERSION=$(grep '^VERSION_ID=' /etc/os-release | head -1 | cut -d= -f2 | tr -d '"' || echo "unknown")
    OS_VERSION="${OS_VERSION:-unknown}"

    case "$OS_ID" in
        debian)
            PKG_MANAGER="apt-get"
            FIREWALL_CMD="ufw"
            ;;
        ubuntu)
            PKG_MANAGER="apt-get"
            FIREWALL_CMD="ufw"
            ;;
        centos|rhel|rocky|almalinux|ol)
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            FIREWALL_CMD="firewall-cmd"
            ;;
        fedora)
            PKG_MANAGER="dnf"
            FIREWALL_CMD="firewall-cmd"
            ;;
        *)
            print_warn "Unsupported OS: $OS_ID. Attempting to continue..."
            if command -v apt-get &>/dev/null; then
                PKG_MANAGER="apt-get"
                FIREWALL_CMD="ufw"
            elif command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
                FIREWALL_CMD="firewall-cmd"
            elif command -v yum &>/dev/null; then
                PKG_MANAGER="yum"
                FIREWALL_CMD="firewall-cmd"
            else
                print_error "No supported package manager found."
                exit 1
            fi
            ;;
    esac

    print_success "OS: $OS_ID $OS_VERSION | Package manager: $PKG_MANAGER"
}

detect_arch() {
    print_info "Detecting architecture..."
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64)   GO_ARCH="amd64" ;;
        aarch64|arm64)   GO_ARCH="arm64" ;;
        armv7*|armhf)    GO_ARCH="armv6l" ;;
        i386|i686)       GO_ARCH="386" ;;
        *)
            print_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    print_success "Architecture: $arch -> Go arch: $GO_ARCH"
}

detect_public_ip() {
    print_info "Detecting public IP..."
    local services=(
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
        "https://api.ipify.org"
    )

    for svc in "${services[@]}"; do
        PUBLIC_IP=$(curl -s --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_success "Public IP: $PUBLIC_IP"
            return 0
        fi
    done

    print_warn "Could not detect public IP automatically."
    read -r -p "Enter this server's public IP: " PUBLIC_IP
}

###############################################################################
# SECTION 3: DEPENDENCY & GO INSTALLATION
###############################################################################

install_dependencies() {
    print_header "Installing Dependencies"

    local packages_deb="git curl wget jq openssl build-essential iptables cron"
    local packages_rpm="git curl wget jq openssl gcc make iptables cronie"

    case "$PKG_MANAGER" in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            # shellcheck disable=SC2086
            apt-get install -y -qq $packages_deb
            ;;
        dnf)
            # shellcheck disable=SC2086
            dnf install -y -q $packages_rpm
            ;;
        yum)
            # shellcheck disable=SC2086
            yum install -y -q $packages_rpm
            ;;
    esac

    print_success "Dependencies installed."
}

install_golang() {
    local target_version="$1"
    print_header "Installing Go ${target_version}"

    # Check if compatible Go is already installed
    if command -v go &>/dev/null; then
        local current
        current=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' || echo "0.0")
        local required
        required=$(echo "$target_version" | grep -oP '^[0-9]+\.[0-9]+')
        if [[ "$current" == "$required" ]] || [[ "$(printf '%s\n' "$required" "$current" | sort -V | head -1)" == "$required" ]]; then
            print_success "Go $current already installed (compatible with $target_version)."
            return 0
        fi
    fi

    if ! check_disk_space 500; then
        print_error "Not enough disk space for Go installation."
        return 1
    fi

    local go_url="https://go.dev/dl/go${target_version}.linux-${GO_ARCH}.tar.gz"
    local tmp_archive="/tmp/go${target_version}.tar.gz"

    print_info "Downloading Go ${target_version} from ${go_url}..."
    if ! curl -sL --fail -o "$tmp_archive" "$go_url"; then
        print_error "Failed to download Go ${target_version}."
        return 1
    fi

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp_archive"
    rm -f "$tmp_archive"

    # Ensure Go is in PATH
    if ! grep -q '/usr/local/go/bin' /etc/profile.d/golang.sh 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
    fi
    export PATH=$PATH:/usr/local/go/bin

    if ! go version &>/dev/null; then
        print_error "Go installation verification failed."
        return 1
    fi

    print_success "Go $(go version | awk '{print $3}') installed."
}

###############################################################################
# SECTION 4: CLONE, PATCH & COMPILE QUICTUN
###############################################################################

clone_quictun() {
    print_info "Cloning QuiCTun repository..."
    mkdir -p "$SRC_DIR"

    if [[ -d "$SRC_DIR/quictun/.git" ]]; then
        print_info "Source already exists, pulling latest..."
        cd "$SRC_DIR/quictun" && git pull --quiet 2>/dev/null || true
        cd /
    else
        rm -rf "$SRC_DIR/quictun"
        if ! git clone --depth 1 "$QUICTUN_REPO" "$SRC_DIR/quictun"; then
            print_error "Failed to clone QuiCTun repository."
            return 1
        fi
    fi

    print_success "QuiCTun source ready at $SRC_DIR/quictun"
}

write_client_auth_go() {
    local dir="$1"
    cat > "$dir/auth.go" << 'GOEOF'
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"
)

func clientAuth(rw io.ReadWriteCloser, psk string) error {
	if psk == "" {
		return nil
	}

	if conn, ok := rw.(net.Conn); ok {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		defer conn.SetDeadline(time.Time{})
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(nonce)
	sig := mac.Sum(nil)

	payload := make([]byte, 48)
	copy(payload[:16], nonce)
	copy(payload[16:], sig)
	if _, err := rw.Write(payload); err != nil {
		return fmt.Errorf("auth send failed: %v", err)
	}

	ack := make([]byte, 1)
	if _, err := io.ReadFull(rw, ack); err != nil {
		return fmt.Errorf("auth response read failed: %v", err)
	}
	if ack[0] != 0x01 {
		return fmt.Errorf("server rejected authentication")
	}
	return nil
}
GOEOF
    print_info "  -> wrote $dir/auth.go"
}

write_server_auth_go() {
    local dir="$1"
    cat > "$dir/auth.go" << 'GOEOF'
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"
)

func serverAuth(rw io.ReadWriteCloser, psk string) error {
	if psk == "" {
		return nil
	}

	if conn, ok := rw.(net.Conn); ok {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		defer conn.SetDeadline(time.Time{})
	}

	payload := make([]byte, 48)
	if _, err := io.ReadFull(rw, payload); err != nil {
		rw.Write([]byte{0x00})
		return fmt.Errorf("auth read failed: %v", err)
	}

	nonce := payload[:16]
	receivedMAC := payload[16:]

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(nonce)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(receivedMAC, expectedMAC) {
		rw.Write([]byte{0x00})
		return fmt.Errorf("invalid PSK")
	}

	rw.Write([]byte{0x01})
	return nil
}
GOEOF
    print_info "  -> wrote $dir/auth.go"
}

patch_config_go() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        print_warn "Config file not found: $config_file"
        return 1
    fi

    if grep -q 'PSK' "$config_file"; then
        print_info "  -> $config_file already patched (PSK field exists)"
        return 0
    fi

    # Add PSK field after the Quiet field
    if grep -q 'Quiet' "$config_file"; then
        sed -i '/Quiet.*bool.*json:"quiet"/a\\tPSK    string `json:"psk"`' "$config_file"
    else
        # Fallback: add before the closing brace of the struct
        sed -i '/^}/i\\tPSK    string `json:"psk"`' "$config_file"
    fi

    print_info "  -> patched $config_file (added PSK field)"
}

patch_client_main() {
    local main_file="$1"
    if [[ ! -f "$main_file" ]]; then
        print_warn "Client main.go not found: $main_file"
        return 1
    fi

    if grep -q 'psk' "$main_file"; then
        print_info "  -> client main.go already patched"
        return 0
    fi

    # 1. Add PSK CLI flag after the "quiet" BoolFlag block
    local suppress_line
    suppress_line=$(grep -n "suppress" "$main_file" | head -1 | cut -d: -f1)
    if [[ -n "$suppress_line" ]]; then
        # The closing }, of the BoolFlag is on the next line
        local insert_after=$((suppress_line + 1))
        local flag_block
        flag_block=$(cat << 'FLAGEOF'
		cli.StringFlag{
			Name:  "psk",
			Value: "",
			Usage: "pre-shared key for authentication",
		},
FLAGEOF
)
        # Use awk to insert after the specific line
        awk -v n="$insert_after" -v text="$flag_block" 'NR==n{print; print text; next}1' \
            "$main_file" > "${main_file}.tmp" && mv "${main_file}.tmp" "$main_file"
    fi

    # 2. Add config.PSK assignment after config.Quiet
    sed -i '/config\.Quiet = c\.Bool("quiet")/a\\t\tconfig.PSK = c.String("psk")' "$main_file"

    # 3. Inject auth call after "defer p2.Close()"
    #    p2 is the QUIC connection in the client
    local auth_inject
    auth_inject=$(cat << 'AUTHEOF'

			if config.PSK != "" {
				if err := clientAuth(p2, config.PSK); err != nil {
					log.Println("auth failed:", err)
					return
				}
			}
AUTHEOF
)
    local defer_line
    defer_line=$(grep -n 'defer p2\.Close()' "$main_file" | head -1 | cut -d: -f1)
    if [[ -n "$defer_line" ]]; then
        awk -v n="$defer_line" -v text="$auth_inject" 'NR==n{print; print text; next}1' \
            "$main_file" > "${main_file}.tmp" && mv "${main_file}.tmp" "$main_file"
    fi

    print_info "  -> patched client main.go (PSK flag + auth call)"
}

patch_server_main() {
    local main_file="$1"
    if [[ ! -f "$main_file" ]]; then
        print_warn "Server main.go not found: $main_file"
        return 1
    fi

    if grep -q 'psk' "$main_file"; then
        print_info "  -> server main.go already patched"
        return 0
    fi

    # 1. Add PSK CLI flag after the "quiet" BoolFlag block
    local suppress_line
    suppress_line=$(grep -n "suppress" "$main_file" | head -1 | cut -d: -f1)
    if [[ -n "$suppress_line" ]]; then
        local insert_after=$((suppress_line + 1))
        local flag_block
        flag_block=$(cat << 'FLAGEOF'
		cli.StringFlag{
			Name:  "psk",
			Value: "",
			Usage: "pre-shared key for authentication",
		},
FLAGEOF
)
        awk -v n="$insert_after" -v text="$flag_block" 'NR==n{print; print text; next}1' \
            "$main_file" > "${main_file}.tmp" && mv "${main_file}.tmp" "$main_file"
    fi

    # 2. Add config.PSK assignment after config.Quiet
    sed -i '/config\.Quiet = c\.Bool("quiet")/a\\t\tconfig.PSK = c.String("psk")' "$main_file"

    # 3. Inject auth call after "defer p1.Close()"
    #    p1 is the QUIC connection in the server
    local auth_inject
    auth_inject=$(cat << 'AUTHEOF'

			if config.PSK != "" {
				if err := serverAuth(p1, config.PSK); err != nil {
					log.Println("auth failed:", err)
					return
				}
			}
AUTHEOF
)
    local defer_line
    defer_line=$(grep -n 'defer p1\.Close()' "$main_file" | head -1 | cut -d: -f1)
    if [[ -n "$defer_line" ]]; then
        awk -v n="$defer_line" -v text="$auth_inject" 'NR==n{print; print text; next}1' \
            "$main_file" > "${main_file}.tmp" && mv "${main_file}.tmp" "$main_file"
    fi

    print_info "  -> patched server main.go (PSK flag + auth call)"
}

patch_quictun() {
    print_info "Applying PSK authentication patches..."
    local src="$SRC_DIR/quictun"

    local client_dir="$src/client"
    local server_dir="$src/server"

    # Verify directories exist
    if [[ ! -d "$client_dir" ]] || [[ ! -d "$server_dir" ]]; then
        print_error "QuiCTun source structure unexpected (missing client/ or server/)."
        return 1
    fi

    # Write auth.go files (new files)
    write_client_auth_go "$client_dir"
    write_server_auth_go "$server_dir"

    # Patch config.go files (add PSK field)
    patch_config_go "$client_dir/config.go"
    patch_config_go "$server_dir/config.go"

    # Patch main.go files (add CLI flag + auth injection)
    patch_client_main "$client_dir/main.go"
    patch_server_main "$server_dir/main.go"

    print_success "PSK patches applied."
}

compile_quictun_modules() {
    local src="$SRC_DIR/quictun"
    print_info "Compiling with Go modules mode..."

    cd "$src"

    # Create go.mod if it doesn't exist
    if [[ ! -f go.mod ]]; then
        go mod init github.com/gnolizuh/quictun
    fi

    # Fetch dependencies
    go get github.com/urfave/cli@v1.22.14 2>/dev/null || go get github.com/urfave/cli
    go get github.com/marten-seemann/quic-conn@latest 2>/dev/null || true
    go mod tidy 2>/dev/null || true

    mkdir -p "$BIN_DIR"
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "$BIN_DIR/quictun-server" ./server
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "$BIN_DIR/quictun-client" ./client

    cd /
}

compile_quictun_gopath() {
    local src="$SRC_DIR/quictun"
    print_info "Compiling with GOPATH mode..."

    export GOPATH="/tmp/quictun-gopath"
    export GO111MODULE=off
    mkdir -p "$GOPATH/src/github.com/gnolizuh"

    # Copy source to GOPATH
    rm -rf "$GOPATH/src/github.com/gnolizuh/quictun"
    cp -r "$src" "$GOPATH/src/github.com/gnolizuh/quictun"

    # Fetch dependencies
    go get -d github.com/urfave/cli 2>/dev/null
    go get -d github.com/marten-seemann/quic-conn 2>/dev/null

    mkdir -p "$BIN_DIR"
    cd "$GOPATH/src/github.com/gnolizuh/quictun"
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "$BIN_DIR/quictun-server" ./server
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "$BIN_DIR/quictun-client" ./client

    cd /
    unset GO111MODULE
}

download_prebuilt() {
    print_info "Attempting to download pre-built binaries..."
    local arch_name="$GO_ARCH"
    if [[ "$arch_name" == "armv6l" ]]; then arch_name="arm"; fi

    local release_url="https://github.com/gnolizuh/quictun/releases"
    local tarball="quictun-linux-${arch_name}.tar.gz"
    local download_url="${release_url}/latest/download/${tarball}"

    mkdir -p "$BIN_DIR"
    local tmp="/tmp/${tarball}"

    if curl -sL --fail -o "$tmp" "$download_url" 2>/dev/null; then
        tar -xzf "$tmp" -C "$BIN_DIR/" 2>/dev/null
        rm -f "$tmp"
        # Rename if needed (releases may use different names)
        for f in "$BIN_DIR"/quictun_client* "$BIN_DIR"/client*; do
            [[ -f "$f" ]] && mv "$f" "$BIN_DIR/quictun-client" 2>/dev/null && break
        done
        for f in "$BIN_DIR"/quictun_server* "$BIN_DIR"/server*; do
            [[ -f "$f" ]] && mv "$f" "$BIN_DIR/quictun-server" 2>/dev/null && break
        done
        chmod +x "$BIN_DIR"/quictun-* 2>/dev/null
        if [[ -x "$BIN_DIR/quictun-server" ]] && [[ -x "$BIN_DIR/quictun-client" ]]; then
            print_warn "Using pre-built binaries WITHOUT PSK authentication patches."
            return 0
        fi
    fi

    return 1
}

build_quictun() {
    print_header "Building QuiCTun"

    clone_quictun || return 1

    # Try patching
    local patched=false
    if patch_quictun; then
        patched=true
    else
        print_warn "PSK patching failed. Will try compiling without patches."
    fi

    # Try compilation with fallback chain
    local compiled=false

    # Try 1: Go modules mode with primary Go version
    if ! $compiled; then
        print_info "Attempt 1: Go modules mode with Go $GO_VERSION..."
        if install_golang "$GO_VERSION" && compile_quictun_modules 2>/dev/null; then
            compiled=true
            print_success "Compilation succeeded (modules mode)."
        else
            print_warn "Modules mode failed."
        fi
    fi

    # Try 2: GOPATH mode with primary Go version
    if ! $compiled; then
        print_info "Attempt 2: GOPATH mode with Go $GO_VERSION..."
        if compile_quictun_gopath 2>/dev/null; then
            compiled=true
            print_success "Compilation succeeded (GOPATH mode)."
        else
            print_warn "GOPATH mode failed."
        fi
    fi

    # Try 3: Older Go version
    if ! $compiled; then
        print_info "Attempt 3: GOPATH mode with Go $GO_FALLBACK_VERSION..."
        if install_golang "$GO_FALLBACK_VERSION" && compile_quictun_gopath 2>/dev/null; then
            compiled=true
            print_success "Compilation succeeded (Go $GO_FALLBACK_VERSION)."
        else
            print_warn "Fallback Go version failed."
        fi
    fi

    # Try 4: Compile without PSK patches
    if ! $compiled && $patched; then
        print_info "Attempt 4: Compiling without PSK patches..."
        clone_quictun  # Re-clone clean source
        if compile_quictun_gopath 2>/dev/null || compile_quictun_modules 2>/dev/null; then
            compiled=true
            patched=false
            print_warn "Compiled WITHOUT PSK patches."
        fi
    fi

    # Try 5: Download pre-built binary
    if ! $compiled; then
        print_info "Attempt 5: Downloading pre-built binary..."
        if download_prebuilt; then
            compiled=true
            patched=false
        else
            print_error "All compilation and download attempts failed."
            print_error "Please check: Go installation, network connectivity, and disk space."
            return 1
        fi
    fi

    # Verify binaries
    chmod +x "$BIN_DIR"/quictun-* 2>/dev/null
    if [[ ! -x "$BIN_DIR/quictun-server" ]] || [[ ! -x "$BIN_DIR/quictun-client" ]]; then
        print_error "Binaries not found after build."
        return 1
    fi

    # SELinux context if enforcing
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        restorecon -v "$BIN_DIR"/quictun-* 2>/dev/null || true
    fi

    if $patched; then
        print_success "QuiCTun built with PSK authentication support."
    else
        print_warn "QuiCTun built WITHOUT PSK authentication. Tunnel will be unauthenticated."
    fi
}

###############################################################################
# SECTION 5: KERNEL OPTIMIZATIONS
###############################################################################

apply_kernel_optimizations() {
    print_header "Applying Kernel Optimizations"

    # Check BBR availability
    local bbr_available=false
    if modprobe tcp_bbr 2>/dev/null; then
        bbr_available=true
    fi

    cat > "$SYSCTL_CONF" << SYSEOF
# QuiCTun kernel optimizations
# Applied by quictun-deploy.sh v${SCRIPT_VERSION}

# IP forwarding (gateway mode)
net.ipv4.ip_forward = 1

# TCP congestion control
$(if $bbr_available; then
echo "net.core.default_qdisc = fq"
echo "net.ipv4.tcp_congestion_control = bbr"
else
echo "# BBR not available on this kernel"
echo "# net.core.default_qdisc = fq"
echo "# net.ipv4.tcp_congestion_control = bbr"
fi)

# UDP buffer sizes (critical for QUIC)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# UDP memory pages
net.ipv4.udp_mem = 32768 65536 131072

# Connection limits
net.core.somaxconn = 65535

# TCP optimizations
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
SYSEOF

    sysctl -p "$SYSCTL_CONF" 2>/dev/null || true

    # File descriptor limits
    local limits_file="/etc/security/limits.conf"
    local marker="# QuiCTun limits"
    if ! grep -q "$marker" "$limits_file" 2>/dev/null; then
        cat >> "$limits_file" << LIMEOF

$marker
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMEOF
    fi

    if $bbr_available; then
        print_success "Kernel optimized: BBR enabled, UDP buffers enlarged, limits raised."
    else
        print_success "Kernel optimized: UDP buffers enlarged, limits raised. (BBR unavailable)"
    fi
}

###############################################################################
# SECTION 6: CONFIGURATION GENERATION
###############################################################################

generate_psk() {
    print_info "Generating PSK..."
    mkdir -p "$CONF_DIR"
    openssl rand -base64 32 > "$CONF_DIR/psk.key"
    chmod 600 "$CONF_DIR/psk.key"
    print_success "PSK generated: $CONF_DIR/psk.key"
}

generate_server_config() {
    local listen_port="$1"
    local target_addr="$2"
    local psk="$3"

    mkdir -p "$CONF_DIR" "$LOG_DIR"

    # JSON config
    cat > "$CONF_DIR/quictun.conf" << CONFEOF
{
    "role": "server",
    "listen_port": ${listen_port},
    "target": "${target_addr}",
    "version": "${SCRIPT_VERSION}"
}
CONFEOF

    # Systemd environment file
    cat > "$CONF_DIR/quictun.env" << ENVEOF
ROLE=server
LISTEN_PORT=${listen_port}
TARGET_ADDR=${target_addr}
PSK=${psk}
ENVEOF

    # Store internal port for port hopping
    echo "$listen_port" > "$CONF_DIR/internal_port"

    chmod 600 "$CONF_DIR/quictun.env" "$CONF_DIR/psk.key"
    print_success "Server configuration written."
}

generate_client_config() {
    local remote_ip="$1"
    local remote_port="$2"
    local local_port="$3"
    local psk="$4"

    mkdir -p "$CONF_DIR" "$LOG_DIR"

    # JSON config
    cat > "$CONF_DIR/quictun.conf" << CONFEOF
{
    "role": "client",
    "remote_ip": "${remote_ip}",
    "remote_port": ${remote_port},
    "local_port": ${local_port},
    "version": "${SCRIPT_VERSION}"
}
CONFEOF

    # Systemd environment file
    cat > "$CONF_DIR/quictun.env" << ENVEOF
ROLE=client
REMOTE_IP=${remote_ip}
REMOTE_PORT=${remote_port}
LOCAL_PORT=${local_port}
PSK=${psk}
ENVEOF

    # Store PSK for port hopping
    echo "$psk" > "$CONF_DIR/psk.key"
    chmod 600 "$CONF_DIR/quictun.env" "$CONF_DIR/psk.key"

    print_success "Client configuration written."
}

###############################################################################
# SECTION 7: SYSTEMD SERVICE
###############################################################################

create_systemd_service() {
    local role="$1"  # "server" or "client"

    print_info "Creating systemd service for ${role}..."

    local exec_start
    if [[ "$role" == "server" ]]; then
        exec_start="${BIN_DIR}/quictun-server --listen :\${LISTEN_PORT} --target \${TARGET_ADDR} --psk \${PSK}"
    else
        exec_start="${BIN_DIR}/quictun-client --localaddr :\${LOCAL_PORT} --remoteaddr \${REMOTE_IP}:\${REMOTE_PORT} --psk \${PSK}"
    fi

    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}.service" << SVCEOF
[Unit]
Description=QuiCTun QUIC Tunnel (${role})
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/gnolizuh/quictun

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/quictun.env
ExecStart=${exec_start}
Restart=always
RestartSec=3
StartLimitBurst=10
StartLimitIntervalSec=60

# Resource limits
LimitNOFILE=1048576
LimitNPROC=65535
MemoryMax=512M

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${LOG_DIR} ${CONF_DIR}

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable "${SYSTEMD_SERVICE}" 2>/dev/null

    print_success "Systemd service created and enabled."
}

###############################################################################
# SECTION 8: FIREWALL CONFIGURATION
###############################################################################

configure_firewall() {
    local role="$1"
    local port="$2"
    local proto="$3"  # "udp" or "tcp"

    print_info "Configuring firewall for ${role} (${proto}/${port})..."

    if [[ "$FIREWALL_CMD" == "ufw" ]]; then
        if command -v ufw &>/dev/null; then
            ufw allow "${port}/${proto}" 2>/dev/null || true
            # Ensure ufw is enabled
            echo "y" | ufw enable 2>/dev/null || true
            print_success "UFW: allowed ${proto}/${port}"
        fi
    elif [[ "$FIREWALL_CMD" == "firewall-cmd" ]]; then
        if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
            firewall-cmd --permanent --add-port="${port}/${proto}" 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            print_success "firewalld: allowed ${proto}/${port}"
        fi
    fi

    # Also handle raw iptables as fallback
    if command -v iptables &>/dev/null; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

###############################################################################
# SECTION 9: PORT HOPPING
###############################################################################

compute_hop_port() {
    local psk="$1"
    local interval="${2:-$DEFAULT_HOP_INTERVAL}"
    local time_offset="${3:-0}"

    local current_time
    current_time=$(date +%s)
    local slot=$(( (current_time / interval) - time_offset ))
    local hex
    hex=$(printf '%s' "$slot" | openssl dgst -sha256 -hmac "$psk" 2>/dev/null | awk '{print $NF}')
    local first4="${hex:0:4}"
    local num=$(( 16#$first4 ))
    echo $(( 10000 + (num % 50000) ))
}

setup_port_hopping_server() {
    local hop_interval="${1:-$DEFAULT_HOP_INTERVAL}"

    print_info "Setting up server-side port hopping (interval: ${hop_interval}s)..."

    echo "$hop_interval" > "$CONF_DIR/hop_interval"

    # Create port-hop.sh script
    cat > "$BIN_DIR/port-hop.sh" << 'HOPEOF'
#!/bin/bash
# QuiCTun Server Port Hopping
# Runs via cron - applies iptables DNAT for deterministic port rotation

CONF_DIR="/opt/quictun/config"
LOG_DIR="/opt/quictun/logs"
PSK=$(cat "$CONF_DIR/psk.key" 2>/dev/null)
INTERNAL_PORT=$(cat "$CONF_DIR/internal_port" 2>/dev/null)
HOP_INTERVAL=$(cat "$CONF_DIR/hop_interval" 2>/dev/null || echo 300)
STATE_FILE="$CONF_DIR/current_port"
CHAIN_NAME="QUICTUN-HOP"

if [[ -z "$PSK" ]] || [[ -z "$INTERNAL_PORT" ]]; then
    echo "$(date): Missing PSK or internal port" >> "$LOG_DIR/porthop.log"
    exit 1
fi

compute_port() {
    local slot=$1
    local hex
    hex=$(printf '%s' "$slot" | openssl dgst -sha256 -hmac "$PSK" 2>/dev/null | awk '{print $NF}')
    local first4="${hex:0:4}"
    local num=$(( 16#$first4 ))
    echo $(( 10000 + (num % 50000) ))
}

current_time=$(date +%s)
current_slot=$((current_time / HOP_INTERVAL))

# Compute ports for current and 2 previous slots (graceful transition)
ports=()
for offset in 0 1 2; do
    slot=$((current_slot - offset))
    ports+=( "$(compute_port "$slot")" )
done

# Check if update needed
current_primary=$(cat "$STATE_FILE" 2>/dev/null || echo "0")
if [[ "${ports[0]}" == "$current_primary" ]]; then
    exit 0
fi

# Flush and recreate chain
iptables -t nat -F "$CHAIN_NAME" 2>/dev/null
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true

for port in "${ports[@]}"; do
    iptables -t nat -A "$CHAIN_NAME" -p udp --dport "$port" -j REDIRECT --to-port "$INTERNAL_PORT"
done

# Ensure chain is referenced from PREROUTING
iptables -t nat -C PREROUTING -j "$CHAIN_NAME" 2>/dev/null || \
    iptables -t nat -A PREROUTING -j "$CHAIN_NAME"

# Update firewall for new ports
for port in "${ports[@]}"; do
    if command -v ufw &>/dev/null; then
        ufw allow "$port/udp" >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --add-port="$port/udp" --permanent >/dev/null 2>&1 || true
    fi
    iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
done
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Update state
echo "${ports[0]}" > "$STATE_FILE"

echo "$(date): Port hopped to ${ports[0]} (active: ${ports[*]})" >> "$LOG_DIR/porthop.log"
HOPEOF
    chmod +x "$BIN_DIR/port-hop.sh"

    # Run immediately to set initial ports
    bash "$BIN_DIR/port-hop.sh"

    # Create cron job
    cat > "$CRON_FILE" << CRONEOF
# QuiCTun port hopping - check every minute
* * * * * root /bin/bash ${BIN_DIR}/port-hop.sh >/dev/null 2>&1
CRONEOF

    # Ensure cron is running
    systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
    systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true

    print_success "Server port hopping configured (interval: ${hop_interval}s)."
}

setup_port_hopping_client() {
    local hop_interval="${1:-$DEFAULT_HOP_INTERVAL}"

    print_info "Setting up client-side port tracking (interval: ${hop_interval}s)..."

    echo "$hop_interval" > "$CONF_DIR/hop_interval"

    # Create client-hop.sh script
    cat > "$BIN_DIR/client-hop.sh" << 'HOPEOF'
#!/bin/bash
# QuiCTun Client Port Tracking
# Runs via cron - tracks server port hops and reconnects

CONF_DIR="/opt/quictun/config"
LOG_DIR="/opt/quictun/logs"
PSK=$(cat "$CONF_DIR/psk.key" 2>/dev/null)
HOP_INTERVAL=$(cat "$CONF_DIR/hop_interval" 2>/dev/null || echo 300)
STATE_FILE="$CONF_DIR/current_port"
ENV_FILE="$CONF_DIR/quictun.env"

if [[ -z "$PSK" ]]; then
    echo "$(date): Missing PSK" >> "$LOG_DIR/porthop.log"
    exit 1
fi

compute_port() {
    local slot=$1
    local hex
    hex=$(printf '%s' "$slot" | openssl dgst -sha256 -hmac "$PSK" 2>/dev/null | awk '{print $NF}')
    local first4="${hex:0:4}"
    local num=$(( 16#$first4 ))
    echo $(( 10000 + (num % 50000) ))
}

current_time=$(date +%s)
current_slot=$((current_time / HOP_INTERVAL))
new_port=$(compute_port "$current_slot")

current_port=$(cat "$STATE_FILE" 2>/dev/null || echo "0")

if [[ "$new_port" != "$current_port" ]]; then
    echo "$new_port" > "$STATE_FILE"

    # Update environment file with new port
    sed -i "s/^REMOTE_PORT=.*/REMOTE_PORT=$new_port/" "$ENV_FILE"

    # Restart service to connect to new port
    systemctl restart quictun

    echo "$(date): Client tracking hop to port $new_port" >> "$LOG_DIR/porthop.log"
fi
HOPEOF
    chmod +x "$BIN_DIR/client-hop.sh"

    # Set initial port
    local psk
    psk=$(cat "$CONF_DIR/psk.key")
    local initial_port
    initial_port=$(compute_hop_port "$psk" "$hop_interval" 0)
    echo "$initial_port" > "$CONF_DIR/current_port"

    # Update env file with computed port
    sed -i "s/^REMOTE_PORT=.*/REMOTE_PORT=$initial_port/" "$CONF_DIR/quictun.env"

    # Create cron job
    cat > "$CRON_FILE" << CRONEOF
# QuiCTun client port tracking - check every minute
* * * * * root /bin/bash ${BIN_DIR}/client-hop.sh >/dev/null 2>&1
CRONEOF

    systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
    systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true

    print_success "Client port tracking configured (interval: ${hop_interval}s)."
}

###############################################################################
# SECTION 10: MONITORING & DIAGNOSTICS
###############################################################################

show_status() {
    print_header "QuiCTun Status"

    # Service status
    if systemctl is-active --quiet "$SYSTEMD_SERVICE" 2>/dev/null; then
        print_success "Service: RUNNING"
    else
        print_error "Service: STOPPED"
    fi
    systemctl status "$SYSTEMD_SERVICE" --no-pager -l 2>/dev/null | head -15 || true

    echo ""

    # Read config
    if [[ -f "$CONF_DIR/quictun.env" ]]; then
        echo -e "${CYAN}Configuration:${NC}"
        grep -v 'PSK=' "$CONF_DIR/quictun.env" 2>/dev/null | while read -r line; do
            echo "  $line"
        done
        echo "  PSK=********"
    fi

    echo ""

    # Connection info
    local role
    role=$(grep '^ROLE=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
    if [[ "$role" == "server" ]]; then
        local port
        port=$(grep '^LISTEN_PORT=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
        echo -e "${CYAN}UDP connections on port ${port}:${NC}"
        ss -ulnp sport = ":${port}" 2>/dev/null || true
    else
        local lport
        lport=$(grep '^LOCAL_PORT=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
        echo -e "${CYAN}TCP listeners on port ${lport}:${NC}"
        ss -tlnp sport = ":${lport}" 2>/dev/null || true
    fi

    echo ""

    # Port hopping status
    if [[ -f "$CONF_DIR/current_port" ]]; then
        echo -e "${CYAN}Port hopping:${NC}"
        echo "  Current port: $(cat "$CONF_DIR/current_port")"
        echo "  Hop interval: $(cat "$CONF_DIR/hop_interval" 2>/dev/null || echo 'N/A')s"
        if [[ -f "$LOG_DIR/porthop.log" ]]; then
            echo "  Last hop: $(tail -1 "$LOG_DIR/porthop.log" 2>/dev/null || echo 'N/A')"
        fi
    else
        echo -e "${CYAN}Port hopping:${NC} disabled"
    fi

    echo ""

    # Resource usage
    echo -e "${CYAN}Resource usage:${NC}"
    local pid
    pid=$(systemctl show -p MainPID "$SYSTEMD_SERVICE" 2>/dev/null | cut -d= -f2)
    if [[ -n "$pid" ]] && [[ "$pid" != "0" ]]; then
        ps -p "$pid" -o pid,vsz,rss,%cpu,%mem,etime --no-headers 2>/dev/null | \
            awk '{printf "  PID: %s | VSZ: %dMB | RSS: %dMB | CPU: %s%% | MEM: %s%% | Uptime: %s\n", $1, $2/1024, $3/1024, $4, $5, $6}'
    else
        echo "  Process not running."
    fi
}

show_logs() {
    local lines="${1:-50}"
    print_header "QuiCTun Logs (last ${lines} lines)"
    journalctl -u "$SYSTEMD_SERVICE" --no-pager -n "$lines" 2>/dev/null || \
        echo "No journal logs available."
}

test_connectivity() {
    local remote_ip="$1"
    local remote_port="$2"

    print_header "Connectivity Test"

    # ICMP ping
    print_info "ICMP ping to ${remote_ip}..."
    if ping -c 3 -W 3 "$remote_ip" &>/dev/null; then
        print_success "ICMP: reachable"
    else
        print_warn "ICMP: unreachable (may be blocked by firewall)"
    fi

    # UDP probe
    print_info "UDP probe to ${remote_ip}:${remote_port}..."
    if timeout 5 bash -c "echo -n 'probe' > /dev/udp/${remote_ip}/${remote_port}" 2>/dev/null; then
        print_success "UDP: port appears open"
    else
        print_warn "UDP: probe failed (may be filtered or wrong port)"
    fi

    # Check local service
    if systemctl is-active --quiet "$SYSTEMD_SERVICE" 2>/dev/null; then
        print_success "Local service: running"
    else
        print_error "Local service: not running"
    fi
}

show_connections() {
    print_header "Active Connections"

    local role
    role=$(grep '^ROLE=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)

    if [[ "$role" == "server" ]]; then
        local port
        port=$(grep '^LISTEN_PORT=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
        echo -e "${CYAN}QUIC sessions (UDP :${port}):${NC}"
        ss -ulnp sport = ":${port}" 2>/dev/null || echo "  None"
        echo ""
        echo -e "${CYAN}Backend TCP connections:${NC}"
        local target
        target=$(grep '^TARGET_ADDR=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
        local target_port
        target_port=$(echo "$target" | cut -d: -f2)
        ss -tnp dport = ":${target_port}" 2>/dev/null || echo "  None"
    else
        local lport
        lport=$(grep '^LOCAL_PORT=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
        echo -e "${CYAN}Local TCP listeners (:${lport}):${NC}"
        ss -tlnp sport = ":${lport}" 2>/dev/null || echo "  None"
        echo ""
        echo -e "${CYAN}Established TCP connections:${NC}"
        ss -tnp sport = ":${lport}" 2>/dev/null || echo "  None"
    fi
}

###############################################################################
# SECTION 11: INSTALLATION ORCHESTRATION
###############################################################################

install_upstream() {
    # Parameters can be passed for non-interactive mode
    local listen_port="${1:-}"
    local target_addr="${2:-}"
    local enable_hop="${3:-}"
    local hop_interval="${4:-$DEFAULT_HOP_INTERVAL}"

    print_header "QuiCTun Upstream (Exit Node) Installation"

    check_root
    acquire_lock
    detect_os
    detect_arch
    detect_public_ip

    install_dependencies
    build_quictun

    # Interactive prompts if values not provided
    if [[ -z "$target_addr" ]]; then
        echo ""
        echo -e "${CYAN}Which VPN is running on this server?${NC}"
        echo "  [1] WireGuard (default: 127.0.0.1:51820)"
        echo "  [2] OpenVPN   (default: 127.0.0.1:1194)"
        echo "  [3] Custom target address"
        local vpn_choice
        read -r -p "Choice [1]: " vpn_choice
        vpn_choice="${vpn_choice:-1}"

        case "$vpn_choice" in
            1) target_addr="127.0.0.1:51820" ;;
            2) target_addr="127.0.0.1:1194" ;;
            3) read -r -p "Enter target address (host:port): " target_addr ;;
            *) target_addr="127.0.0.1:51820" ;;
        esac
    fi

    if [[ -z "$listen_port" ]]; then
        local default_port
        default_port=$(random_port 10000 60000)
        read -r -p "$(echo -e "${CYAN}QUIC listen port [${default_port}]: ${NC}")" listen_port
        listen_port="${listen_port:-$default_port}"
    fi

    # Generate PSK
    generate_psk
    local psk
    psk=$(cat "$CONF_DIR/psk.key")

    # Apply optimizations and configuration
    apply_kernel_optimizations
    generate_server_config "$listen_port" "$target_addr" "$psk"
    create_systemd_service "server"
    configure_firewall "server" "$listen_port" "udp"

    # Port hopping
    if [[ -z "$enable_hop" ]]; then
        echo ""
        if confirm_action "Enable port hopping? (recommended for censorship resistance)"; then
            enable_hop="yes"
            read -r -p "$(echo -e "${CYAN}Hop interval in seconds [${DEFAULT_HOP_INTERVAL}]: ${NC}")" hop_interval
            hop_interval="${hop_interval:-$DEFAULT_HOP_INTERVAL}"
        else
            enable_hop="no"
        fi
    fi

    if [[ "$enable_hop" == "yes" ]]; then
        setup_port_hopping_server "$hop_interval"
    fi

    # Start service
    print_info "Starting QuiCTun service..."
    systemctl start "$SYSTEMD_SERVICE"
    sleep 2

    if systemctl is-active --quiet "$SYSTEMD_SERVICE"; then
        print_success "QuiCTun upstream is running!"
    else
        print_error "Service failed to start. Check: journalctl -u $SYSTEMD_SERVICE"
        return 1
    fi

    # Show pair config for downstream
    show_pair_config "$listen_port" "$psk" "$enable_hop" "$hop_interval"
}

install_downstream() {
    # Parameters for non-interactive mode
    local remote_ip="${1:-}"
    local remote_port="${2:-}"
    local local_port="${3:-}"
    local psk="${4:-}"
    local enable_hop="${5:-}"
    local hop_interval="${6:-$DEFAULT_HOP_INTERVAL}"

    print_header "QuiCTun Downstream (Bridge Node) Installation"

    check_root
    acquire_lock
    detect_os
    detect_arch

    install_dependencies
    build_quictun

    # Interactive prompts
    if [[ -z "$remote_ip" ]]; then
        read -r -p "$(echo -e "${CYAN}Upstream server IP: ${NC}")" remote_ip
    fi

    if [[ -z "$remote_port" ]]; then
        read -r -p "$(echo -e "${CYAN}Upstream server port: ${NC}")" remote_port
    fi

    if [[ -z "$psk" ]]; then
        read -r -p "$(echo -e "${CYAN}PSK (from upstream output): ${NC}")" psk
    fi

    if [[ -z "$local_port" ]]; then
        echo ""
        echo -e "${CYAN}Local TCP listen port:${NC}"
        echo "  [1] 51820 (WireGuard default)"
        echo "  [2] 1194  (OpenVPN default)"
        echo "  [3] 1935  (QuiCTun default)"
        echo "  [4] Custom port"
        local port_choice
        read -r -p "Choice [3]: " port_choice
        port_choice="${port_choice:-3}"

        case "$port_choice" in
            1) local_port="51820" ;;
            2) local_port="1194" ;;
            3) local_port="1935" ;;
            4) read -r -p "Enter local port: " local_port ;;
            *) local_port="1935" ;;
        esac
    fi

    # Store PSK
    mkdir -p "$CONF_DIR"
    echo "$psk" > "$CONF_DIR/psk.key"
    chmod 600 "$CONF_DIR/psk.key"

    # Apply optimizations and configuration
    apply_kernel_optimizations
    generate_client_config "$remote_ip" "$remote_port" "$local_port" "$psk"
    create_systemd_service "client"
    configure_firewall "client" "$local_port" "tcp"

    # Port hopping
    if [[ -z "$enable_hop" ]]; then
        echo ""
        if confirm_action "Enable port hopping? (must match upstream setting)"; then
            enable_hop="yes"
            read -r -p "$(echo -e "${CYAN}Hop interval in seconds [${DEFAULT_HOP_INTERVAL}]: ${NC}")" hop_interval
            hop_interval="${hop_interval:-$DEFAULT_HOP_INTERVAL}"
        else
            enable_hop="no"
        fi
    fi

    if [[ "$enable_hop" == "yes" ]]; then
        setup_port_hopping_client "$hop_interval"
    fi

    # Start service
    print_info "Starting QuiCTun service..."
    systemctl start "$SYSTEMD_SERVICE"
    sleep 2

    if systemctl is-active --quiet "$SYSTEMD_SERVICE"; then
        print_success "QuiCTun downstream is running!"
    else
        print_error "Service failed to start. Check: journalctl -u $SYSTEMD_SERVICE"
        return 1
    fi

    # Test connectivity
    echo ""
    test_connectivity "$remote_ip" "$remote_port"

    echo ""
    print_success "Downstream setup complete."
    echo -e "  Local TCP port: ${GREEN}${local_port}${NC}"
    echo -e "  Point your VPN client to: ${GREEN}127.0.0.1:${local_port}${NC}"
}

show_pair_config() {
    local listen_port="$1"
    local psk="$2"
    local hop_enabled="${3:-no}"
    local hop_interval="${4:-$DEFAULT_HOP_INTERVAL}"

    local display_port="$listen_port"
    if [[ "$hop_enabled" == "yes" ]] && [[ -f "$CONF_DIR/current_port" ]]; then
        display_port=$(cat "$CONF_DIR/current_port")
    fi

    print_header "Downstream Configuration"
    echo -e "${BOLD}Copy this information to set up the downstream (bridge) server:${NC}"
    echo ""
    echo "┌──────────────────────────────────────────────────────────────┐"
    echo "│  Upstream IP:      ${PUBLIC_IP:-<detect failed>}"
    echo "│  Upstream Port:    ${display_port}"
    echo "│  PSK:              ${psk}"
    if [[ "$hop_enabled" == "yes" ]]; then
    echo "│  Port Hopping:     ENABLED (interval: ${hop_interval}s)"
    else
    echo "│  Port Hopping:     DISABLED"
    fi
    echo "└──────────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "${CYAN}One-liner for downstream:${NC}"

    local hop_flags=""
    if [[ "$hop_enabled" == "yes" ]]; then
        hop_flags=" --port-hop --hop-interval ${hop_interval}"
    fi

    echo "  bash quictun-deploy.sh install-downstream \\"
    echo "    --remote-ip ${PUBLIC_IP:-<IP>} \\"
    echo "    --remote-port ${display_port} \\"
    echo "    --local-port 1935 \\"
    echo "    --psk '${psk}'${hop_flags}"
    echo ""
}

###############################################################################
# SECTION 12: NON-INTERACTIVE MODE
###############################################################################

parse_cli_args() {
    local command="${1:-}"
    shift 2>/dev/null || true

    case "$command" in
        install-upstream)
            local listen_port="" target="" port_hop="no" hop_interval="$DEFAULT_HOP_INTERVAL"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --listen-port)  listen_port="$2"; shift 2 ;;
                    --target)       target="$2"; shift 2 ;;
                    --port-hop)     port_hop="yes"; shift ;;
                    --hop-interval) hop_interval="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            install_upstream "$listen_port" "$target" "$port_hop" "$hop_interval"
            ;;

        install-downstream)
            local remote_ip="" remote_port="" local_port="" psk="" port_hop="no" hop_interval="$DEFAULT_HOP_INTERVAL"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --remote-ip)    remote_ip="$2"; shift 2 ;;
                    --remote-port)  remote_port="$2"; shift 2 ;;
                    --local-port)   local_port="$2"; shift 2 ;;
                    --psk)          psk="$2"; shift 2 ;;
                    --port-hop)     port_hop="yes"; shift ;;
                    --hop-interval) hop_interval="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            install_downstream "$remote_ip" "$remote_port" "$local_port" "$psk" "$port_hop" "$hop_interval"
            ;;

        status)     show_status ;;
        logs)       show_logs "${1:-50}" ;;
        restart)    check_root; systemctl restart "$SYSTEMD_SERVICE"; print_success "Service restarted." ;;
        stop)       check_root; systemctl stop "$SYSTEMD_SERVICE"; print_success "Service stopped." ;;
        uninstall)  uninstall ;;
        *)          return 1 ;;  # Fall through to interactive menu
    esac

    return 0
}

###############################################################################
# SECTION 13: UNINSTALL
###############################################################################

uninstall() {
    print_header "QuiCTun Uninstall"
    check_root

    if ! confirm_action "This will remove QuiCTun and all its configuration. Continue?"; then
        print_info "Uninstall cancelled."
        return 0
    fi

    # Stop and disable service
    print_info "Stopping service..."
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null || true
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}.service"
    systemctl daemon-reload

    # Remove cron job
    print_info "Removing cron jobs..."
    rm -f "$CRON_FILE"

    # Flush iptables port hopping rules
    print_info "Cleaning iptables rules..."
    iptables -t nat -D PREROUTING -j QUICTUN-HOP 2>/dev/null || true
    iptables -t nat -F QUICTUN-HOP 2>/dev/null || true
    iptables -t nat -X QUICTUN-HOP 2>/dev/null || true

    # Remove firewall rules (best effort)
    if [[ -f "$CONF_DIR/quictun.env" ]]; then
        local port
        port=$(grep -E '^(LISTEN_PORT|LOCAL_PORT)=' "$CONF_DIR/quictun.env" 2>/dev/null | head -1 | cut -d= -f2)
        if [[ -n "$port" ]]; then
            if command -v ufw &>/dev/null; then
                ufw delete allow "$port/udp" 2>/dev/null || true
                ufw delete allow "$port/tcp" 2>/dev/null || true
            fi
            if command -v firewall-cmd &>/dev/null; then
                firewall-cmd --permanent --remove-port="$port/udp" 2>/dev/null || true
                firewall-cmd --permanent --remove-port="$port/tcp" 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
            fi
        fi
    fi

    # Remove installation directory
    print_info "Removing files..."
    rm -rf "$INSTALL_DIR"

    # Remove sysctl config
    rm -f "$SYSCTL_CONF"
    sysctl --system 2>/dev/null || true

    # Clean limits.conf
    if [[ -f /etc/security/limits.conf ]]; then
        sed -i '/# QuiCTun limits/,+4d' /etc/security/limits.conf 2>/dev/null || true
    fi

    # Remove Go profile
    rm -f /etc/profile.d/golang.sh

    print_success "QuiCTun has been completely uninstalled."
}

###############################################################################
# SECTION 14: INTERACTIVE MENU SYSTEM
###############################################################################

show_manage_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}${BOLD}--- Manage QuiCTun ---${NC}"
        echo "  [1] Restart Service"
        echo "  [2] Stop Service"
        echo "  [3] Start Service"
        echo "  [4] Edit Configuration"
        echo "  [0] Back"
        echo ""
        local choice
        read -r -p "Choice: " choice

        case "$choice" in
            1) systemctl restart "$SYSTEMD_SERVICE" && print_success "Restarted." ;;
            2) systemctl stop "$SYSTEMD_SERVICE" && print_success "Stopped." ;;
            3) systemctl start "$SYSTEMD_SERVICE" && print_success "Started." ;;
            4)
                if command -v nano &>/dev/null; then
                    nano "$CONF_DIR/quictun.env"
                elif command -v vi &>/dev/null; then
                    vi "$CONF_DIR/quictun.env"
                fi
                echo ""
                if confirm_action "Restart service to apply changes?"; then
                    systemctl restart "$SYSTEMD_SERVICE"
                fi
                ;;
            0) return ;;
            *) print_warn "Invalid choice." ;;
        esac
    done
}

show_advanced_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}${BOLD}--- Advanced Settings ---${NC}"
        echo "  [1] Enable Port Hopping"
        echo "  [2] Disable Port Hopping"
        echo "  [3] Re-apply Kernel Optimizations"
        echo "  [4] Run Connectivity Test"
        echo "  [5] Show Active Connections"
        echo "  [6] View Port Hop Log"
        echo "  [0] Back"
        echo ""
        local choice
        read -r -p "Choice: " choice

        case "$choice" in
            1)
                local role
                role=$(grep '^ROLE=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
                local interval
                read -r -p "$(echo -e "${CYAN}Hop interval [${DEFAULT_HOP_INTERVAL}]: ${NC}")" interval
                interval="${interval:-$DEFAULT_HOP_INTERVAL}"
                if [[ "$role" == "server" ]]; then
                    setup_port_hopping_server "$interval"
                else
                    setup_port_hopping_client "$interval"
                fi
                ;;
            2)
                rm -f "$CRON_FILE"
                iptables -t nat -D PREROUTING -j QUICTUN-HOP 2>/dev/null || true
                iptables -t nat -F QUICTUN-HOP 2>/dev/null || true
                iptables -t nat -X QUICTUN-HOP 2>/dev/null || true
                rm -f "$CONF_DIR/current_port" "$CONF_DIR/hop_interval"
                print_success "Port hopping disabled."
                ;;
            3)
                apply_kernel_optimizations
                ;;
            4)
                local rip rport
                rip=$(grep '^REMOTE_IP=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
                rport=$(grep '^REMOTE_PORT=' "$CONF_DIR/quictun.env" 2>/dev/null | cut -d= -f2)
                if [[ -n "$rip" ]] && [[ -n "$rport" ]]; then
                    test_connectivity "$rip" "$rport"
                else
                    read -r -p "Remote IP: " rip
                    read -r -p "Remote port: " rport
                    test_connectivity "$rip" "$rport"
                fi
                ;;
            5) show_connections ;;
            6)
                if [[ -f "$LOG_DIR/porthop.log" ]]; then
                    tail -20 "$LOG_DIR/porthop.log"
                else
                    print_info "No port hop log found."
                fi
                ;;
            0) return ;;
            *) print_warn "Invalid choice." ;;
        esac
    done
}

show_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║   QuiCTun Tunnel Manager v${SCRIPT_VERSION}        ║${NC}"
        echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════╝${NC}"
        echo ""
        echo "  [1] Install - Setup Upstream (Foreign/Exit Node)"
        echo "  [2] Install - Setup Downstream (Iran/Bridge Node)"
        echo "  [3] Manage Existing Installation"
        echo "  [4] View Status & Logs"
        echo "  [5] Advanced Settings"
        echo "  [6] Uninstall"
        echo "  [0] Exit"
        echo ""
        local choice
        read -r -p "Choice: " choice

        case "$choice" in
            1) install_upstream ;;
            2) install_downstream ;;
            3)
                if [[ ! -f "$CONF_DIR/quictun.env" ]]; then
                    print_warn "No installation found."
                else
                    show_manage_menu
                fi
                ;;
            4)
                if [[ ! -f "$CONF_DIR/quictun.env" ]]; then
                    print_warn "No installation found."
                else
                    show_status
                    echo ""
                    if confirm_action "View recent logs?"; then
                        show_logs 30
                    fi
                fi
                ;;
            5)
                if [[ ! -f "$CONF_DIR/quictun.env" ]]; then
                    print_warn "No installation found."
                else
                    show_advanced_menu
                fi
                ;;
            6) uninstall ;;
            0)
                echo ""
                print_info "Goodbye."
                exit 0
                ;;
            *)
                print_warn "Invalid choice."
                ;;
        esac
    done
}

###############################################################################
# MAIN ENTRY POINT
###############################################################################

main() {
    # Non-interactive mode: parse CLI arguments
    if [[ $# -gt 0 ]]; then
        if parse_cli_args "$@"; then
            exit 0
        fi
        # If parse_cli_args returns 1, fall through to interactive menu
    fi

    # Interactive mode
    check_root
    show_menu
}

main "$@"
