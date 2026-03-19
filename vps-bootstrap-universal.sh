#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
TTY_DEVICE="/dev/tty"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-vps-bootstrap.conf"
SSHD_MAIN="/etc/ssh/sshd_config"
F2B_JAIL="/etc/fail2ban/jail.d/sshd.local"
BBR_CONF="/etc/sysctl.d/99-bbr.conf"
BBR_MODULES_CONF="/etc/modules-load.d/bbr.conf"
SUPPORTED_IDS="debian ubuntu"

log() { printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
warn() { printf '\n[WARN] %s\n' "$*" >&2; }
die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

tty_print() { printf '%s' "$*" > "$TTY_DEVICE"; }
tty_println() { printf '%s\n' "$*" > "$TTY_DEVICE"; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root: bash ${SCRIPT_NAME}"
}

require_tty() {
  [[ -r "$TTY_DEVICE" && -w "$TTY_DEVICE" ]] || die "Interactive terminal not available. Run this script from a real SSH shell."
}

require_supported_os() {
  [[ -r /etc/os-release ]] || die "Cannot detect OS (missing /etc/os-release)."
  # shellcheck disable=SC1091
  . /etc/os-release
  command -v apt-get >/dev/null 2>&1 || die "This script supports Debian/Ubuntu systems with apt-get."
  case "${ID:-}" in
    debian|ubuntu)
      OS_FAMILY="$ID"
      OS_NAME="${PRETTY_NAME:-$ID}"
      ;;
    *)
      die "Unsupported system: ${PRETTY_NAME:-unknown}. Supported: ${SUPPORTED_IDS}."
      ;;
  esac
}

prompt_nonempty() {
  local prompt="$1"
  local value=""
  while true; do
    tty_print "$prompt"
    IFS= read -r value < "$TTY_DEVICE"
    [[ -n "$value" ]] && { printf '%s' "$value"; return 0; }
    tty_println "Value cannot be empty."
  done
}

prompt_auth_method() {
  local choice=""
  while true; do
    tty_println ""
    tty_println "Choose login method for the new user:"
    tty_println "1) Password"
    tty_println "2) SSH key only"
    tty_print "Selection [1/2]: "
    IFS= read -r choice < "$TTY_DEVICE"
    case "$choice" in
      1) printf 'password'; return 0 ;;
      2) printf 'ssh'; return 0 ;;
      *) tty_println "Enter 1 or 2." ;;
    esac
  done
}

prompt_password() {
  local p1="" p2=""
  while true; do
    tty_print "Enter password for the new user: "
    IFS= read -r -s p1 < "$TTY_DEVICE"
    tty_println ""

    tty_print "Repeat password: "
    IFS= read -r -s p2 < "$TTY_DEVICE"
    tty_println ""

    [[ -n "$p1" ]] || { tty_println "Password cannot be empty."; continue; }
    [[ "$p1" == "$p2" ]] || { tty_println "Passwords do not match."; continue; }
    printf '%s' "$p1"
    return 0
  done
}

validate_username() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Invalid username. Use lowercase letters, digits, _ or -, starting with a letter or _."
  ! id "$username" >/dev/null 2>&1 || die "User '$username' already exists."
}

prompt_ssh_key() {
  local key=""
  tty_println ""
  tty_println "Paste your PUBLIC SSH key (expected: ssh-rsa ...)."
  while true; do
    IFS= read -r key < "$TTY_DEVICE"
    [[ -n "$key" ]] || { tty_println "Key cannot be empty."; continue; }
    [[ "$key" == ssh-rsa\ * ]] || { tty_println "This does not look like an RSA public key. It should start with 'ssh-rsa '."; continue; }
    printf '%s' "$key"
    return 0
  done
}

validate_ip_or_cidr() {
  local value="$1"
  python3 - "$value" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except Exception:
    raise SystemExit(1)
PY
}

prompt_trusted_ips() {
  local raw="" token="" cleaned=""
  local -a valid=()
  declare -A seen=()

  while true; do
    tty_println ""
    tty_println "Enter trusted IPs or CIDR ranges for whitelist."
    tty_println "You can enter multiple values separated by spaces or commas."
    tty_println "Examples: 1.2.3.4 5.6.7.8/32 2001:db8::1"
    tty_println "These IPs will be added to UFW whitelist and Fail2ban ignoreip."
    tty_print "Trusted IPs/CIDRs (leave empty to skip): "
    IFS= read -r raw < "$TTY_DEVICE"

    cleaned="${raw//,/ }"
    valid=()
    seen=()

    if [[ -z "${cleaned//[[:space:]]/}" ]]; then
      printf ''
      return 0
    fi

    for token in $cleaned; do
      validate_ip_or_cidr "$token" || {
        tty_println "Invalid IP or CIDR: $token"
        valid=()
        break
      }
      if [[ -z "${seen[$token]+x}" ]]; then
        valid+=("$token")
        seen[$token]=1
      fi
    done

    if (( ${#valid[@]} > 0 )); then
      printf '%s' "${valid[*]}"
      return 0
    fi
  done
}

ensure_include_for_sshd_dropins() {
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_MAIN"; then
    cp -a "$SSHD_MAIN" "${SSHD_MAIN}.bak.$(date +%s)"
    { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat "$SSHD_MAIN"; } > "${SSHD_MAIN}.tmp"
    mv "${SSHD_MAIN}.tmp" "$SSHD_MAIN"
  fi
}

pick_random_port() {
  local port used
  used="$(ss -Htanul 2>/dev/null | awk '{print $5}' | sed -En 's/.*:([0-9]+)$/\1/p' | sort -u || true)"
  while true; do
    port="$(shuf -i 20000-65000 -n 1)"
    if ! grep -qx "$port" <<< "$used"; then
      printf '%s' "$port"
      return 0
    fi
  done
}

get_ssh_service_name() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    printf 'ssh'
  elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    printf 'sshd'
  else
    printf 'ssh'
  fi
}

install_packages() {
  log "Updating system and installing required packages for ${OS_NAME}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -y upgrade
  apt-get install -y \
    sudo \
    openssh-server \
    ufw \
    fail2ban \
    btop \
    iproute2 \
    ca-certificates \
    curl \
    lsof \
    kmod \
    python3-minimal
}

configure_user() {
  local username="$1"
  local auth_method="$2"
  local password="${3:-}"
  local ssh_key="${4:-}"

  log "Creating user '$username'"
  adduser --disabled-password --gecos "" "$username"

  if [[ "$auth_method" == "password" ]]; then
    [[ -n "$password" ]] || die "Password login selected, but password is empty."
    echo "${username}:${password}" | chpasswd
  fi

  usermod -aG sudo "$username"

  if [[ "$auth_method" == "ssh" ]]; then
    [[ -n "$ssh_key" ]] || die "SSH login selected, but SSH key is empty."
    install -d -m 700 -o "$username" -g "$username" "/home/$username/.ssh"
    printf '%s\n' "$ssh_key" > "/home/$username/.ssh/authorized_keys"
    chown "$username:$username" "/home/$username/.ssh/authorized_keys"
    chmod 600 "/home/$username/.ssh/authorized_keys"
  fi
}

configure_ssh() {
  local ssh_port="$1"
  local ssh_service="$2"
  local auth_method="$3"
  local password_auth="yes"

  [[ "$auth_method" == "ssh" ]] && password_auth="no"

  command -v sshd >/dev/null 2>&1 || die "sshd binary not found after installing openssh-server."

  log "Configuring SSH daemon"
  mkdir -p /etc/ssh/sshd_config.d
  ensure_include_for_sshd_dropins

  cat > "$SSHD_DROPIN" <<EOF_SSH
Port ${ssh_port}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
KbdInteractiveAuthentication no
UsePAM yes
EOF_SSH

  sshd -t || die "sshd configuration test failed. Config not applied."
  systemctl enable "$ssh_service" >/dev/null 2>&1 || true
  systemctl restart "$ssh_service"
  systemctl is-active --quiet "$ssh_service" || die "SSH service failed to restart."
}

configure_fail2ban() {
  local ssh_port="$1"
  local trusted_ips="$2"
  local ignore_line="127.0.0.1/8 ::1"

  [[ -n "$trusted_ips" ]] && ignore_line+=" ${trusted_ips}"

  log "Configuring Fail2ban"
  mkdir -p /etc/fail2ban/jail.d
  cat > "$F2B_JAIL" <<EOF_F2B
[DEFAULT]
ignoreip = ${ignore_line}

[sshd]
enabled = true
port = ${ssh_port}
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF_F2B

  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban
  systemctl is-active --quiet fail2ban || die "Fail2ban failed to start."
}

collect_active_ports() {
  ss -H -lntu 2>/dev/null | while read -r netid state recvq sendq local peer _; do
    local addr port proto
    proto="$netid"
    addr="$local"
    port="${addr##*:}"

    [[ "$port" =~ ^[0-9]+$ ]] || continue

    case "$addr" in
      127.*:*|[[]::1[]]:*|::1:*|localhost:*)
        continue
        ;;
    esac

    case "$proto" in
      tcp|tcp6)
        printf 'tcp:%s\n' "$port"
        ;;
      udp|udp6)
        printf 'udp:%s\n' "$port"
        ;;
    esac
  done | sort -u
}

configure_ufw() {
  local ssh_port="$1"
  local active_ports="$2"
  local trusted_ips="$3"
  local item proto port ip

  log "Configuring UFW"
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  if [[ -n "$trusted_ips" ]]; then
    for ip in $trusted_ips; do
      ufw allow from "$ip"
    done
  fi

  ufw limit "${ssh_port}/tcp"

  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    proto="${item%%:*}"
    port="${item##*:}"
    [[ "$port" == "$ssh_port" && "$proto" == "tcp" ]] && continue
    ufw allow "${port}/${proto}"
  done <<< "$active_ports"

  ufw --force enable
}

configure_bbr() {
  log "Checking BBR"

  if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    modprobe tcp_bbr >/dev/null 2>&1 || true
  fi

  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    printf 'tcp_bbr\n' > "$BBR_MODULES_CONF"
    cat > "$BBR_CONF" <<'EOF_BBR'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF_BBR
    sysctl --system >/dev/null

    if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" == "bbr" ]]; then
      echo "enabled"
      return 0
    fi
    echo "failed"
    return 0
  fi

  echo "unsupported"
}

main() {
  local username auth_method password="" ssh_key="" trusted_ips ssh_port ssh_service active_ports bbr_status item

  require_root
  require_tty
  require_supported_os

  tty_println "Interactive VPS bootstrap for Debian/Ubuntu"
  tty_println "Detected OS: ${OS_NAME}"
  tty_println "This script will update the server, create a sudo user, harden SSH, enable UFW, configure Fail2ban, install btop and try to enable BBR."
  tty_println ""

  username="$(prompt_nonempty 'Enter new username: ')"
  validate_username "$username"
  auth_method="$(prompt_auth_method)"

  if [[ "$auth_method" == "password" ]]; then
    password="$(prompt_password)"
  else
    ssh_key="$(prompt_ssh_key)"
  fi

  install_packages

  trusted_ips="$(prompt_trusted_ips)"
  ssh_service="$(get_ssh_service_name)"
  ssh_port="$(pick_random_port)"

  configure_user "$username" "$auth_method" "$password" "$ssh_key"
  configure_ssh "$ssh_port" "$ssh_service" "$auth_method"
  configure_fail2ban "$ssh_port" "$trusted_ips"

  active_ports="$(collect_active_ports)"
  configure_ufw "$ssh_port" "$active_ports" "$trusted_ips"
  bbr_status="$(configure_bbr)"

  tty_println ""
  tty_println "Done"
  tty_println ""
  tty_println "Detected OS: ${OS_NAME}"
  tty_println "New sudo user: $username"
  tty_println "Login method: $auth_method"
  tty_println "New SSH port: $ssh_port"
  tty_println ""

  if [[ -n "$trusted_ips" ]]; then
    tty_println "Trusted IP whitelist:"
    for item in $trusted_ips; do
      tty_println "  - $item"
    done
    tty_println ""
    tty_println "Fail2ban ignoreip includes localhost plus your trusted IPs."
    tty_println ""
  else
    tty_println "Trusted IP whitelist: skipped"
    tty_println ""
  fi

  tty_println "Allowed public ports in UFW:"
  if [[ -n "$active_ports" ]]; then
    while IFS= read -r item; do
      [[ -n "$item" ]] && tty_println "  - $item"
    done <<< "$active_ports"
  else
    tty_println "  - none detected (except SSH $ssh_port/tcp, which was allowed with rate limit)"
  fi
  tty_println ""

  case "$bbr_status" in
    enabled)
      tty_println "BBR: enabled" ;;
    failed)
      tty_println "BBR: configuration was written, but the active check did not confirm it." ;;
    unsupported)
      tty_println "BBR: not available in this kernel / provider image." ;;
  esac

  tty_println ""
  tty_println "Test SSH in a NEW terminal before closing this session:"
  tty_println "  ssh -p $ssh_port $username@<your_server_ip>"
  tty_println ""
  tty_println "Current UFW status:"
  ufw status numbered
}

main "$@"
