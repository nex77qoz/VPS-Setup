#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-vps-bootstrap.conf"
SSHD_MAIN="/etc/ssh/sshd_config"
F2B_JAIL="/etc/fail2ban/jail.d/sshd.local"
BBR_CONF="/etc/sysctl.d/99-bbr.conf"
BBR_MODULES_CONF="/etc/modules-load.d/bbr.conf"

log() { printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\n[WARN] %s\n' "$*" >&2; }
die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root: sudo bash ${SCRIPT_NAME}"
}

require_debian() {
  [[ -r /etc/os-release ]] || die "Cannot detect OS (missing /etc/os-release)."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "debian" ]] || die "This script is adapted specifically for Debian. Detected: ${PRETTY_NAME:-unknown}."
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found."
}

prompt_nonempty() {
  local prompt="$1"
  local value=""
  while true; do
    read -r -p "$prompt" value
    [[ -n "$value" ]] && { printf '%s' "$value"; return 0; }
    echo "Value cannot be empty."
  done
}

prompt_password() {
  local p1="" p2=""
  while true; do
    read -r -s -p "Enter password for the new user: " p1; echo
    read -r -s -p "Repeat password: " p2; echo
    [[ -n "$p1" ]] || { echo "Password cannot be empty."; continue; }
    [[ "$p1" == "$p2" ]] || { echo "Passwords do not match."; continue; }
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
  echo
  echo "Paste your PUBLIC SSH key (expected: ssh-rsa ...)."
  while true; do
    read -r key
    [[ -n "$key" ]] || { echo "Key cannot be empty."; continue; }
    [[ "$key" == ssh-rsa\ * ]] || { echo "This does not look like an RSA public key. It should start with 'ssh-rsa '."; continue; }
    printf '%s' "$key"
    return 0
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
  local port
  local used
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
  log "Updating system and installing Debian packages"
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
    kmod
}

configure_user() {
  local username="$1"
  local password="$2"
  local ssh_key="$3"

  log "Creating user '$username'"
  adduser --disabled-password --gecos "" "$username"
  echo "${username}:${password}" | chpasswd
  usermod -aG sudo "$username"

  install -d -m 700 -o "$username" -g "$username" "/home/$username/.ssh"
  printf '%s\n' "$ssh_key" > "/home/$username/.ssh/authorized_keys"
  chown "$username:$username" "/home/$username/.ssh/authorized_keys"
  chmod 600 "/home/$username/.ssh/authorized_keys"
}

configure_ssh() {
  local ssh_port="$1"
  local ssh_service="$2"

  command -v sshd >/dev/null 2>&1 || die "sshd binary not found after installing openssh-server."

  log "Configuring SSH daemon"
  mkdir -p /etc/ssh/sshd_config.d
  ensure_include_for_sshd_dropins

  cat > "$SSHD_DROPIN" <<EOF_SSH
Port ${ssh_port}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication yes
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

  log "Configuring Fail2ban"
  mkdir -p /etc/fail2ban/jail.d
  cat > "$F2B_JAIL" <<EOF_F2B
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
  ss -H -lntu 2>/dev/null | while read -r netid state recvq sendq local peer; do
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
  local item proto port

  log "Configuring UFW"
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
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
  require_root
  require_debian

  echo "Interactive VPS bootstrap for Debian"
  echo "This script will update the server, create a sudo user, harden SSH, enable UFW, configure Fail2ban, install btop and try to enable BBR."
  echo

  local username password ssh_key ssh_port ssh_service active_ports bbr_status

  username="$(prompt_nonempty 'Enter new username: ')"
  validate_username "$username"

  password="$(prompt_password)"
  ssh_key="$(prompt_ssh_key)"

  install_packages

  ssh_service="$(get_ssh_service_name)"
  ssh_port="$(pick_random_port)"

  configure_user "$username" "$password" "$ssh_key"
  configure_ssh "$ssh_port" "$ssh_service"
  configure_fail2ban "$ssh_port"

  active_ports="$(collect_active_ports)"
  configure_ufw "$ssh_port" "$active_ports"
  bbr_status="$(configure_bbr)"

  log "Done"
  echo
  echo "New sudo user: $username"
  echo "New SSH port: $ssh_port"
  echo
  echo "Allowed public ports in UFW:"
  if [[ -n "$active_ports" ]]; then
    echo "$active_ports" | sed 's/^/  - /'
  else
    echo "  - none detected (except SSH ${ssh_port}/tcp, which was allowed with rate limit)"
  fi
  echo
  case "$bbr_status" in
    enabled)
      echo "BBR: enabled" ;;
    failed)
      echo "BBR: configuration was written, but the active check did not confirm it." ;;
    unsupported)
      echo "BBR: not available in this kernel / provider image." ;;
  esac
  echo
  echo "Test SSH in a NEW terminal before closing this session:"
  echo "  ssh -p $ssh_port $username@<your_server_ip>"
  echo
  echo "Current UFW status:"
  ufw status numbered
}

main "$@"
