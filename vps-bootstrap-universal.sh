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
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Запустите от имени root: bash ${SCRIPT_NAME}"
}

require_tty() {
  [[ -r "$TTY_DEVICE" && -w "$TTY_DEVICE" ]] || die "Интерактивный терминал недоступен. Запустите скрипт из реального SSH-сеанса."
}

require_supported_os() {
  [[ -r /etc/os-release ]] || die "Не удалось определить ОС (отсутствует /etc/os-release)."
  # shellcheck disable=SC1091
  . /etc/os-release
  command -v apt-get >/dev/null 2>&1 || die "Скрипт поддерживает только системы Debian/Ubuntu с apt-get."
  case "${ID:-}" in
    debian|ubuntu)
      OS_FAMILY="$ID"
      OS_NAME="${PRETTY_NAME:-$ID}"
      ;;
    *)
      die "Неподдерживаемая система: ${PRETTY_NAME:-unknown}. Поддерживаются: ${SUPPORTED_IDS}."
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
    tty_println "Значение не может быть пустым."
  done
}

prompt_auth_method() {
  local choice=""
  while true; do
    tty_println ""
    tty_println "Выберите метод входа для нового пользователя:"
    tty_println "1) Пароль"
    tty_println "2) Только SSH-ключ"
    tty_print "Выбор [1/2]: "
    IFS= read -r choice < "$TTY_DEVICE"
    case "$choice" in
      1) printf 'password'; return 0 ;;
      2) printf 'ssh'; return 0 ;;
      *) tty_println "Введите 1 или 2." ;;
    esac
  done
}

prompt_password() {
  local p1="" p2=""
  while true; do
    tty_print "Введите пароль для нового пользователя: "
    IFS= read -r -s p1 < "$TTY_DEVICE"
    tty_println ""

    tty_print "Повторите пароль: "
    IFS= read -r -s p2 < "$TTY_DEVICE"
    tty_println ""

    [[ -n "$p1" ]] || { tty_println "Пароль не может быть пустым."; continue; }
    [[ "$p1" == "$p2" ]] || { tty_println "Пароли не совпадают."; continue; }
    printf '%s' "$p1"
    return 0
  done
}

validate_username() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Недопустимое имя пользователя. Используйте строчные буквы, цифры, _ или -, начиная с буквы или _."
  ! id "$username" >/dev/null 2>&1 || die "Пользователь '$username' уже существует."
}

prompt_ssh_key() {
  local key=""
  tty_println ""
  tty_println "Вставьте ваш ПУБЛИЧНЫЙ SSH-ключ (ожидается: ssh-rsa ...)."
  while true; do
    IFS= read -r key < "$TTY_DEVICE"
    [[ -n "$key" ]] || { tty_println "Ключ не может быть пустым."; continue; }
    [[ "$key" == ssh-rsa\ * ]] || { tty_println "Это не похоже на публичный RSA-ключ. Он должен начинаться с 'ssh-rsa '."; continue; }
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
    tty_println "Введите доверенные IP-адреса или диапазоны CIDR для белого списка."
    tty_println "Можно указать несколько значений через пробел или запятую."
    tty_println "Примеры: 1.2.3.4 5.6.7.8/32 2001:db8::1"
    tty_println "Эти IP будут добавлены в белый список UFW и в ignoreip Fail2ban."
    tty_print "Доверенные IP/CIDR (оставьте пустым, чтобы пропустить): "
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
        tty_println "Неверный IP или CIDR: $token"
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

prompt_confirm() {
  local prompt="${1:-Продолжить?}"
  local choice=""
  while true; do
    tty_print "${prompt} [y/N]: "
    IFS= read -r choice < "$TTY_DEVICE"
    case "$choice" in
      [yY]|[yY][eE][sS]) return 0 ;;
      [nN]|[nN][oO]|"") return 1 ;;
      *) tty_println "Введите y или n." ;;
    esac
  done
}

ensure_include_for_sshd_dropins() {
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_MAIN"; then
    cp -a "$SSHD_MAIN" "${SSHD_MAIN}.bak.$(date +%s)"
    { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat "$SSHD_MAIN"; } > "${SSHD_MAIN}.tmp"
    mv "${SSHD_MAIN}.tmp" "$SSHD_MAIN"
  fi
}

port_is_reserved() {
  local port="$1"
  awk -v port="$port" '
    $1 !~ /^#/ && $2 ~ "/" {
      split($2, service, "/")
      if (service[1] == port) {
        found = 1
        exit
      }
    }
    END { exit found ? 0 : 1 }
  ' /etc/services 2>/dev/null
}

pick_random_port() {
  local port used
  used="$(ss -Htanul 2>/dev/null | awk '{print $5}' | sed -En 's/.*:([0-9]+)$/\1/p' | sort -u || true)"
  while true; do
    port="$(shuf -i 20000-65000 -n 1)"
    if ! grep -qx "$port" <<< "$used" && ! port_is_reserved "$port"; then
      printf '%s' "$port"
      return 0
    fi
  done
}

pick_confirmed_ssh_port() {
  local port=""
  while true; do
    port="$(pick_random_port)"
    tty_println ""
    tty_println "Предлагаемый SSH-порт: $port"
    tty_println "Порт не найден среди текущих listen-портов и записей /etc/services."
    if prompt_confirm "Использовать этот порт для SSH?"; then
      printf '%s' "$port"
      return 0
    fi
  done
}

get_ssh_service_name() {
  local units
  units="$(systemctl list-unit-files 2>/dev/null)"
  if echo "$units" | grep -q '^ssh\.service'; then
    printf 'ssh'
  elif echo "$units" | grep -q '^sshd\.service'; then
    printf 'sshd'
  else
    printf 'ssh'
  fi
}

install_packages() {
  log "Обновление системы и установка необходимых пакетов для ${OS_NAME}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -y -o Dpkg::Options::="--force-confold" upgrade
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

  log "Создание пользователя '$username'"
  adduser --disabled-password --gecos "" "$username"

  [[ -n "$password" ]] || die "Пароль нового пользователя не задан."
  echo "${username}:${password}" | chpasswd

  usermod -aG sudo "$username"

  if [[ "$auth_method" == "ssh" ]]; then
    [[ -n "$ssh_key" ]] || die "Выбран вход по SSH-ключу, но ключ не задан."
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
  local username="$4"
  local password_auth="yes"
  local main_backup="" dropin_backup="" dropin_existed="no" tmp_dropin=""

  [[ "$auth_method" == "ssh" ]] && password_auth="no"

  command -v sshd >/dev/null 2>&1 || die "Бинарный файл sshd не найден после установки openssh-server."

  log "Настройка SSH-демона"
  mkdir -p /etc/ssh/sshd_config.d
  main_backup="${SSHD_MAIN}.bak.$(date +%s)"
  cp -a "$SSHD_MAIN" "$main_backup"

  if [[ -e "$SSHD_DROPIN" ]]; then
    dropin_existed="yes"
    dropin_backup="${SSHD_DROPIN}.bak.$(date +%s)"
    cp -a "$SSHD_DROPIN" "$dropin_backup"
  fi

  tmp_dropin="${SSHD_DROPIN}.tmp.$$"
  cat > "$tmp_dropin" <<EOF_SSH
Port ${ssh_port}
AllowUsers ${username}
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
KbdInteractiveAuthentication no
LoginGraceTime 30
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
EOF_SSH

  ensure_include_for_sshd_dropins
  mv "$tmp_dropin" "$SSHD_DROPIN"

  if ! sshd -t; then
    cp -a "$main_backup" "$SSHD_MAIN"
    if [[ "$dropin_existed" == "yes" ]]; then
      cp -a "$dropin_backup" "$SSHD_DROPIN"
    else
      rm -f "$SSHD_DROPIN"
    fi
    rm -f "$tmp_dropin"
    die "Проверка конфигурации sshd завершилась ошибкой. Предыдущая конфигурация восстановлена."
  fi

  systemctl enable "$ssh_service" >/dev/null 2>&1 || true
  if ! systemctl restart "$ssh_service" || ! systemctl is-active --quiet "$ssh_service"; then
    cp -a "$main_backup" "$SSHD_MAIN"
    if [[ "$dropin_existed" == "yes" ]]; then
      cp -a "$dropin_backup" "$SSHD_DROPIN"
    else
      rm -f "$SSHD_DROPIN"
    fi
    systemctl restart "$ssh_service" >/dev/null 2>&1 || true
    die "Не удалось перезапустить SSH-сервис. Предыдущая конфигурация восстановлена."
  fi
}

configure_fail2ban() {
  local ssh_port="$1"
  local trusted_ips="$2"
  local ignore_line="127.0.0.1/8 ::1"

  [[ -n "$trusted_ips" ]] && ignore_line+=" ${trusted_ips}"

  log "Настройка Fail2ban"
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
  systemctl is-active --quiet fail2ban || die "Не удалось запустить Fail2ban."
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
  local allow_trusted_all="$4"
  local item proto port ip

  log "Настройка UFW"
  warn "Сбрасываются все существующие правила UFW."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  if [[ -n "$trusted_ips" && "$allow_trusted_all" == "yes" ]]; then
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
  log "Проверка BBR"

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
  local username auth_method password="" ssh_key="" trusted_ips allow_trusted_all="no" ssh_port ssh_service active_ports bbr_status server_ip item

  require_root
  require_tty
  require_supported_os

  tty_println "Интерактивная настройка VPS для Debian/Ubuntu"
  tty_println "Обнаруженная ОС: ${OS_NAME}"
  tty_println "Этот скрипт обновит сервер, создаст sudo-пользователя, ужесточит настройки SSH, включит UFW, настроит Fail2ban, установит btop и попытается включить BBR."
  tty_println ""

  username="$(prompt_nonempty 'Введите имя нового пользователя: ')"
  validate_username "$username"
  password="$(prompt_password)"
  auth_method="$(prompt_auth_method)"

  if [[ "$auth_method" == "ssh" ]]; then
    ssh_key="$(prompt_ssh_key)"
  fi

  tty_println ""
  tty_println "Итоговая конфигурация:"
  tty_println "  Пользователь: $username"
  tty_println "  Метод входа:  $auth_method"
  tty_println "  Пароль пользователя будет задан для входа по паролю и sudo."
  tty_println ""
  prompt_confirm "Начать установку и настройку?" || die "Отменено пользователем."

  install_packages

  trusted_ips="$(prompt_trusted_ips)"
  if [[ -n "$trusted_ips" ]]; then
    tty_println ""
    tty_println "Доверенные IP всегда будут добавлены в ignoreip Fail2ban."
    if prompt_confirm "Разрешить доверенным IP доступ ко всем портам через UFW?"; then
      allow_trusted_all="yes"
    fi
  fi
  ssh_service="$(get_ssh_service_name)"
  ssh_port="$(pick_confirmed_ssh_port)"
  tty_println ""
  tty_println "Выбранный SSH-порт: $ssh_port — запомните его до завершения скрипта!"

  configure_user "$username" "$auth_method" "$password" "$ssh_key"
  configure_ssh "$ssh_port" "$ssh_service" "$auth_method" "$username"
  configure_fail2ban "$ssh_port" "$trusted_ips"

  active_ports="$(collect_active_ports)"
  if [[ -n "$active_ports" ]]; then
    tty_println ""
    tty_println "UFW: будут разрешены следующие обнаруженные публичные порты:"
    while IFS= read -r item; do
      [[ -n "$item" ]] && tty_println "  - $item"
    done <<< "$active_ports"
    tty_println "  SSH-порт $ssh_port/tcp — с rate-limit; все остальные — разрешены."
    prompt_confirm "Продолжить настройку UFW?" || die "Отменено пользователем."
  fi

  configure_ufw "$ssh_port" "$active_ports" "$trusted_ips" "$allow_trusted_all"
  bbr_status="$(configure_bbr)"

  tty_println ""
  tty_println "Готово"
  tty_println ""
  tty_println "Обнаруженная ОС: ${OS_NAME}"
  tty_println "Новый sudo-пользователь: $username"
  tty_println "Метод входа: $auth_method"
  tty_println "Новый SSH-порт: $ssh_port"
  tty_println ""

  if [[ -n "$trusted_ips" ]]; then
    tty_println "Белый список доверенных IP:"
    for item in $trusted_ips; do
      tty_println "  - $item"
    done
    tty_println ""
    tty_println "В ignoreip Fail2ban включены localhost и ваши доверенные IP."
    if [[ "$allow_trusted_all" == "yes" ]]; then
      tty_println "UFW: доверенным IP разрешён доступ ко всем портам."
    else
      tty_println "UFW: доверенным IP не выдавалось отдельное разрешение на все порты."
    fi
    tty_println ""
  else
    tty_println "Белый список доверенных IP: пропущено"
    tty_println ""
  fi

  tty_println "Разрешённые публичные порты в UFW:"
  if [[ -n "$active_ports" ]]; then
    while IFS= read -r item; do
      [[ -n "$item" ]] && tty_println "  - $item"
    done <<< "$active_ports"
  else
    tty_println "  - не обнаружено (кроме SSH $ssh_port/tcp, разрешённого с ограничением частоты)"
  fi
  tty_println ""

  case "$bbr_status" in
    enabled)
      tty_println "BBR: включён" ;;
    failed)
      tty_println "BBR: конфигурация записана, но активная проверка не подтвердила результат." ;;
    unsupported)
      tty_println "BBR: недоступен в данном ядре / образе провайдера." ;;
  esac

  tty_println ""
  server_ip="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  tty_println "Проверьте SSH в НОВОМ терминале, не закрывая текущий сеанс:"
  if [[ -n "$server_ip" ]]; then
    tty_println "  ssh -p $ssh_port $username@${server_ip}"
  else
    tty_println "  ssh -p $ssh_port $username@<your_server_ip>"
  fi
  tty_println ""
  tty_println "Текущий статус UFW:"
  ufw status numbered > "$TTY_DEVICE"
}

main "$@"
