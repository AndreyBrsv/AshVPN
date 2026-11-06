#!/usr/bin/env bash
# Executed over SSH, as root. Parameters arrive on encrypted stdin, never argv.
set -Eeuo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a UCF_FORCE_CONFFOLD=1
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG=/var/log/vpn-setup.log
ACTION="${1:---help}"
SECRET_TMP=''
SOCKS_BACKUP=''
SOCKS_NEW=0
SOCKS_WAS_RUNNING=false
SSH_BACKUP=''
SSH_EXTRA_BACKUP=''
SSH_CHANGED=0
GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'

info() { printf '%s\n' "[INFO] $*" | tee -a "$LOG"; }
ok() { printf '%s[OK]%s %s\n' "$GREEN" "$NC" "$*" | tee -a "$LOG"; }
warn() { printf '%s[WARN]%s %s\n' "$YELLOW" "$NC" "$*" | tee -a "$LOG" >&2; }
err() { printf '%s[ERROR]%s %s\n' "$RED" "$NC" "$*" | tee -a "$LOG" >&2; }
fatal() {
    err "$*"
    if command -v python3 >/dev/null && [[ -f "$BASE_DIR/lifecycle.py" ]]; then
        python3 "$BASE_DIR/lifecycle.py" record-action "$ACTION" failed 1 </dev/null || true
    fi
    exit 1
}
field() { IFS= read -r -d '' "$1" || fatal "Missing input fields."; }
port_ok() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
username_ok() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,30}$ && "$1" != root && "$1" != nobody ]]; }
header() {
    printf '\n┌────────────────────────────────────────────────────┐\n│ %s\n└────────────────────────────────────────────────────┘\n' "$*"
    info "Step: $ACTION"
}
cleanup() {
    if [[ -n "$SECRET_TMP" && "$SECRET_TMP" == /run/ashapp.* ]]; then rm -f -- "$SECRET_TMP"; fi
}
restore_ssh() {
    if [[ "$SSH_CHANGED" == 1 ]]; then
        cp -- "$SSH_BACKUP" /etc/ssh/sshd_config
        if [[ -n "$SSH_EXTRA_BACKUP" ]]; then
            cp -- "$SSH_EXTRA_BACKUP" /etc/ssh/ashapp.conf
        else
            rm -f -- /etc/ssh/ashapp.conf
        fi
        /usr/sbin/sshd -t && (systemctl reload ssh || systemctl reload sshd) || true
        SSH_CHANGED=0
    fi
}
on_error() {
    local code=$? line="$1" command="$2"
    trap - ERR
    set +e
    restore_ssh
    if [[ "$SOCKS_NEW" == 1 ]]; then docker rm -f amnezia-socks5proxy >/dev/null 2>&1; fi
    if [[ -n "$SOCKS_BACKUP" ]]; then
        docker rename "$SOCKS_BACKUP" amnezia-socks5proxy
        if [[ "$SOCKS_WAS_RUNNING" == true ]]; then docker start amnezia-socks5proxy >/dev/null; fi
    fi
    # BASH_COMMAND contains variable references, not their secret values. Stdin is never logged.
    err "Action $ACTION, line $line, code $code. Command: $command"
    if command -v python3 >/dev/null && [[ -f "$BASE_DIR/lifecycle.py" ]]; then
        python3 "$BASE_DIR/lifecycle.py" record-action "$ACTION" failed "$code" </dev/null || true
    fi
    cleanup
    exit "$code"
}

if [[ "$ACTION" == --help ]]; then
    printf 'Ashapp remote backend. Invoked by the desktop app.\n'
    exit 0
fi
[[ $EUID -eq 0 ]] || { printf 'ERROR: root is required.\n' >&2; exit 1; }
[[ ! -L "$LOG" && ( ! -e "$LOG" || -f "$LOG" ) ]] || { printf 'ERROR: Unsafe action log path.\n' >&2; exit 1; }
touch "$LOG"; chmod 600 "$LOG"
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
trap 'restore_ssh; cleanup' EXIT
[[ ! -L /run/ashapp ]] || fatal 'Unsafe runtime directory.'
install -d -o root -g root -m 0700 /run/ashapp
exec 9>/run/ashapp/setup.lock
flock -n 9 || fatal 'Another Ashapp operation is running on this server.'

preflight() {
    [[ -f /etc/os-release ]] || fatal 'Operating system metadata is missing.'
    # OS metadata is trusted system configuration, never user input.
    . /etc/os-release
    case "$ID:${VERSION_ID:-}" in
        ubuntu:22.04|ubuntu:24.04|debian:12) ;;
        *) fatal 'Supported systems: Ubuntu 22.04/24.04 and Debian 12.' ;;
    esac
    [[ "$(ps -p 1 -o comm=)" == systemd ]] || fatal 'A VPS with systemd is required.'
    local virt
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    [[ "$virt" != lxc && "$virt" != openvz ]] || fatal 'The kernel module requires a full VPS/KVM.'
    local python=false
    command -v python3 >/dev/null && python=true
    printf 'ASHAPP_JSON:{"os":"%s","version":"%s","kernel":"%s","architecture":"%s","python":%s}\n' \
        "$ID" "$VERSION_ID" "$(uname -r)" "$(uname -m)" "$python"
}

ensure_ssh_ready() {
    # Ubuntu's socket-activated OpenSSH package upgrade can stop ssh.service
    # and remove /run/sshd while this accepted session stays connected. A new
    # login would start it again, but sshd -t/-T in this session fails first.
    # Starting the existing unit restores its owned runtime directory without
    # restarting an active daemon or changing its socket/configuration policy.
    systemctl start ssh || systemctl start sshd
    /usr/sbin/sshd -t
    ok 'SSH service is ready; existing sessions are preserved.'
}

dependencies() {
    header 'Base packages'
    printf '%s\n' 'iptables-persistent iptables-persistent/autosave_v4 boolean false' \
        'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 update
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 install -y sudo curl wget ca-certificates python3 openssh-server \
        iptables iptables-persistent procps iproute2
    ensure_ssh_ready
    ok 'Base dependencies installed.'
}

upgrade() {
    header 'System upgrade'
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 update
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 upgrade -y
    ensure_ssh_ready
    if [[ -f /var/run/reboot-required ]]; then warn 'Reboot before building AmneziaWG.'; fi
}

root_password() {
    header 'Change root password'
    local password
    field password
    [[ ${#password} -ge 8 && "$password" != *$'\n'* && "$password" != *$'\r'* ]] || fatal 'Invalid password.'
    python3 "$BASE_DIR/lifecycle.py" record-credential root-password started
    printf 'root:%s\n' "$password" | chpasswd
    unset password
    python3 "$BASE_DIR/lifecycle.py" record-credential root-password committed
    ok 'Root password changed.'
}

create_user() {
    header 'Administrator account'
    local user password uid temporary
    field user; field password
    username_ok "$user" || fatal 'Invalid username.'
    [[ ${#password} -ge 8 && "$password" != *$'\n'* && "$password" != *$'\r'* ]] || fatal 'Invalid password.'
    if id "$user" >/dev/null 2>&1; then
        uid="$(id -u "$user")"
        (( uid >= 1000 && uid < 65534 )) || fatal 'System accounts cannot be changed.'
    else
        adduser --disabled-password --gecos '' --shell /bin/bash "$user" >/dev/null
    fi
    usermod -aG sudo -s /bin/bash "$user"
    temporary="$(mktemp /etc/sudoers.d/.ashapp.XXXXXXXX)"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "$temporary"
    chmod 440 "$temporary"
    visudo -cf "$temporary"
    install -o root -g root -m 0440 "$temporary" "/etc/sudoers.d/90-ashapp-$user"
    rm -f -- "$temporary"
    visudo -cf /etc/sudoers
    python3 "$BASE_DIR/lifecycle.py" record-credential administrator started
    printf '%s:%s\n' "$user" "$password" | chpasswd
    unset password
    python3 "$BASE_DIR/lifecycle.py" record-credential administrator committed
    ok 'Passwordless sudo granted to the administrator.'
}

ssh_config() {
    header 'SSH settings'
    local user root_mode timestamp extra new addr host root_effective password_effective
    field user; field root_mode
    username_ok "$user" || fatal 'Invalid username.'
    [[ "$root_mode" == keep || "$root_mode" == no ]] || fatal 'Invalid root SSH mode.'
    # One sshd -T -C address cannot prove a global denial across Match rules.
    if [[ "$root_mode" == no ]]; then
        ssh_policy_without_match /etc/ssh/sshd_config || fatal 'Root SSH was not changed. Conditional (Match) or unsupported SSH policy needs manual review.'
    fi
    timestamp="$(date +%Y%m%d-%H%M%S-%N)"
    SSH_BACKUP="/etc/ssh/sshd_config.bak.$timestamp"
    cp -a -- /etc/ssh/sshd_config "$SSH_BACKUP"
    if [[ -f /etc/ssh/ashapp.conf ]]; then
        SSH_EXTRA_BACKUP="/etc/ssh/ashapp.conf.bak.$timestamp"
        cp -a -- /etc/ssh/ashapp.conf "$SSH_EXTRA_BACKUP"
    fi
    # Our Include must be first: sshd normally uses the first global value it sees.
    new="$(mktemp /etc/ssh/.ashapp-main.XXXXXXXX)"
    printf 'Include /etc/ssh/ashapp.conf\n' > "$new"
    sed '\|^Include /etc/ssh/ashapp.conf$|d' /etc/ssh/sshd_config >> "$new"
    SSH_CHANGED=1
    cat "$new" > /etc/ssh/sshd_config
    rm -f -- "$new"
    extra="$(mktemp /etc/ssh/.ashapp-extra.XXXXXXXX)"
    # Do not reopen password authentication on an already hardened server.
    printf 'PubkeyAuthentication yes\n' > "$extra"
    if [[ "$root_mode" == no ]]; then
        printf 'PermitRootLogin no\n' >> "$extra"
    elif [[ -n "$SSH_EXTRA_BACKUP" ]]; then
        # Preserve a previous Ashapp root decision when only adjusting password login.
        sed -n '/^PermitRootLogin /p' "$SSH_EXTRA_BACKUP" >> "$extra"
    fi
    install -o root -g root -m 0600 "$extra" /etc/ssh/ashapp.conf
    rm -f -- "$extra"
    /usr/sbin/sshd -t
    addr="${SSH_CONNECTION:-127.0.0.1}"; addr="${addr%% *}"
    host="$(hostname)"
    password_effective="$(/usr/sbin/sshd -T -C "user=$user,addr=$addr,host=$host" | awk '$1=="passwordauthentication" {print $2}')"
    [[ -n "$password_effective" ]] || fatal 'SSH authentication policy could not be verified.'
    if [[ "$root_mode" == no ]]; then
        root_effective="$(/usr/sbin/sshd -T -C "user=root,addr=$addr,host=$host" | awk '$1=="permitrootlogin" {print $2}')"
        [[ "$root_effective" == no ]] || fatal 'An SSH Match block permits root; restoring the original configuration.'
    fi
    systemctl reload ssh || systemctl reload sshd
    SSH_CHANGED=0
    ok 'SSH validated and reloaded. Current session preserved.'
}

ssh_policy_without_match() {
    python3 - "$1" <<'SSH_POLICY'
import glob
import re
import shlex
import sys
from pathlib import Path

def check_config(path, base=Path('/etc/ssh'), stack=(), budget=None):
    if budget is None:
        budget = [0, 0]
    path = Path(path).resolve(strict=True)
    if path in stack or len(stack) >= 16:
        raise ValueError('Cyclic or excessively nested SSH Includes.')
    budget[0] += 1
    content = path.read_bytes()
    budget[1] += len(content)
    if budget[0] > 128 or budget[1] > 4 * 1024 * 1024:
        raise ValueError('SSH policy exceeds review limits.')
    for line in content.decode('utf-8').splitlines():
        tokens = shlex.split(line, comments=True, posix=True)
        if not tokens:
            continue
        keyword, equal, attached = tokens.pop(0).partition('=')
        keyword = keyword.lower()
        if equal and attached:
            tokens.insert(0, attached)
        elif not equal and tokens and tokens[0].startswith('='):
            value = tokens.pop(0)[1:]
            if value:
                tokens.insert(0, value)
        if keyword == 'match':
            raise ValueError('Conditional SSH policy requires manual review.')
        if keyword != 'include':
            continue
        if not tokens:
            raise ValueError('Empty SSH Include.')
        for value in tokens:
            # sshd/libc glob and Python glob differ for bracket classes and
            # extensions. Refuse them rather than treating an unmatched pattern
            # as proof that no conditional policy exists.
            if any(c in value for c in ('~', '$', '%', '\\', '\x00', '[', ']', '{', '}')):
                raise ValueError('Unsupported SSH Include syntax.')
            target = Path(value)
            if not target.is_absolute():
                target = base / target
            matches = sorted(glob.glob(str(target)))
            if not matches and not glob.has_magic(str(target)):
                raise ValueError('Missing SSH Include.')
            for child in matches:
                check_config(child, base, (*stack, path), budget)

if __name__ == '__main__':
    try:
        check_config(sys.argv[1])
    except (OSError, ValueError):
        raise SystemExit(1)
SSH_POLICY
}

icmp() {
    header 'Block ping replies'
    # A netfilter-persistent plugin avoids snapshotting Docker/AWG dynamic chains.
    install -d -m 0755 /usr/share/netfilter-persistent/plugins.d
    if [[ -e /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp ]] && ! grep -qF 'ashapp-owned-icmp-v1' /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp; then
        fatal 'An existing ping rule or plugin needs manual review; it was not changed.'
    fi
    if [[ -e /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp ]]; then
        python3 "$BASE_DIR/lifecycle.py" verify-ping </dev/null >/dev/null
    fi
    cat > /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp <<'PLUGIN'
#!/bin/sh
# ashapp-owned-icmp-v1
set -e
case "$1" in
    start|restart|reload)
        iptables -C INPUT -p icmp --icmp-type echo-request -m comment --comment ashapp-owned-icmp-v1 -j DROP 2>/dev/null ||
            iptables -I INPUT -p icmp --icmp-type echo-request -m comment --comment ashapp-owned-icmp-v1 -j DROP
        ;;
    flush)
        while iptables -C INPUT -p icmp --icmp-type echo-request -m comment --comment ashapp-owned-icmp-v1 -j DROP 2>/dev/null; do
            iptables -D INPUT -p icmp --icmp-type echo-request -m comment --comment ashapp-owned-icmp-v1 -j DROP
        done
        ;;
    save|stop) : ;;
esac
PLUGIN
    chmod 755 /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp
    /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp start
    systemctl enable netfilter-persistent
    ok 'IPv4 ping blocked; netfilter-persistent restores the rule on startup.'
}

prepare_awg() {
    header 'Prepare AmneziaWG kernel packages'
    [[ -d "/lib/modules/$(uname -r)" ]] || fatal 'Current kernel module directory is missing.'
    [[ ! -f /var/run/reboot-required ]] || fatal 'Reboot after the kernel upgrade before continuing.'
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 update
    apt-get -o DPkg::Options::=--force-confold -o DPkg::Lock::Timeout=180 install -y dkms git build-essential "linux-headers-$(uname -r)" qrencode
    git --version; dkms --version
    printf '%s  %s\n' '10c9ef9b3b4e9ee4838c06fb8fe89a512a65149f68830dc87fe90f437d2accd4' \
        "$BASE_DIR/amneziawg-install.sh" | sha256sum -c -
    install -d -m 0700 /opt/ashapp/vendor
    install -m 0700 "$BASE_DIR/amneziawg-install.sh" /opt/ashapp/vendor/amneziawg-install.sh
    ok 'Pinned installer verified for configured kernel installation.'
}


check_awg() {
    header 'Verify AmneziaWG kernel interface'
    if ! modprobe amneziawg; then
        dkms status || true
        dmesg | tail -n 20 || true
        fatal 'The kernel module did not load.'
    fi
    command -v awg
    if pgrep -x amneziawg-go >/dev/null; then fatal 'amneziawg-go detected. Only kernel mode is supported.'; fi
    python3 "$BASE_DIR/clients.py" status
    python3 - "$BASE_DIR/clients.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('clients', sys.argv[1])
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
status = module.status()
if not (status['awg'] and status['kernel'] and not status['userspace']):
    raise SystemExit('ERROR: The AWG kernel interface or service is inactive.')
PY
    ok 'Kernel interface verified; no amneziawg-go process detected.'
}

docker_ready() {
    python3 "$BASE_DIR/docker_setup.py"
}

socks_install() {
    header 'SOCKS5 proxy'
    local port user password replace directory occupied access bind
    field port; field user; field password; field replace
    access=public
    if IFS= read -r -d '' access; then :; else access=public; fi
    [[ "$access" == public || "$access" == private ]] || fatal 'Invalid SOCKS5 exposure mode.'
    port_ok "$port" || fatal 'Invalid port.'
    [[ "$user" =~ ^[a-zA-Z0-9_]{1,128}$ && "$password" =~ ^[a-zA-Z0-9_]{8,128}$ ]] || fatal 'SOCKS5 credentials must use letters, digits or underscores.'
    if [[ "$access" == private ]]; then
        # A fresh VPS has no daemon to inspect yet. Install/start a missing
        # Docker first, while preserving the early refusal for existing shared
        # daemons. Never create a localhost publication before the version check.
        if ! command -v docker >/dev/null; then docker_ready; fi
        python3 "$BASE_DIR/clients.py" socks-private-ready >/dev/null
    fi
    docker_ready
    if docker inspect --type container amnezia-socks5proxy >/dev/null 2>&1 && [[ "$replace" != yes ]]; then
        fatal 'SOCKS5 already exists. Explicit replacement is required.'
    fi
    directory=/opt/ashapp/socks5
    install -d -m 0700 "$directory"
    cat > "$directory/Dockerfile" <<'DOCKERFILE'
FROM 3proxy/3proxy:busybox@sha256:1b21878c40b112723bd525d3282afb19136e6ccfd2b626b1ca0f53737c26bde1
LABEL org.opencontainers.image.title="Amnezia-compatible SOCKS5 / Ashapp"
LABEL io.ashapp.managed="socks5-v1"
RUN mkdir -p /opt/amnezia /usr/local/3proxy/conf /usr/local/3proxy/logs
COPY start.sh /opt/amnezia/start.sh
ENTRYPOINT ["/bin/sh", "/opt/amnezia/start.sh"]
DOCKERFILE
    cat > "$directory/start.sh" <<'START'
#!/bin/sh
if [ -s /usr/local/3proxy/conf/3proxy.cfg ]; then
    exec /bin/3proxy /usr/local/3proxy/conf/3proxy.cfg
fi
exec tail -f /dev/null
START
    docker build -t amnezia-socks5proxy "$directory"
    if docker inspect --type container amnezia-socks5proxy >/dev/null 2>&1; then
        SOCKS_WAS_RUNNING="$(docker inspect --type container -f '{{.State.Running}}' amnezia-socks5proxy)"
        SOCKS_BACKUP="ashapp-socks5-backup-$(date +%s%N)"
        docker stop amnezia-socks5proxy >/dev/null
        docker rename amnezia-socks5proxy "$SOCKS_BACKUP"
    fi
    SOCKS_NEW=1
    bind="$port:$port/tcp"
    if [[ "$access" == private ]]; then bind="127.0.0.1:$port:$port/tcp"; fi
    docker run -d --restart always --label io.ashapp.managed=socks5-v1 -p "$bind" --name amnezia-socks5proxy amnezia-socks5proxy >/dev/null
    SECRET_TMP="$(mktemp /run/ashapp.XXXXXXXXXX)"
    {
        printf 'config /usr/local/3proxy/conf/3proxy.cfg\n'
        printf 'timeouts 1 5 30 60 180 1800 15 60\n'
        printf 'nserver 1.1.1.1\nnserver 1.0.0.1\n'
        printf 'users %s:CL:%s\n' "$user" "$password"
        printf 'auth strong\nallow %s\nsocks -p%s\n' "$user" "$port"
    } > "$SECRET_TMP"
    unset password
    docker cp "$SECRET_TMP" amnezia-socks5proxy:/usr/local/3proxy/conf/3proxy.cfg
    docker exec amnezia-socks5proxy chmod 600 /usr/local/3proxy/conf/3proxy.cfg
    cleanup; SECRET_TMP=''
    docker restart amnezia-socks5proxy >/dev/null
    python3 "$BASE_DIR/clients.py" socks-check
    SOCKS_NEW=0
    if [[ -n "$SOCKS_BACKUP" ]]; then
        local previous="$SOCKS_BACKUP"
        SOCKS_BACKUP=''
        docker rm "$previous" >/dev/null || warn 'New SOCKS5 is healthy; an old stopped container could not be removed.'
    fi
    ok 'SOCKS5 authentication verified.'
    warn 'AmneziaVPN caches existing SOCKS5 credentials on this computer. Update its saved proxy credentials there, or remove and rediscover that service. Server-side changes cannot update another application on your computer.'
}

if command -v python3 >/dev/null && [[ -f "$BASE_DIR/lifecycle.py" ]]; then
    python3 "$BASE_DIR/lifecycle.py" record-action "$ACTION" running </dev/null
fi

case "$ACTION" in
    preflight) preflight ;;
    security-status|security-preview|security-stage|security-setup|security-confirm|security-rollback|security-unban|security-reset-preview|security-reset-stage)
        python3 "$BASE_DIR/security_manager.py" "$ACTION" ;;
    lifecycle-status|lifecycle-begin|lifecycle-step|lifecycle-finish|diagnostics|reset-preview|reset)
        python3 "$BASE_DIR/lifecycle.py" "$ACTION" ;;
    dependencies) dependencies ;;
    upgrade) upgrade ;;
    root-password) root_password ;;
    create-user) create_user ;;
    ssh-config) ssh_config ;;
    icmp) icmp ;;
    prepare-awg) prepare_awg ;;
    install-awg-configured) python3 "$BASE_DIR/awg_setup.py" ;;
    install-awg-amnezia)
        docker_ready </dev/null
        python3 "$BASE_DIR/amnezia_setup.py" ;;
    install-vless|vless-control) python3 "$BASE_DIR/vless_manager.py" "$ACTION" ;;
    check-awg) check_awg ;;
    socks-install) socks_install ;;
    status|clients|add-client|get-client|revoke-client|rename-client|import-client|socks-info|socks-check|users|awg-control|socks-control)
        python3 "$BASE_DIR/clients.py" "$ACTION" ;;
    ssh-key)
        field key_user; field key
        username_ok "$key_user" || [[ "$key_user" == root ]] || fatal 'Invalid account.'
        key_home="$(getent passwd "$key_user" | cut -d: -f6)"
        [[ -d "$key_home" && "$key" != *$'\n'* && "$key" != *$'\r'* ]] || fatal 'Invalid public key.'
        SECRET_TMP="$(mktemp /run/ashapp.XXXXXXXXXX)"
        printf '%s\n' "$key" > "$SECRET_TMP"
        ssh-keygen -lf "$SECRET_TMP" >/dev/null || fatal 'Invalid OpenSSH public key.'
        install -d -o "$key_user" -g "$(id -gn "$key_user")" -m 0700 "$key_home/.ssh"
        touch "$key_home/.ssh/authorized_keys"
        grep -qxF -- "$key" "$key_home/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$key_home/.ssh/authorized_keys"
        chown "$key_user:$(id -gn "$key_user")" "$key_home/.ssh/authorized_keys"
        chmod 600 "$key_home/.ssh/authorized_keys"
        ok 'Public key installed.' ;;
    icmp-unblock)
        if [[ -x /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp ]]; then
            grep -qF 'ashapp-owned-icmp-v1' /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp || fatal 'The existing ping plugin needs manual review; no rules were removed.'
            python3 "$BASE_DIR/lifecycle.py" verify-ping </dev/null >/dev/null
            /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp flush
            rm -f /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp
        fi
        ok 'Ashapp ping block removed.' ;;
    reboot)
        header 'Reboot'
        systemd-run --unit="ashapp-reboot-$(date +%s)" --on-active=3s /usr/sbin/reboot ;;
    *) fatal 'Unknown action.' ;;
esac

if command -v python3 >/dev/null && [[ -f "$BASE_DIR/lifecycle.py" ]]; then
    python3 "$BASE_DIR/lifecycle.py" record-action "$ACTION" done </dev/null
fi
