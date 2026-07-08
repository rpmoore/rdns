#!/usr/bin/env bash
# rdns installer — fetches the latest (or a pinned) GitHub release binary,
# installs it to /usr/local/bin, and optionally sets up a systemd service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rpmoore/rdns/main/scripts/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --yes
#   curl -fsSL .../install.sh | sudo bash -s -- --version v0.1.2 --no-service

set -euo pipefail

REPO="rpmoore/rdns"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="rdns"
CONFIG_DIR="/etc/rdns"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
UNIT_PATH="/etc/systemd/system/rdns.service"
SVC_USER="rdns"

VERSION_OVERRIDE=""
AUTO_YES=0
NO_SERVICE=0

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh [--yes] [--no-service] [--version <tag>] [--help]

  --yes, -y          Install and enable the systemd service without prompting.
  --no-service       Install the binary only; skip the systemd service setup.
  --version <tag>    Install a specific release tag (e.g. v0.1.2) instead of latest.
  --help             Show this help.

Environment variable equivalents (useful for scripted/CI installs):
  RDNS_INSTALL_YES=1
  RDNS_INSTALL_NO_SERVICE=1
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) AUTO_YES=1 ;;
    --no-service) NO_SERVICE=1 ;;
    --version)
      shift
      [ $# -gt 0 ] || die "--version requires an argument"
      VERSION_OVERRIDE="$1"
      ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[ "${RDNS_INSTALL_YES:-0}" = "1" ] && AUTO_YES=1
[ "${RDNS_INSTALL_NO_SERVICE:-0}" = "1" ] && NO_SERVICE=1

# --- Preflight -----------------------------------------------------------

os="$(uname -s)"
[ "$os" = "Linux" ] || die "rdns installer currently supports Linux x86_64 only (detected: $os)"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ;;
  *) die "rdns installer currently supports Linux x86_64 only (detected arch: $arch)" ;;
esac

for tool in curl tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not found; install it and re-run"
done

if [ "$(id -u)" -ne 0 ]; then
  die "this installer must be run as root (it writes to /etc, /usr/local/bin, and /etc/systemd/system, and creates a system user).

Re-run with:
  curl -fsSL https://raw.githubusercontent.com/rpmoore/rdns/main/scripts/install.sh | sudo bash"
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# --- Resolve version -------------------------------------------------------

if [ -n "$VERSION_OVERRIDE" ]; then
  TAG="$VERSION_OVERRIDE"
else
  log "Looking up latest release for ${REPO}..."
  http_code="$(curl -sSL -o "$TMPDIR/latest.json" -w '%{http_code}' \
    "https://api.github.com/repos/${REPO}/releases/latest" || echo "000")"
  case "$http_code" in
    200) ;;
    404) die "no published release found for ${REPO} yet" ;;
    403) die "GitHub API rate limit hit while resolving the latest release; try again shortly" ;;
    *) die "failed to query GitHub releases API (HTTP $http_code)" ;;
  esac
  TAG="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$TMPDIR/latest.json" \
    | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
  [ -n "$TAG" ] || die "could not parse a release tag from the GitHub API response"
fi

case "$TAG" in
  *[!A-Za-z0-9._-]*|"") die "invalid release tag: '$TAG'" ;;
esac

log "Installing rdns ${TAG} (linux-x86_64)"

ASSET="rdns-${TAG}-linux-x86_64.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

# --- Download & verify -----------------------------------------------------

log "Downloading ${ASSET}..."
curl -fsSL --retry 3 -o "$TMPDIR/$ASSET" "$DOWNLOAD_URL" \
  || die "failed to download $DOWNLOAD_URL (check that this release/asset exists)"

log "Verifying checksum..."
curl -fsSL --retry 3 -o "$TMPDIR/$ASSET.sha256" "$CHECKSUM_URL" \
  || die "failed to download checksum file $CHECKSUM_URL — refusing to install an unverified binary"

( cd "$TMPDIR" && sha256sum -c "$ASSET.sha256" ) \
  || die "checksum verification failed for $ASSET — the download may be corrupted or tampered with"

# --- Extract & install binary ------------------------------------------------

archive_members="$(tar -tzf "$TMPDIR/$ASSET")"
[ "$archive_members" = "$BIN_NAME" ] \
  || die "unexpected archive contents (expected only '$BIN_NAME', got: $archive_members)"

tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
[ -f "$TMPDIR/$BIN_NAME" ] || die "extracted archive did not contain a '$BIN_NAME' binary"

service_was_active=0
if systemctl is-active --quiet rdns.service 2>/dev/null; then
  service_was_active=1
fi

install -d -m 0755 -o root -g root "$INSTALL_DIR"
install -m 0755 -o root -g root "$TMPDIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

# --- Decide whether to set up systemd ---------------------------------------

already_has_unit=0
[ -f "$UNIT_PATH" ] && already_has_unit=1

setup_service=0
if [ "$NO_SERVICE" -eq 1 ]; then
  setup_service=0
elif [ "$already_has_unit" -eq 1 ]; then
  # Upgrading an existing install: keep the service configured, don't re-prompt.
  setup_service=1
elif [ "$AUTO_YES" -eq 1 ]; then
  setup_service=1
elif [ -r /dev/tty ] && { exec 3<>/dev/tty; } 2>/dev/null; then
  printf 'Install and start rdns as a systemd service (recommended)? [Y/n] ' >&3
  read -r reply <&3
  exec 3<&-
  case "$reply" in
    [nN]|[nN][oO]) setup_service=0 ;;
    *) setup_service=1 ;;
  esac
else
  warn "no interactive terminal available; skipping systemd service setup."
  warn "re-run with --yes (or RDNS_INSTALL_YES=1) to install it non-interactively."
  setup_service=0
fi

config_freshly_installed=0
unit_backup=""

if [ "$setup_service" -eq 1 ]; then
  command -v systemctl >/dev/null 2>&1 \
    || die "systemctl not found — this system does not appear to use systemd; re-run with --no-service"

  if ! getent group "$SVC_USER" >/dev/null; then
    groupadd --system "$SVC_USER"
  fi
  if ! getent passwd "$SVC_USER" >/dev/null; then
    nologin_shell="/usr/sbin/nologin"
    [ -x "$nologin_shell" ] || nologin_shell="/sbin/nologin"
    [ -x "$nologin_shell" ] || nologin_shell="$(command -v nologin || true)"
    [ -n "$nologin_shell" ] || nologin_shell="/bin/false"

    log "Creating system user '$SVC_USER'..."
    useradd --system --no-create-home --shell "$nologin_shell" \
      --gid "$SVC_USER" --comment "rdns DNS resolver daemon" "$SVC_USER"
  fi

  install -d -m 0755 -o root -g root "$CONFIG_DIR"

  if [ ! -f "$CONFIG_FILE" ]; then
    log "Installing default config to $CONFIG_FILE"
    cat > "$CONFIG_FILE" <<'RDNS_DEFAULT_CONFIG_EOF'
# rdns runtime configuration — installed default.
#
# Loaded on startup, and re-loaded on SIGHUP (resolution, upstreams, and
# local_dns_entries hot-reload — dns_listen and [metrics] changes require
# `systemctl restart rdns`). Override the path with the RDNS_CONFIG
# environment variable.
#
# Installed once; re-running the installer never overwrites this file.
#
# Keep this file in sync with the embedded copy in scripts/install.sh.

# LAN-facing bind on the standard port. The installer grants the rdns
# service account CAP_NET_BIND_SERVICE via systemd AmbientCapabilities,
# so no setcap/root is needed at runtime.
#
# WARNING: 0.0.0.0 listens on every interface, including any public one
# this host may have. An open recursive resolver reachable from the
# internet is a well-known DDoS amplification vector — if this host has
# a public IP, firewall UDP/TCP 53 to your LAN/trusted subnet only, or
# change this to a specific LAN address (e.g. "192.168.1.1:53").
dns_listen = ["0.0.0.0:53"]
per_query_deadline_ms = 2000
max_udp_payload_size = 1232

# Prometheus metrics on GET /metrics — no TLS/auth, loopback-only by
# default. Only change `listen` to a routable address if you understand
# the exposure (e.g. put it behind a firewall/reverse proxy first).
[metrics]
enabled = true
listen = "127.0.0.1:9053"
max_connections = 32

# Recursive mode: rdns walks root -> TLD -> authority itself for anything
# not answered locally. Switch to mode = "forward" and add [[upstreams]]
# entries instead if you'd rather forward to an upstream resolver.
[resolution]
mode = "recursive"

[resolution.recursive]
root_hints = "bundled"
root_hints_version = "bundled:v1"

# No local DNS entries by default. To answer exact names for devices on
# your network (suffix ".lan"), add a [[local_dns_entries]] block below,
# e.g.:
#
# [[local_dns_entries]]
# name = "nas.lan"
# ipv4 = ["192.168.1.10"]
# ttl = 300
# enabled = true
# public_address_acknowledged = false   # must be true if ipv4/ipv6 is a
#                                        # public/routable address
#
# Changes to local_dns_entries hot-reload on `systemctl reload rdns` —
# no restart needed.
RDNS_DEFAULT_CONFIG_EOF
    chmod 0644 "$CONFIG_FILE"
    config_freshly_installed=1
  else
    log "Existing config at $CONFIG_FILE left untouched"
  fi

  UNIT_TMP="$TMPDIR/rdns.service"
  cat > "$UNIT_TMP" <<'RDNS_SERVICE_UNIT_EOF'
# Keep this file in sync with the embedded copy in scripts/install.sh.
[Unit]
Description=rdns - Rust DNS resolver daemon
Documentation=https://github.com/rpmoore/rdns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rdns --config /etc/rdns/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s

User=rdns
Group=rdns

# Tags journald/syslog-forwarded lines as "rdns" (journalctl -t rdns),
# instead of the default derived-from-binary-path identifier.
SyslogIdentifier=rdns

# Bind port 53 without root. Ambient (process) capability, not `setcap`
# (a file xattr an upgrade's `install`/`cp` of a new binary would wipe).
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
RDNS_SERVICE_UNIT_EOF

  if [ -f "$UNIT_PATH" ] && ! cmp -s "$UNIT_TMP" "$UNIT_PATH"; then
    unit_backup="${UNIT_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    log "Existing $UNIT_PATH differs from the installer-managed unit; backing up to $unit_backup"
    cp -p "$UNIT_PATH" "$unit_backup"
  fi

  log "Installing systemd unit to $UNIT_PATH"
  install -m 0644 -o root -g root "$UNIT_TMP" "$UNIT_PATH"

  systemctl daemon-reload
  systemctl enable rdns.service >/dev/null

  if [ "$service_was_active" -eq 1 ]; then
    log "Restarting rdns.service (binary updated)..."
    systemctl restart rdns.service
  else
    log "Starting rdns.service..."
    systemctl start rdns.service
  fi

  systemctl --no-pager --full status rdns.service || true
fi

# --- Summary -----------------------------------------------------------

echo
log "rdns ${TAG} installed to ${INSTALL_DIR}/${BIN_NAME}"
if [ "$setup_service" -eq 1 ]; then
  log "Service installed and running. Useful commands:"
  echo "    journalctl -u rdns -f       # follow logs"
  echo "    systemctl reload rdns       # hot-reload resolution/upstreams/local_dns_entries"
  echo "    systemctl restart rdns      # apply dns_listen/[metrics] changes"
  if [ -n "$unit_backup" ]; then
    echo
    log "Your previous $UNIT_PATH had customizations; backed up to $unit_backup"
    echo "    before installing the installer-managed unit. Diff and re-apply any"
    echo "    overrides you want to keep (e.g. via a systemd drop-in)."
  fi
  if [ "$config_freshly_installed" -eq 1 ]; then
    echo
    log "$CONFIG_FILE ships with no local DNS entries configured."
    echo "    To answer names for devices on your network, edit $CONFIG_FILE and add a"
    echo "    [[local_dns_entries]] block (a commented example is already in the file),"
    echo "    then run: systemctl reload rdns"
    echo
    log "Security: dns_listen defaults to 0.0.0.0:53 (all interfaces)."
    echo "    If this host has a public IP, firewall port 53 to trusted networks only —"
    echo "    an open recursive resolver reachable from the internet can be abused for"
    echo "    DNS amplification attacks."
  fi
else
  log "Systemd service was not installed."
  echo "    Re-run this installer with --yes to install and start it as a service,"
  echo "    or run '${INSTALL_DIR}/${BIN_NAME} --config <path>' manually."
fi
