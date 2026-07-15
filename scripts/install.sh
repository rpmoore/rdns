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

# True (0) if $1 is a strictly lower dotted version than $2.
version_lt() {
  [ "$1" = "$2" ] && return 1
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

# True (0) if $1 is a plain dotted-numeric version (e.g. "0.1.4") that's
# safe to feed to version_lt.
looks_like_version() {
  case "$1" in
    ''|*[!0-9.]*) return 1 ;;
  esac
}

usage() {
  cat <<'EOF'
Usage: install.sh [--yes] [--no-service] [--version <tag>] [--help]

  --yes, -y          Install and enable the systemd service without prompting.
  --no-service       Install the binary only; skip the systemd service setup.
  --version <tag>    Install a specific release tag (e.g. v0.1.2) instead of
                     latest — this can also downgrade an existing install.
                     Downgrading prompts for confirmation unless --yes (or
                     RDNS_INSTALL_YES=1) is given.
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

# Release binaries are built on ubuntu-latest and are glibc-linked. A
# musl-only system (e.g. Alpine) reports x86_64 too, but the binary won't
# run there — ldd itself is the musl libc on those systems and says so.
if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
  die "rdns installer's release binary is glibc-linked and will not run on musl-based systems (e.g. Alpine); detected musl libc"
fi

for tool in curl tar sha256sum grep sed head install mktemp sort awk timeout; do
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
    "https://api.github.com/repos/${REPO}/releases/latest" || true)"
  [ -n "$http_code" ] || http_code="000"
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

# --- Warn/confirm on downgrade ----------------------------------------------

installed_version=""
# Reject a symlink at this path outright rather than executing whatever it
# points to as root; only run a plain, non-symlink, executable regular file
# (this does not check ownership/permissions beyond that).
if [ -f "$INSTALL_DIR/$BIN_NAME" ] && [ ! -L "$INSTALL_DIR/$BIN_NAME" ] && [ -x "$INSTALL_DIR/$BIN_NAME" ]; then
  # `timeout` guards against a pre-`version`-subcommand binary that would
  # otherwise ignore the "version" arg and start serving DNS/metrics forever,
  # hanging the installer instead of just failing the version query.
  installed_version="$(timeout 5s "$INSTALL_DIR/$BIN_NAME" version 2>/dev/null | awk '{print $2}')" || true
fi

target_version="${TAG#v}"
installed_version="${installed_version#v}"

# installed_version fails to look like a version for a fresh install, if the
# existing binary predates the `version` subcommand, if querying it timed
# out, or if its output was garbage. target_version fails to look like one
# for a non-semver tag (e.g. "latest" or "v0.1.0-rc1"). Either way, skip the
# downgrade check rather than risk a wrong verdict from version_lt.
if looks_like_version "$installed_version" && looks_like_version "$target_version" \
  && version_lt "$target_version" "$installed_version"; then
  warn "downgrading rdns: installed version is ${installed_version}, requested is ${target_version} (${TAG})."
  warn "an older binary may not understand config/state written by ${installed_version}."
  if [ "$AUTO_YES" -eq 1 ]; then
    log "proceeding with downgrade (--yes/RDNS_INSTALL_YES set)."
  elif [ -r /dev/tty ] && { exec 3<>/dev/tty; } 2>/dev/null; then
    printf 'Continue with downgrade to %s? [y/N] ' "$TAG" >&3
    read -r reply <&3
    exec 3<&-
    case "$reply" in
      [yY]|[yY][eE][sS]) ;;
      *) die "downgrade cancelled" ;;
    esac
  else
    die "downgrading from ${installed_version} to ${target_version} requires confirmation; re-run interactively, or pass --yes (or RDNS_INSTALL_YES=1) to confirm non-interactively."
  fi
fi

log "Installing rdns ${TAG} (linux-x86_64)"

ASSET="rdns-${TAG}-linux-x86_64.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

# --- Download & verify -----------------------------------------------------

log "Downloading ${ASSET}..."
curl -fsSL --retry 3 -o "$TMPDIR/$ASSET" "$DOWNLOAD_URL" \
  || die "failed to download $DOWNLOAD_URL (check that this release/asset exists)"

log "Verifying download integrity..."
curl -fsSL --retry 3 -o "$TMPDIR/$ASSET.sha256" "$CHECKSUM_URL" \
  || die "failed to download checksum file $CHECKSUM_URL — refusing to install without an integrity check"

# Note: this only proves the tarball matches what release.yml published — the
# checksum comes from the same GitHub origin as the binary, so it guards
# against a corrupted/incomplete download, not against a compromised release.
( cd "$TMPDIR" && sha256sum -c "$ASSET.sha256" ) \
  || die "checksum mismatch for $ASSET — the download is corrupted or was tampered with in transit"

# --- Extract & install binary ------------------------------------------------

archive_members="$(tar -tzf "$TMPDIR/$ASSET")"
[ "$archive_members" = "$BIN_NAME" ] \
  || die "unexpected archive contents (expected only '$BIN_NAME', got: $archive_members)"

tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
[ -f "$TMPDIR/$BIN_NAME" ] || die "extracted archive did not contain a '$BIN_NAME' binary"

service_was_active=0
service_was_enabled=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet rdns.service 2>/dev/null; then
    service_was_active=1
  fi
  if systemctl is-enabled --quiet rdns.service 2>/dev/null; then
    service_was_enabled=1
  fi
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
  for tool in systemctl getent useradd groupadd cmp cp date; do
    command -v "$tool" >/dev/null 2>&1 \
      || die "required tool '$tool' not found for systemd service setup (this system may not use systemd); re-run with --no-service to skip it"
  done

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
# local_dns_entries hot-reload — dns_listen, [metrics], and [chaos] changes
# require `systemctl restart rdns`). Override the path with the
# RDNS_CONFIG environment variable.
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
max_tcp_connections = 128

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

# Answers `version.bind. CH TXT` (BIND's classic operator-fingerprint
# query, e.g. `dig version.bind chaos txt`) with a fixed string instead of
# resolving it like a normal query. On by default; set enabled = false to
# opt out.
[chaos]
enabled = true
version_bind = "rdns"
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

# Log level defaults to "info" (startup/shutdown/errors only — no
# per-query lines). To temporarily see the per-query audit trail:
#   sudo systemctl edit rdns
# and add:
#   [Service]
#   Environment=RUST_LOG=debug
# then `systemctl restart rdns`. Revert by removing the override.
#Environment=RUST_LOG=info

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

  if [ "$already_has_unit" -eq 1 ]; then
    # Upgrade: respect whatever enabled/active state the operator already
    # chose — don't re-enable or (re)start a service they deliberately
    # disabled or stopped.
    if [ "$service_was_enabled" -eq 1 ]; then
      systemctl enable rdns.service >/dev/null
    fi
    if [ "$service_was_active" -eq 1 ]; then
      log "Restarting rdns.service (binary updated)..."
      systemctl restart rdns.service
    else
      log "rdns.service was not running before this upgrade; leaving it stopped."
      echo "    Start it with: systemctl start rdns.service"
    fi
  else
    systemctl enable rdns.service >/dev/null
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
