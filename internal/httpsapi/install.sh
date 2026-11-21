#!/bin/sh
# infra-agent installer, served by an infra-hub at GET /install. It holds no secret. Use it on a Debian or Ubuntu host that
# is already on the tailnet, as root:
#
#   curl -fsSk --pinnedpubkey <pin> https://<hub>:11883/install | sudo sh -s -- <ih1 token> <inventory-host-name> [--hub] [--force]
#
# What it does: installs what the agent's runs need if it is missing (ansible-core, git, openssh-client, age, curl, openssl,
# ca-certificates through apt; sops from its GitHub release, checked against the release's checksums file), creates
# /etc/infra (0700) and /etc/infra/age.key (and prints its public key), writes /etc/infra/agent.env (0600), installs the
# latest infra-agent release (checked against the release's SHA256SUMS) and the systemd unit. It does NOT start the agent.
# With --hub it also creates /etc/infra/deploy_key and writes github_known_hosts (hub hosts only).
# It is safe to run again. It never replaces an existing age.key or a different agent.env unless --force is given (the old
# file is kept as <file>.bak-<time>); with --force it replaces them.
#
# The whole script is one function that is called at the end, so that a command that reads standard input cannot eat
# the rest of a script that is piped into sh; every command that might read it gets /dev/null as well.

main() {
    set -eu
    umask 022

    sops_version=3.13.3 # keep in sync with sops_version in the infra repository (inventory/group_vars/all.yml)
    agent_repo=https://github.com/KazuhaHub/infra-hub/releases
    sops_repo=https://github.com/getsops/sops/releases/download
    lib_dir=/usr/local/lib/infra-agent
    etc_dir=/etc/infra
    github_repo=git@github.com:KazuhaHub/infra.git
    # GitHub's published ed25519 host key (SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU, see https://api.github.com/meta).
    github_host_key='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'

    usage() {
        echo "usage: sh -s -- <ih1 token> <inventory host name> [--hub] [--force]" >&2
        exit 2
    }
    die() {
        echo "install: $*" >&2
        exit 1
    }
    say() { echo "install: $*"; }

    token=${1:-}
    host=${2:-}
    [ -n "$token" ] && [ -n "$host" ] || usage
    shift 2
    hub=0
    force=0
    for arg in "$@"; do
        case $arg in
        --hub) hub=1 ;;
        --force) force=1 ;;
        *) usage ;;
        esac
    done
    case $token in
    ih1.?*) ;;
    *) die "the first argument is not an ih1. join token" ;;
    esac
    [ "${#token}" -le 16384 ] || die "the join token is too long"
    printf '%s\n' "${token#ih1.}" | grep -Eq '^[A-Za-z0-9_-]+$' || die "the join token has characters that are not allowed"
    printf '%s\n' "$host" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' || die "the host name has characters that are not allowed"
    [ "$(id -u)" = 0 ] || die "run as root (sudo sh -s -- ...)"
    [ "$(uname -s)" = Linux ] || die "Linux only"
    command -v apt-get >/dev/null 2>&1 || die "this installer supports Debian and Ubuntu (apt) only"
    case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
    esac

    # The new agent.env, built first so that a refusal below changes nothing.
    new_env=$(mktemp)
    work=$(mktemp -d)
    trap 'rm -rf "$work" "$new_env"' EXIT
    {
        echo "INFRA_AGENT_TOKEN=$token"
        echo "INFRA_AGENT_HOST=$host"
        echo "INFRA_AGENT_MODE=apply"
        if [ "$hub" = 1 ]; then echo "INFRA_AGENT_GITHUB_REPO=$github_repo"; fi
    } >"$new_env"
    if [ -e "$etc_dir/agent.env" ] && [ "$force" = 0 ] && ! cmp -s "$new_env" "$etc_dir/agent.env"; then
        die "$etc_dir/agent.env exists and differs from what this run would write; look at it, or run again with --force (the old file is kept as agent.env.bak-<time>)"
    fi
    stamp=$(date +%Y%m%d%H%M%S)
    backup() { # a file that --force is about to replace
        if [ -e "$1" ]; then cp -p "$1" "$1.bak-$stamp"; fi
    }

    # 1. Packages: only what is missing.
    pkgs=""
    need() { # command, package
        command -v "$1" >/dev/null 2>&1 || pkgs="$pkgs $2"
    }
    need ansible-playbook ansible-core
    need git git
    need ssh-keygen openssh-client
    need age-keygen age
    need curl curl
    need openssl openssl
    [ -e /etc/ssl/certs/ca-certificates.crt ] || pkgs="$pkgs ca-certificates"
    if [ -n "$pkgs" ]; then
        say "installing:$pkgs"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq </dev/null
        # shellcheck disable=SC2086
        apt-get install -y -qq $pkgs </dev/null >/dev/null
    fi

    # 2. sops, from its GitHub release; the checksum comes from the same release (sops-vX.Y.Z.checksums.txt).
    if ! command -v sops >/dev/null 2>&1; then
        say "installing sops $sops_version"
        sops_file=sops-v$sops_version.linux.$arch
        curl -fsSL --max-time 120 -o "$work/sops" "$sops_repo/v$sops_version/$sops_file" </dev/null
        curl -fsSL --max-time 60 -o "$work/sops.sums" "$sops_repo/v$sops_version/sops-v$sops_version.checksums.txt" </dev/null
        want=$(grep " [*]\{0,1\}$sops_file\$" "$work/sops.sums" | head -n 1 | cut -d' ' -f1)
        [ -n "$want" ] || die "no checksum for $sops_file in the sops release"
        [ "$(sha256sum "$work/sops" | cut -d' ' -f1)" = "$want" ] || die "the sops download does not match its checksum"
        install -m 755 "$work/sops" /usr/local/bin/sops
    fi

    # 3. /etc/infra and the age key.
    install -d -m 700 "$etc_dir"
    install -d -m 700 /var/lib/infra
    if [ -e "$etc_dir/age.key" ] && [ "$force" = 1 ]; then
        backup "$etc_dir/age.key"
        rm -f "$etc_dir/age.key"
        say "the old age key was kept as $etc_dir/age.key.bak-$stamp"
    fi
    if [ -e "$etc_dir/age.key" ]; then
        say "$etc_dir/age.key exists, kept"
    else
        (umask 077 && age-keygen -o "$etc_dir/age.key" >/dev/null 2>&1 </dev/null)
    fi
    chmod 600 "$etc_dir/age.key"
    age_pub=$(age-keygen -y "$etc_dir/age.key" </dev/null)

    # 4. agent.env.
    if [ -e "$etc_dir/agent.env" ] && ! cmp -s "$new_env" "$etc_dir/agent.env"; then
        backup "$etc_dir/agent.env"
    fi
    install -m 600 "$new_env" "$etc_dir/agent.env"

    # 5. Hub hosts: the deploy key the mirror and the GitHub fallback use, and GitHub's host key.
    deploy_pub=""
    if [ "$hub" = 1 ]; then
        if [ ! -e "$etc_dir/deploy_key" ]; then
            ssh-keygen -q -t ed25519 -N '' -C "infra@$host" -f "$etc_dir/deploy_key" </dev/null
        fi
        chmod 600 "$etc_dir/deploy_key"
        deploy_pub=$(cat "$etc_dir/deploy_key.pub" 2>/dev/null || ssh-keygen -y -f "$etc_dir/deploy_key" </dev/null)
        printf '%s\n' "$github_host_key" >"$etc_dir/github_known_hosts"
        chmod 644 "$etc_dir/github_known_hosts"
    fi

    # 6. infra-agent, the latest release; the redirect of the latest-release URL names the tag.
    tag=$(curl -fsSLI --max-time 30 -o /dev/null -w '%{url_effective}' "$agent_repo/latest" </dev/null | sed 's|.*/||')
    printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "cannot resolve the latest infra-hub release (got '$tag')"
    dir=$lib_dir/$tag
    if [ ! -x "$dir/infra-agent" ]; then
        say "downloading infra-agent $tag"
        curl -fsSL --max-time 180 -o "$work/infra-agent-linux-$arch" "$agent_repo/download/$tag/infra-agent-linux-$arch" </dev/null
        curl -fsSL --max-time 60 -o "$work/SHA256SUMS" "$agent_repo/download/$tag/SHA256SUMS" </dev/null
        (cd "$work" && grep " [*]\{0,1\}infra-agent-linux-$arch\$" SHA256SUMS | sha256sum -c --quiet -) ||
            die "the infra-agent download does not match the release's SHA256SUMS"
        chmod 755 "$work/infra-agent-linux-$arch"
        "$work/infra-agent-linux-$arch" version >/dev/null </dev/null || die "the downloaded infra-agent does not run"
        install -d -m 755 "$lib_dir" "$dir"
        install -m 755 "$work/infra-agent-linux-$arch" "$dir/infra-agent"
    fi
    ln -sfn "$dir/infra-agent" "$lib_dir/infra-agent.new"
    mv -T "$lib_dir/infra-agent.new" "$lib_dir/infra-agent"

    # 7. The unit (docs/infra-agent.service of infra-hub, with the stable path of the binary). Not started.
    unit=/etc/systemd/system/infra-agent.service
    cat >"$work/unit" <<'UNIT'
# Example unit for infra-agent. Copy it to /etc/systemd/system/infra-agent.service, then:
#   systemctl daemon-reload && systemctl enable --now infra-agent
# The settings are in /etc/infra/agent.env (the default of --env-file) (docs/agent.md); the agent reads that file itself.
[Unit]
Description=infra-agent (fetch, verify and apply the config bundle, report)
Documentation=https://github.com/KazuhaHub/infra-hub/blob/main/docs/agent.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/infra-agent run
Restart=always
RestartSec=30
# On stop systemd sends SIGTERM to the agent only (KillMode=mixed). The agent then sends SIGTERM to ansible's process
# group and SIGKILL to it after 30 s; the 60 s here leave room for that, and only then does systemd kill what is left.
TimeoutStopSec=60
KillMode=mixed

# Hardening. ansible has to be able to change anything on the host (packages, /etc, services, users, kernel settings,
# mounts), so this unit takes away nothing that a configuration run may need:
#   - no ProtectSystem, ProtectHome, PrivateTmp, ReadWritePaths or other file system sandboxing: ansible's writes would
#     fail or land in a private copy of the file system;
#   - no User=: root is required;
#   - no capability bounding, RestrictAddressFamilies or SystemCallFilter: tasks may need any of them.
# NoNewPrivileges is the systemd default (no); it is written out so that nobody switches it on: tasks run sudo and
# other setuid programs, and some roles install setuid files, all of which NoNewPrivileges=yes would break.
NoNewPrivileges=no
# The agent opens no listening port. Logs go to the journal (stderr); nothing writes log files.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=infra-agent
# ansible needs a HOME and a PATH that finds ansible-playbook, git and sops.
Environment=HOME=/root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
UNIT
    sed -i "s|^ExecStart=.*|ExecStart=$lib_dir/infra-agent run|" "$work/unit"
    if [ -e "$unit" ] && ! cmp -s "$work/unit" "$unit" && [ "$force" = 0 ]; then
        say "$unit exists and differs, kept (--force replaces it)"
    else
        if [ -e "$unit" ] && ! cmp -s "$work/unit" "$unit"; then backup "$unit"; fi
        install -m 644 "$work/unit" "$unit"
        if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload </dev/null || true; fi
    fi

    cat <<EOF

install: done. infra-agent $tag is installed for host "$host" and is NOT running.

Age public key of this host (register it in the infra repository):
  $age_pub
EOF
    if [ -n "$deploy_pub" ]; then
        cat <<EOF

Deploy key of this hub host (add it as a read-only deploy key to the KazuhaHub/infra repository on GitHub):
  $deploy_pub
EOF
    fi
    cat <<EOF

Next steps:
  1. In the infra repository add "$host" to the inventory with the age public key above (and to .sops.yaml), and merge it.
  2. Put the numeric GitHub IDs that the signing certificate must carry into $etc_dir/agent.env, from you and not
     from the hub (the hub is not trusted to say who signs):
       INFRA_AGENT_SIGSTORE_REPO_ID=<gh api repos/KazuhaHub/infra -q .id>
       INFRA_AGENT_SIGSTORE_OWNER_ID=<gh api users/KazuhaHub -q .id>
  3. Check:  infra-agent check-config  (the binary is $lib_dir/infra-agent), then
     systemctl enable --now infra-agent
EOF
}

main "$@"
