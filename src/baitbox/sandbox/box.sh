#!/usr/bin/env bash
set -euo pipefail

readonly FAKE_USER=alex
readonly FAKE_HOME=/home/$FAKE_USER
readonly FAKE_HOST=alex-thinkpad
readonly TRACED_CALLS=clone,clone3,fork,vfork,execve,execveat,open,openat,openat2,creat,connect,sendto,sendmsg,sendmmsg,bind,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,symlink,symlinkat,link,linkat,chmod,fchmod,fchmodat,truncate,ptrace
readonly CACHE_PRUNE=(-path ./.npm -o -path ./.cache -o -path ./.local/share/pnpm -o -path ./.local/state -o -path ./.pnpm-store)
readonly SUDO=/usr/bin/sudo

die() {
  printf 'box.sh: %s\n' "$*" >&2
  exit 2
}

usage() {
  cat >&2 << 'EOF'
usage: box.sh <net|nonet> <project_dir> <box_dir> <seconds> <command>

Runs <command> with bash inside a bubblewrap sandbox and records every
process, file and network call with strace.

  net      share the host network (only for installs with scripts disabled)
  nonet    loopback only

The project folder is mounted read-write at /work. A fake home with bait
secrets is created in <box_dir>/fakehome and mounted at /home/alex.
Recordings are written to <box_dir>/logs and are never visible inside.
EOF
  exit 2
}

is_within() {
  [[ "$1/" == "$2/"* ]]
}

make_fake_home() {
  local h=$1
  mkdir -p "$h/.ssh" "$h/.aws" "$h/.gnupg" "$h/.local/bin" "$h/.config/gh" "$h/.config/solana" \
    "$h/.config/google-chrome/Default" "$h/.config/BraveSoftware/Brave-Browser/Default" \
    "$h/.config/discord/Local Storage/leveldb" "$h/.config/Code/User" "$h/.docker" "$h/.kube" \
    "$h/Documents" "$h/Downloads" "$h/Projects"
  chmod 700 "$h/.ssh" "$h/.gnupg"
  printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' \
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW' \
    'QyNTUxOQAAACBiYWl0Ym94LWRlY295LWtleS1ub3QtcmVhbC0wMDAwMDAwAAAAoGJhaXRi' \
    '-----END OPENSSH PRIVATE KEY-----' > "$h/.ssh/id_ed25519"
  chmod 600 "$h/.ssh/id_ed25519"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhaXRib3gtZGVjb3kta2V5 %s@%s\n' "$FAKE_USER" "$FAKE_HOST" > "$h/.ssh/id_ed25519.pub"
  printf 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n' > "$h/.ssh/known_hosts"
  printf '[default]\naws_access_key_id = AKIAZBAITBOXDECOY001\naws_secret_access_key = bAiTbOxDeCoYbAiTbOxDeCoYbAiTbOxDeCoY0001\nregion = us-east-1\n' > "$h/.aws/credentials"
  printf 'SQLite format 3\000baitbox-decoy-login-data\n' > "$h/.config/google-chrome/Default/Login Data"
  printf 'SQLite format 3\000baitbox-decoy-cookies\n' > "$h/.config/google-chrome/Default/Cookies"
  printf 'SQLite format 3\000baitbox-decoy-web-data\n' > "$h/.config/google-chrome/Default/Web Data"
  printf '{"os_crypt":{"encrypted_key":"RFBBUEkBAAAAYmFpdGJveC1kZWNveQ=="}}\n' > "$h/.config/google-chrome/Local State"
  printf 'SQLite format 3\000baitbox-decoy-brave-login\n' > "$h/.config/BraveSoftware/Brave-Browser/Default/Login Data"
  printf 'baitbox-decoy-discord-token\n' > "$h/.config/discord/Local Storage/leveldb/000003.log"
  printf '[12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34]\n' > "$h/.config/solana/id.json"
  printf 'github.com:\n    user: %s\n    oauth_token: gho_BaItBoXdEcOyToKeN0000000000000000000\n    git_protocol: ssh\n' "$FAKE_USER" > "$h/.config/gh/hosts.yml"
  printf '{"auths":{"https://index.docker.io/v1/":{"auth":"YWxleDpiYWl0Ym94LWRlY295"}}}\n' > "$h/.docker/config.json"
  printf 'apiVersion: v1\nkind: Config\nusers:\n- name: alex\n  user:\n    token: baitbox-decoy-kube-token\n' > "$h/.kube/config"
  printf '//registry.npmjs.org/:_authToken=npm_BaItBoXdEcOyToKeN000000000000000000\n' > "$h/.npmrc"
  printf 'https://%s:ghp_BaItBoXdEcOyToKeN000000000000000000@github.com\n' "$FAKE_USER" > "$h/.git-credentials"
  printf '[user]\n\tname = Alex\n\temail = alex@example.com\n[credential]\n\thelper = store\n' > "$h/.gitconfig"
  printf '%s\n' 'export OPENAI_API_KEY=sk-baitbox-decoy-0000000000000000' "export PATH=\"\$HOME/.local/bin:\$PATH\"" > "$h/.bashrc"
  printf 'export GEMINI_API_KEY=baitbox-decoy-0000000000000000\n' > "$h/.zshrc"
  printf '%s\n' "if [ -f \"\$HOME/.bashrc\" ]; then . \"\$HOME/.bashrc\"; fi" > "$h/.profile"
  printf 'DATABASE_URL=postgres://alex:baitbox-decoy@localhost:5432/app\nSTRIPE_SECRET_KEY=sk_live_baitboxdecoy000000\n' > "$h/Projects/.env"
  printf 'baitbox-decoy-gnupg\n' > "$h/.gnupg/pubring.kbx"
  printf '{}\n' > "$h/.config/Code/User/settings.json"
}

manifest() {
  (
    cd "$1" || exit 0
    find . \( "${CACHE_PRUNE[@]}" \) -prune -o -type f -print0 2> /dev/null | LC_ALL=C sort -z | xargs -0 -r sha256sum 2> /dev/null || true
    find . \( "${CACHE_PRUNE[@]}" \) -prune -o -type l -printf 'symlink  ./%P -> %l\n' 2> /dev/null | LC_ALL=C sort || true
  )
}

[ $# -eq 5 ] || usage
mode=$1
src_in=$2
box_in=$3
secs=$4
cmd=$5

case $mode in
  net | nonet) ;;
  *) usage ;;
esac
[[ $secs =~ ^[0-9]+$ ]] || die "seconds must be a whole number"
((10#$secs >= 1 && 10#$secs <= 86400)) || die "seconds must be between 1 and 86400"
secs=$((10#$secs))
[ -n "$cmd" ] || die "command is empty"

for tool in bwrap strace timeout sha256sum realpath find node; do
  command -v "$tool" > /dev/null 2>&1 || die "missing required tool: $tool"
done

[ -d "$src_in" ] || die "project folder not found: $src_in"
src=$(realpath -e -- "$src_in")
box=$(realpath -m -- "$box_in")
real_home=$(realpath -e -- "${HOME:-/nonexistent}" 2> /dev/null || printf '/nonexistent')

[ "$src" != / ] || die "refusing to mount / as the project"
if is_within "$real_home" "$src"; then
  die "refusing to mount a folder that contains your home folder: $src"
fi
for sys in /bin /boot /dev /etc /home /lib /lib64 /media /mnt /opt /proc /root /run /sbin /srv /sys /tmp /usr /var /var/tmp /dev/shm; do
  [ "$src" != "$sys" ] || die "refusing to mount a system folder as the project: $src"
done
if is_within "$box" "$src" || is_within "$src" "$box"; then
  die "box folder and project folder must not contain each other"
fi
socket=$(find "$src" -type s -print -quit 2> /dev/null || true)
[ -z "$socket" ] || die "project folder contains a socket, which could reach host services: $socket"

node_bin=${BAITBOX_NODE:-$(cd / && node -p 'process.execPath')}
[ -x "$node_bin" ] || die "node binary not found: $node_bin"
node_dir=$(dirname -- "$(dirname -- "$(realpath -e -- "$node_bin")")")
if is_within "$node_dir" "$src" || is_within "$src" "$node_dir"; then
  die "node install folder and project folder must not overlap"
fi
if is_within "$real_home" "$node_dir" || [ "$node_dir" = / ]; then
  die "node install folder is too broad to mount: $node_dir"
fi

fh="$box/fakehome"
logs="$box/logs"
mkdir -p "$logs"
if [ ! -d "$fh" ]; then
  mkdir -p "$fh"
  make_fake_home "$fh"
  (cd "$fh" && find . -type f -printf '%P\n' | LC_ALL=C sort) > "$box/decoys.txt"
  printf '{"fake_home": "%s", "fake_user": "%s", "fake_host": "%s"}\n' "$FAKE_HOME" "$FAKE_USER" "$FAKE_HOST" > "$box/meta.json"
fi

uid=$(id -u)
path="$node_dir/bin:/usr/local/bin:/usr/bin:/bin"
pnpm_home=${PNPM_HOME:-}
if [ -z "$pnpm_home" ] && [ -n "${HOME:-}" ]; then
  pnpm_home="$HOME/.local/share/pnpm"
fi

args=(
  --ro-bind /usr /usr
  --symlink usr/bin /bin
  --symlink usr/lib /lib
  --symlink usr/lib64 /lib64
  --symlink usr/sbin /sbin
  --ro-bind /etc /etc
  --proc /proc
  --dev /dev
  --tmpfs /dev/shm
  --tmpfs /tmp
  --tmpfs /run
  --dir "/run/user/$uid"
  --dir /home
  --bind "$fh" "$FAKE_HOME"
  --bind "$src" /work
  --unshare-all
  --die-with-parent
  --new-session
  --clearenv
  --hostname "$FAKE_HOST"
  --setenv HOME "$FAKE_HOME"
  --setenv USER "$FAKE_USER"
  --setenv LOGNAME "$FAKE_USER"
  --setenv SHELL /bin/bash
  --setenv TERM xterm-256color
  --setenv LANG en_US.UTF-8
  --setenv DISPLAY :0
  --setenv XDG_SESSION_TYPE x11
  --setenv XDG_RUNTIME_DIR "/run/user/$uid"
  --setenv DBUS_SESSION_BUS_ADDRESS "unix:path=/run/user/$uid/bus"
  --chdir /work
)
if ! is_within "$node_dir" /usr; then
  args+=(--ro-bind "$node_dir" "$node_dir")
fi
if [ -n "$pnpm_home" ] && [ -x "$pnpm_home/pnpm" ] && ! is_within "$pnpm_home" "$src" && ! is_within "$real_home" "$pnpm_home"; then
  args+=(--ro-bind "$pnpm_home" "$pnpm_home")
  path="$pnpm_home:$path"
fi
if [ "$mode" = net ]; then
  args+=(--share-net --setenv NPM_CONFIG_USERCONFIG /dev/null)
  resolv=$(realpath -e /etc/resolv.conf 2> /dev/null || true)
  case $resolv in
    /run/*) args+=(--ro-bind-try "$(dirname -- "$resolv")" "$(dirname -- "$resolv")") ;;
  esac
fi
args+=(--setenv PATH "$path")

scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2> /dev/null || printf 0)
lowered=0
restore_scope() {
  [ "$lowered" = 1 ] || return 0
  lowered=0
  if ! "$SUDO" -n sysctl -q -w "kernel.yama.ptrace_scope=$scope" 2> /dev/null &&
    ! "$SUDO" -p "BaitBox: password to set ptrace_scope back to $scope: " sysctl -q -w "kernel.yama.ptrace_scope=$scope"; then
    printf 'box.sh: could not set ptrace_scope back to %s. Run: sudo sysctl -w kernel.yama.ptrace_scope=%s\n' "$scope" "$scope" >&2
  fi
}
case $scope in
  0 | 1) ;;
  2)
    [ -x "$SUDO" ] || die "kernel.yama.ptrace_scope is 2 and $SUDO is missing, so strace cannot record the sandbox"
    "$SUDO" -p "BaitBox: password to set ptrace_scope to 1 while this run is recorded: " sysctl -q -w kernel.yama.ptrace_scope=1 ||
      die "kernel.yama.ptrace_scope is 2 and sudo could not set it to 1. Run baitbox in a terminal, so sudo can ask for your password"
    lowered=1
    trap restore_scope EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    ;;
  *) die "kernel.yama.ptrace_scope is $scope, which turns ptrace off, so strace cannot record the sandbox" ;;
esac

strace_opts=(-f -qq -y -s 512 -e signal=none -e "trace=$TRACED_CALLS")
if strace --kill-on-exit -o /dev/null true > /dev/null 2>&1; then
  strace_opts=(--kill-on-exit "${strace_opts[@]}")
fi
if strace --pidns-translation -o /dev/null true > /dev/null 2>&1; then
  strace_opts=(--pidns-translation "${strace_opts[@]}")
fi

tag="$(date +%Y%m%d-%H%M%S)-$mode-$$"
printf '%s\n' "$cmd" > "$logs/$tag.cmd"
printf '%s\n' "$secs" > "$logs/$tag.limit"
manifest "$fh" > "$logs/$tag.before"
start=$(date +%s)

set +e
timeout -k 10 "$((secs + 60))" strace "${strace_opts[@]}" -o "$logs/$tag.trace" \
  bwrap "${args[@]}" timeout -k 5 "$secs" bash --noprofile --norc -c "$cmd" < /dev/null 2>&1 | cat > "$logs/$tag.out"
status=${PIPESTATUS[0]}
set -e

printf '%s\n' "$(($(date +%s) - start))" > "$logs/$tag.seconds"
printf '%s\n' "$status" > "$logs/$tag.status"
manifest "$fh" > "$logs/$tag.after"
diff "$logs/$tag.before" "$logs/$tag.after" > "$logs/$tag.homediff" || true

if [ ! -s "$logs/$tag.trace" ]; then
  printf 'box.sh: strace recorded nothing. Output:\n' >&2
  head -20 "$logs/$tag.out" >&2
  exit 3
fi
if ! grep -qE "execve\(\"[^\"]*/timeout\", \[\"timeout\", \"-k\", \"5\", \"$secs\"" "$logs/$tag.trace"; then
  printf 'box.sh: the sandbox failed to start. Output:\n' >&2
  head -20 "$logs/$tag.out" >&2
  printf 'box.sh: run "baitbox doctor" for help.\n' >&2
  exit 3
fi

printf 'run: %s\n' "$tag"
if [ "$status" = 124 ]; then
  printf 'exit: %s (stopped by the time limit)\n' "$status"
else
  printf 'exit: %s\n' "$status"
fi
printf 'output: %s\n' "$logs/$tag.out"
printf 'trace: %s\n' "$logs/$tag.trace"
printf 'fake home changes: %s\n' "$(grep -c '^[<>]' "$logs/$tag.homediff" || true)"
