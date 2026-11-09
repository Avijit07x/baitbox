import ipaddress

DEFAULT_FAKE_HOME = "/home/alex"

MAX_ITEMS = 60

HIGH_BINS = {
    "sudo", "su", "pkexec", "doas", "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp",
    "sftp", "systemctl", "crontab", "at", "usermod", "useradd", "passwd", "chpasswd", "xdotool", "xclip",
    "xsel", "wl-copy", "wl-paste", "secret-tool", "powershell", "pwsh", "osascript", "security", "insmod",
    "modprobe", "mount", "nsenter", "unshare", "gsettings", "dconf",
}
MEDIUM_BINS = {
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "base64", "openssl", "gpg", "xxd", "dd",
    "zip", "7z", "7za", "rar", "tar", "scrot", "import", "gnome-screenshot", "ps", "pgrep", "pkill", "kill",
    "killall", "ip", "ifconfig", "netstat", "ss", "arp", "lsblk", "whoami", "hostnamectl", "lscpu", "lspci",
    "dmidecode", "chattr", "chmod", "chown", "ln", "screen", "tmux", "xdg-open", "find", "nohup", "setsid",
}
QUIET_BINS = {"timeout", "bwrap"}
EARLY_PHASES = ("config load", "install scripts", "install")
BAD_DNS = (
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "no-ip.org", "no-ip.biz", "ddns.net",
    "hopto.org", "serveo.net", "localtunnel.me", "loca.lt", "pastebin.com", "paste.ee", "transfer.sh", "webhook.site",
    "requestbin.net", "pipedream.net", "api.telegram.org", "interact.sh", "oast.fun", "oast.live", "oast.me",
    "burpcollaborator.net", "canarytokens.com", "ipinfo.io", "ip-api.com", "ifconfig.me", "icanhazip.com",
    "api.ipify.org", "checkip.amazonaws.com", "ipwho.is", "geolocation-db.com",
)
PKG_TOOLS = {"npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "corepack", "bun", "bunx"}
PKG_TOOL_MARKERS = ("npm-cli.js", "npx-cli.js", "pnpm.cjs", "pnpm.mjs", "yarn.js", "corepack")
REGISTRY_NETS = [ipaddress.ip_network(n) for n in ("104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32")]
NET_DNS_OK = (
    "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com", "codeload.github.com", "github.com",
    "api.github.com", "objects.githubusercontent.com", "nodejs.org", "registry.npmmirror.com",
)
NONET_DNS_INFO = (
    "registry.npmjs.org", "registry.yarnpkg.com", "telemetry.nextjs.org", "fonts.googleapis.com",
    "fonts.gstatic.com", "localhost",
)
SANDBOX_PROBES = (
    "/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "/proc/1/sched", "/proc/scsi/scsi", "/sys/hypervisor",
    "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor",
)
WRITE_OK_SYSTEM = (
    "/work", "/tmp", "/dev/shm", "/dev/null", "/dev/tty", "/dev/pts", "/dev/zero", "/dev/urandom", "/dev/random",
    "/dev/full", "/proc/self", "/proc/thread-self", "/run/user",
)
HOME_CACHES = (
    ".npm", ".cache", ".local/share/pnpm", ".local/state", ".pnpm-store", ".yarn", ".yarnrc", ".node_repl_history",
    ".node-gyp", ".config/yarn", ".config/configstore", ".config/nextjs-nodejs", ".config/pnpm", ".bun",
    ".config/turborepo", ".config/vercel", ".config/astro", ".config/ngrok", ".lesshst",
)
HOME_EXEC_OK = (".cache/ms-playwright", ".cache/puppeteer", ".cache/node-gyp", ".npm/_npx", ".local/share/pnpm", ".bun")
PERSIST_HOME = (
    ".config/systemd", ".config/autostart", ".local/share/applications", ".config/environment.d", ".bashrc",
    ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zlogin", ".zshenv",
    ".xprofile", ".xinitrc", ".xsessionrc", ".config/fish", ".local/bin", ".ssh/authorized_keys", ".ssh/rc",
    ".ssh/config", ".config/Code/User", ".vscode/extensions", ".gitconfig", ".config/git", ".npmrc", ".pam_environment",
    ".config/plasma-workspace", ".config/lxsession", ".config/openbox", ".config/i3", ".config/hypr",
)
PERSIST_SYSTEM = ("/etc", "/usr", "/var/spool/cron", "/var/lib", "/lib", "/bin", "/sbin", "/boot", "/root")
SENSITIVE_HOME = (
    ".ssh", ".aws", ".gnupg", ".config/google-chrome", ".config/BraveSoftware", ".config/chromium",
    ".config/microsoft-edge", ".config/opera", ".config/vivaldi", ".config/discord", ".config/solana", ".config/gh",
    ".mozilla", ".local/share/keyrings", ".docker/config.json", ".kube", ".git-credentials", ".netrc",
    ".config/Exodus", ".electrum", ".ethereum", ".bitcoin", ".config/Signal", ".config/Slack", ".config/telegram-desktop",
    ".local/share/TelegramDesktop", "Projects", "Documents", "Downloads", ".config/filezilla", ".config/rclone",
    ".pgpass", ".my.cnf", ".config/op", ".password-store",
)
SENSITIVE_SYSTEM = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/dev/input", "/dev/uinput", "/dev/mem", "/dev/kmem")
