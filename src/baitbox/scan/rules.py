import re

KNOWN_HASHES = {
    "5c0d263e6decfa6d4db3da32eec9ec3f5c83b717d55390f49110cb8d04f55fd6": "tw-motion-css backdoor (runtime.js)",
    "cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743": "@codentra/postcss-kinetix loader (config.js)",
}
KNOWN_STRINGS = (
    "DEERGS42", "216.126.231.70", "153.75.88.215", "tw-motion-css", "postcss-kinetix", "@codentra/", "carybernal",
    "gvfs-network-boot", "gvfs-network-activate",
)
CONFIG_RE = re.compile(
    r"^(tailwind|postcss|vite|vitest|next|nuxt|astro|svelte|webpack|rollup|babel|jest|eslint|prettier|tsup|esbuild"
    r"|remix|gatsby|metro|playwright|cypress|stylelint|commitlint|lint-staged|electron-builder|electron\.vite|quasar"
    r"|vue|angular|unocss|uno|panda|drizzle|knip|turbo|wrangler|react-router|rspack|rsbuild|farm|storybook|histoire"
    r"|vuepress|docusaurus|tsdown|rolldown|unbuild|webpack\.dev|webpack\.prod|craco|karma|mocha|ava|c8|nyc"
    r"|graphql|codegen|orval|kubb|sanity|payload|keystatic|contentlayer|velite|i18next-parser|svgo|size-limit)"
    r"\.config\.(js|cjs|mjs|ts|cts|mts|json|jsx|tsx)$"
)
RC_JS_RE = re.compile(r"^\.(babelrc|eslintrc|prettierrc|stylelintrc|lintstagedrc|mocharc|postcssrc|swcrc|ncurc|releaserc)\.(js|cjs|mjs|ts)$")
OTHER_AUTORUN = {
    "gulpfile.js": "runs when gulp starts", "Gruntfile.js": "runs when grunt starts", "Makefile": "runs on make",
    "Dockerfile": "runs on docker build", "docker-compose.yml": "runs on docker compose",
    "docker-compose.yaml": "runs on docker compose", "compose.yml": "runs on docker compose",
    "compose.yaml": "runs on docker compose", "Procfile": "runs on deploy", "justfile": "runs on just",
    "build.rs": "runs on cargo build", "nodemon.json": "configures nodemon", "deno.json": "configures deno tasks",
    "tsconfig.json": "editors load TypeScript plugins listed here", "jsconfig.json": "editors load plugins listed here",
}
PY_AUTORUN = {"setup.py": "medium", "conftest.py": "medium", "sitecustomize.py": "high", "usercustomize.py": "high", "noxfile.py": "info", "tasks.py": "info"}
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepack", "postpack", "dependencies")
PKG_TOOL_KEYS = ("eslintConfig", "prettier", "babel", "jest", "stylelint", "postcss", "lint-staged", "husky", "simple-git-hooks", "ava", "mocha", "nyc", "c8", "xo")
VSCODE_RISKY_KEYS = re.compile(
    r'"(terminal\.integrated\.(?:shell|profiles|env|automationProfile|defaultProfile)[^"]*|typescript\.tsdk|'
    r'js/ts\.tsdk|eslint\.runtime|eslint\.nodePath|eslint\.execArgv|prettier\.prettierPath|npm\.packageManager|'
    r'npm\.scriptRunner|python\.defaultInterpreterPath|python\.pythonPath|git\.path|[\w.]*executablePath|'
    r'[\w.]*\.serverPath|[\w.]*\.binPath|[\w.]*\.command|task\.allowAutomaticTasks|security\.workspace\.trust[^"]*)"\s*:'
)

STRONG = (
    ("known-malware", re.compile("|".join(re.escape(s) for s in KNOWN_STRINGS)), "high", "high"),
    ("obfuscated-code", re.compile(r"\b_0x[0-9a-f]{4,6}\b"), "high", "medium"),
    ("exfil-endpoint", re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|pastebin\.com/raw|hastebin|transfer\.sh|webhook\.site|requestbin|pipedream\.net|ngrok-free\.app|\.ngrok\.io|interact\.sh|\boast\.(?:fun|live|me|site|online|pro)|burpcollaborator|canarytokens|ipinfo\.io|ip-api\.com|ifconfig\.me|icanhazip|api\.ipify\.org"), "high", "medium"),
    ("wallet-extension-id", re.compile(r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|fhbohimaelbohpjbbldcngcnapndodjp|aholpfdialjgjfhomihkjbmgjidlcdno|ejbalbakoplchlghecdalmeeeajnimhm|egjidjbpglichdcondbcbdnbeeppgdph|dmkamcknogkgcdfhhbddcghachkejeap|aeachknmefphepccionboohckonoeemg"), "high", "high"),
    ("browser-secrets", re.compile(r"Login Data|Local State|Local Extension Settings|Web Data|/Cookies\b|\\\\Cookies\b|BraveSoftware|google-chrome|Opera Software|\.mozilla/firefox|key4\.db|logins\.json|Chrome/User Data"), "high", "medium"),
    ("app-secrets", re.compile(r"\.ssh/id_|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.config/solana|Exodus|Electrum|\.gnupg|\.docker/config\.json|\.kube/config|\.config/gh/hosts|\.git-credentials|Keychains|login\.keychain|\.netrc\b"), "high", "info"),
    ("download-and-run", re.compile(r"curl[^\n]{0,120}\|\s*(?:ba|z)?sh|wget[^\n]{0,120}\|\s*(?:ba|z)?sh|Invoke-WebRequest|Invoke-Expression|\bIEX\s*\(|powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|nop|w|windowstyle|ExecutionPolicy)\b|DownloadString|certutil(?:\.exe)?\s+-urlcache|\bmshta\b|bitsadmin|/dev/tcp/"), "high", "medium"),
    ("starts-at-login", re.compile(r"systemctl\s+--user|\.config/autostart|\.config/systemd/user|crontab\s+-|\bLaunchAgents\b|\bLaunchDaemons\b|CurrentVersion\\\\Run|\bschtasks\b|Start Menu\\\\Programs\\\\Startup|reg(?:\.exe)?\s+add\s+HKCU"), "high", "medium"),
    ("bidi-control", re.compile("[‪-‮⁦-⁩]"), "high", "high"),
    ("invisible-code", re.compile("(?:[​-‏⁠-⁤︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]){8,}"), "high", "high"),
    ("hidden-after-spaces", re.compile(r"\S[ \t]{150,}\S"), "medium", "info"),
    ("dumps-env", re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys)\(\s*process\.env\s*\)|os\.environ\.copy\(\)|dict\(os\.environ\)"), "medium", "info"),
    ("public-ip", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\w.])"), "medium", "info"),
)
SOURCE_ONLY = (
    ("eval", re.compile(r"(?<![\w.$])eval\s*\("), "medium"),
    ("new-function", re.compile(r"new\s+Function\s*\("), "medium"),
    ("shell-commands", re.compile(r"child_process|\bexecSync\b|\bspawnSync\b|\bexecFile(?:Sync)?\b|\bspawn\s*\(|\bsubprocess\.|\bos\.system\("), "medium"),
    ("decodes-base64", re.compile(r"\batob\s*\(|Buffer\.from\([^)]{0,200}['\"](?:base64|hex)['\"]|b64decode|String\.fromCharCode\s*\(|\.charCodeAt\([^)]*\)\s*\^"), "info"),
    ("base64-blob", re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), "medium"),
    ("hex-blob", re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:0x[0-9a-fA-F]{2},\s*){60,}"), "medium"),
    ("home-folder", re.compile(r"os\.homedir\(\)|\bhomedir\(\)|process\.env\.(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA)\b|expanduser\("), "info"),
    ("network-call", re.compile(r"\bfetch\s*\(|\baxios\b|https?\.(?:get|request)\s*\(|new\s+WebSocket|net\.(?:connect|createConnection|Socket)|dgram\.|XMLHttpRequest|require\(['\"](?:node:)?(?:http|https|net|dgram|tls)['\"]\)|\brequests\.(?:get|post)\(|urllib\.request|socket\.socket\("), "info"),
    ("dynamic-load", re.compile(r"require\(\s*(?![\'\"`)\s])[^)]{1,80}\)|import\(\s*(?![\'\"`)\s])[^)]{1,80}\)|__import__\(|importlib\.import_module\("), "info"),
    ("self-hiding", re.compile(r"unlinkSync\(\s*__filename|fs\.rm(?:Sync)?\(\s*__dirname|detached\s*:\s*true|\.unref\(\)\s*;?\s*$|windowsHide\s*:\s*true"), "medium"),
)
IMPORT_RE = re.compile(r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"\s]+)['"]""", re.M)
TEXT_EXT = {
    ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx", ".json", ".jsonc", ".json5", ".sh", ".bash", ".zsh",
    ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".py", ".pth", ".rb", ".php", ".pl", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass", ".less", ".env", ".lua", ".go", ".rs",
    ".java", ".kt", ".swift", ".c", ".h", ".cpp", ".cs", ".sql", ".graphql", ".gql", ".xml", ".svg", ".md", ".mdx", ".txt",
}
CODE_EXT = TEXT_EXT - {".md", ".mdx", ".txt", ".svg", ".xml", ".css", ".scss", ".sass", ".less"}
WIN_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msp", ".reg", ".com", ".pif", ".cpl", ".jar"}
PREBUILT_OK = re.compile(
    r"node_modules/(?:\.pnpm/[^/]+/node_modules/)?(?:@esbuild|esbuild|@next/swc|@swc|lightningcss|@rollup|@img|sharp|turbo|"
    r"@biomejs|@oxc|oxc|@tailwindcss/oxide|@parcel/watcher|fsevents|@unrs|unrs|@napi-rs|@rspack|@rolldown|rolldown|"
    r"@ast-grep|bufferutil|utf-8-validate|canvas|better-sqlite3|bcrypt|argon2|@prisma|prisma|@node-rs|node-gyp|"
    r"playwright-core|puppeteer|@playwright|electron|7zip-bin|@ngrok|cypress|workerd|@cloudflare|@oven|bun|lefthook|"
    r"@lefthook|@sentry/cli|@sentry|@vercel/nft|@ffmpeg-installer|ffmpeg-static|@esbuild-kit|@dprint|dprint|"
    r"@lancedb|onnxruntime-node|@tensorflow|re2|@mapbox/node-pre-gyp|deasync|nodejieba|@resvg|@sveltejs|@vscode|"
    r"@ampproject|@lmdb|lmdb|msgpackr-extract|@msgpackr-extract|cpu-features|ssh2|@serialport|serialport|usb|"
    r"keytar|node-pty|@homebridge|sqlite3|@libsql|libsql|@duckdb|duckdb|@tauri-apps|@astrojs/compiler|svelte|"
    r"@typescript/native-preview|typescript-go|@rolldown/binding|@oxlint|oxlint|nodemon|@esbuild/[\w-]+|@swc/core-[\w-]+)"
)
PACKED_DIRS = ("/dist/", "/build/", "/umd/", "/cjs/", "/esm/", "/lib/", "/bundle/", "/min/", "/vendor/", "/public/", "/static/", "/out/", "/.next/")
MAX_FILE = 15_000_000
CAP_PER_FILE = 3
CAP_PROJECT = 80
CAP_NM = 40
