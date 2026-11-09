from baitbox.deps.registry import POPULAR_DOWNLOADS, flag

POPULAR = (
    "react", "react-dom", "next", "vue", "nuxt", "vite", "tailwindcss", "postcss", "autoprefixer", "axios", "lodash",
    "express", "typescript", "eslint", "prettier", "webpack", "moment", "dayjs", "chalk", "commander", "dotenv", "zod",
    "jsonwebtoken", "bcrypt", "bcryptjs", "mongoose", "prisma", "nodemon", "jest", "vitest", "framer-motion", "motion",
    "clsx", "uuid", "socket.io", "cors", "body-parser", "sharp", "styled-components", "redux", "react-router-dom",
    "react-router", "tailwind-merge", "lucide-react", "date-fns", "classnames", "react-icons", "swr", "zustand",
    "recharts", "three", "gsap", "nanoid", "cookie-parser", "multer", "nodemailer", "stripe", "openai", "firebase",
    "sass", "less", "esbuild", "rollup", "daisyui", "react-hook-form", "yup", "formik", "i18next", "graphql", "pg",
    "mysql2", "redis", "ioredis", "debug", "colors", "request", "node-fetch", "cross-env", "concurrently", "rimraf",
    "glob", "minimist", "yargs", "inquirer", "ws", "helmet", "morgan", "passport", "sequelize", "typeorm", "knex",
    "puppeteer", "playwright", "cheerio", "marked", "highlight.js", "chart.js", "antd", "electron", "ethers", "web3",
)


def lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def flag_lookalikes(results):
    weekly = {r["name"]: r["weekly"] for r in results}
    lookalikes = []
    for r in results:
        n = r["name"]
        if (weekly.get(n) or 0) >= POPULAR_DOWNLOADS:
            continue
        base = n.split("/")[-1]
        for p in POPULAR:
            if n == p or base == p or len(p) <= 4 or n.startswith(("@types/", f"@{p}/")):
                continue
            if lev(base, p) <= (1 if len(p) <= 6 else 2) or base in (p + "js", p + "-js", p + ".js", "node-" + p, p + "-node") and n not in POPULAR:
                flag(r, "LOOKALIKE", "medium", f"name looks like the popular package {p}")
                lookalikes.append({"name": n, "looks_like": p})
                break
    return lookalikes
