import re
import urllib.parse

NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-zA-Z0-9_][a-zA-Z0-9._~-]*$")


def valid_name(name):
    return isinstance(name, str) and 0 < len(name) <= 214 and bool(NAME_RE.match(name)) and ".." not in name


def split_name_version(s):
    s = s.strip().strip("'\"")
    i = s.rfind("@")
    if i <= 0:
        return s, ""
    return s[:i], s[i + 1:]


def split_first(s):
    s = s.strip().strip("'\"")
    i = s.find("@", 1)
    if i <= 0:
        return s, ""
    return s[:i], s[i + 1:]


def classify_spec(spec):
    s = str(spec).strip()
    if s.startswith("npm:"):
        real, rng = split_name_version(s[4:])
        return "alias", real, rng
    if s.startswith("workspace:"):
        return "workspace", None, s
    if s.startswith(("link:", "portal:")):
        return "link", None, s.split(":", 1)[1]
    if s.startswith("file:") or s.startswith(("./", "../", "/", "~/")):
        return "file", None, s[5:] if s.startswith("file:") else s
    if s.startswith("exec:"):
        return "exec", None, s
    if s.startswith(("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:")):
        return "git", None, s
    if s.startswith(("http://", "https://")):
        return "url", None, s
    if s.startswith("patch:"):
        inner = urllib.parse.unquote(s[6:].split("#")[0])
        real, rng = split_name_version(inner)
        return "registry", real, rng
    if re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s) and not s.startswith("@"):
        return "git", None, s
    return "registry", None, s
