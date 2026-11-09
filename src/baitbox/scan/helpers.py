import ipaddress
import re


def magic(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None
    if head == b"\x7fELF":
        return "Linux program (ELF)"
    if head[:2] == b"MZ":
        return "Windows program (PE)"
    if head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        return "Mac program (Mach-O)"
    if head == b"\x00asm":
        return "WebAssembly module"
    return None


def snippet(line, m):
    s = max(0, m.start() - 60)
    e = min(len(line), m.end() + 60)
    t = line[s:e].replace("\t", " ")
    t = "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in t)
    return ("..." if s else "") + t + ("..." if e < len(line) else "")


def code_like(line):
    if re.search(r"_0x[0-9a-f]{4}|\beval\s*\(|new Function|\\x[0-9a-f]{2}\\x|atob\(|fromCharCode|require\(|import\(", line):
        return True
    marks = line.count(";") + line.count("{") + line.count("=>") + line.count("function")
    return marks * 120 > len(line)


def public_ip(token):
    ip = token.split(":")[0]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_private or a.is_unspecified or a.is_multicast or a.is_reserved or a.is_link_local:
        return False
    parts = [int(x) for x in ip.split(".")]
    return not (parts[0] == 0 or all(p < 10 for p in parts) or parts == [255, 255, 255, 255])


def mask_tokens(s):
    return re.sub(r"(_authToken\s*=\s*|_auth\s*=\s*|_password\s*=\s*|npmAuthToken:\s*|//[^\s:]+:_authToken=)(\S{4})\S+", r"\1\2****", s)


def package_of(spec):
    if spec.startswith((".", "/", "node:", "#", "~", "@/", "virtual:", "data:", "http:", "https:", "bun:")):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return spec.split("/")[0] or None
