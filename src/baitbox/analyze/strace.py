import ipaddress
import re

LINE_RE = re.compile(r"^(\d+)\s+(.*)$")
NAME_RE = re.compile(r"^(\w+)\(")
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
STR = r'"((?:[^"\\]|\\.)*)"'
STRING_RE = re.compile(STR + r"(\.\.\.)?")
DIRFD_STR_RE = re.compile(r"(?:(?:AT_FDCWD|-?\d+)<((?:[^>\\]|\\.)*)>,\s*)?" + STR)
RESULT_RE = re.compile(r"\)\s+=\s+(-?\d+|\?|0x[0-9a-f]+)(?:<((?:[^>\\]|\\.)*)>)?(?:\s+(E[A-Z0-9]+))?")
EXEC_RE = re.compile(r"^execve(?:at)?\((?:-?\d+(?:<[^>]*>)?, )?" + STR + r", \[(.*?)\](?:\.\.\.)?, (?:0x|\[|NULL)")
PIDNS_RE = re.compile(r"/\* (\d+) in strace's PID NS \*/")
CLONE_CALLS = ("clone", "clone3", "fork", "vfork")
FD_DECOR_RE = re.compile(r"^\s*-?\d+<((?:[^>\\]|\\.)*)>")
IN4_RE = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)')
IN6_RE = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
UNIX_RE = re.compile(r'sa_family=AF_UNIX, sun_path=(@?)' + STR)
MODE_RE = re.compile(r",\s*0([0-7]{3,4})\b")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
SIMPLE_ESC = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, '"': 34, "\\": 92, "'": 39}


def c_unescape(s):
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        i += 1
        if i >= n:
            out.append(92)
            break
        c = s[i]
        if c in SIMPLE_ESC:
            out.append(SIMPLE_ESC[c])
            i += 1
        elif c == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 1:i + 3]):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        elif c in "01234567":
            j = i
            while j < n and j - i < 3 and s[j] in "01234567":
                j += 1
            out.append(int(s[i:j], 8) & 0xFF)
            i = j
        else:
            out += ("\\" + c).encode("utf-8", "surrogateescape")
            i += 1
    return bytes(out)


def text(s):
    return c_unescape(s).decode("utf-8", "replace")


def dns_query_name(b):
    if len(b) < 17 or b[2] & 0x80 or int.from_bytes(b[4:6], "big") != 1 or b[6:8] != b"\0\0":
        return None
    i = 12
    labels = []
    while i < len(b):
        ln = b[i]
        if ln == 0:
            i += 1
            break
        if ln > 63 or i + 1 + ln > len(b):
            return None
        label = b[i + 1:i + 1 + ln]
        if not re.fullmatch(rb"[A-Za-z0-9_-]+", label):
            return None
        labels.append(label.decode("ascii"))
        i += 1 + ln
    else:
        return None
    if not labels or len(b) < i + 4:
        return None
    return ".".join(labels).lower()


def norm_ip(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return a.ipv4_mapped
    return a
