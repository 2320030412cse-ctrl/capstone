"""
fp_reader.py - Parse the p0f.fp fingerprint database.

Mirrors the logic in readfp.c:  reads [mtu], [tcp:request],
[tcp:response], [http:request], [http:response] sections and
populates the global signature stores used by the fingerprinting
modules.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ── module-type constants (mirror CF_MOD_* in readfp.h) ──────────────────────
CF_MOD_TCP  = 0
CF_MOD_HTTP = 1
CF_MOD_MTU  = 2

# ── window-size type constants (mirror WIN_TYPE_* in fp_tcp.h) ───────────────
WIN_TYPE_NORMAL = 0
WIN_TYPE_ANY    = 1
WIN_TYPE_MOD    = 2
WIN_TYPE_MSS    = 3
WIN_TYPE_MTU    = 4

# ── quirk bit flags (mirror QUIRK_* in process.h) ────────────────────────────
QUIRK_ECN          = 0x00000001
QUIRK_DF           = 0x00000002
QUIRK_NZ_ID        = 0x00000004
QUIRK_ZERO_ID      = 0x00000008
QUIRK_NZ_MBZ       = 0x00000010
QUIRK_FLOW         = 0x00000020
QUIRK_ZERO_SEQ     = 0x00001000
QUIRK_NZ_ACK       = 0x00002000
QUIRK_ZERO_ACK     = 0x00004000
QUIRK_NZ_URG       = 0x00008000
QUIRK_URG          = 0x00010000
QUIRK_PUSH         = 0x00020000
QUIRK_OPT_ZERO_TS1 = 0x01000000
QUIRK_OPT_NZ_TS2   = 0x02000000
QUIRK_OPT_EOL_NZ   = 0x04000000
QUIRK_OPT_EXWS     = 0x08000000
QUIRK_OPT_BAD      = 0x10000000

# ── TCP option codes (mirror TCPOPT_* in tcp.h) ───────────────────────────────
TCPOPT_EOL    = 0
TCPOPT_NOP    = 1
TCPOPT_MAXSEG = 2
TCPOPT_WSCALE = 3
TCPOPT_SACKOK = 4
TCPOPT_SACK   = 5
TCPOPT_TSTAMP = 8

# string → option code
OPT_NAME_MAP = {
    "eol":  TCPOPT_EOL,
    "nop":  TCPOPT_NOP,
    "mss":  TCPOPT_MAXSEG,
    "ws":   TCPOPT_WSCALE,
    "sok":  TCPOPT_SACKOK,
    "sack": TCPOPT_SACK,
    "ts":   TCPOPT_TSTAMP,
}

# ── data classes ─────────────────────────────────────────────────────────────

@dataclass
class TcpSig:
    """A single TCP signature as parsed from p0f.fp."""
    ip_ver: int        # -1=any, 4, 6
    ittl: int
    bad_ttl: bool
    ip_opt_len: int
    mss: int           # -1 = wildcard
    win: int
    win_type: int      # WIN_TYPE_*
    win_param: int     # multiplier or modulo value
    wscale: int        # -1 = wildcard
    opt_layout: List[int]
    opt_eol_pad: int
    quirks: int
    pay_class: int     # -1=any, 0=zero, 1=nonzero
    # computed after parsing
    opt_hash: int = 0


@dataclass
class TcpSigRecord:
    generic: bool
    class_id: int      # -1 = application
    name_id: int
    flavor: str
    label_id: int
    sys: List[int]
    line_no: int
    bad_ttl: bool
    sig: TcpSig


@dataclass
class HttpHdr:
    name: str
    value: Optional[str]   # None = no value match
    optional: bool


@dataclass
class HttpSig:
    http_ver: int          # -1=any, 0=1.0, 1=1.1
    headers: List[HttpHdr]
    absent: List[str]      # headers that must NOT appear
    sw: Optional[str]      # expected User-Agent/Server substring


@dataclass
class HttpSigRecord:
    generic: bool
    class_id: int
    name_id: int
    flavor: str
    label_id: int
    sys: List[int]
    line_no: int
    sig: HttpSig


@dataclass
class MtuSigRecord:
    name: str
    mtu: int


# ── SYS_CLASS_FLAG (mirror SYS_CLASS_FLAG in readfp.h) ───────────────────────
SYS_CLASS_FLAG = 0x80000000


# ── global signature database ─────────────────────────────────────────────────
# filled by read_fp()
fp_os_classes: List[str] = []
fp_os_names:   List[str] = []

tcp_sigs:  List[List[TcpSigRecord]]  = [[], []]   # [to_srv][...], [from_srv][...]
http_sigs: List[List[HttpSigRecord]] = [[], []]
mtu_sigs:  List[MtuSigRecord]        = []

ua_map: List[Tuple[int, str]] = []   # (name_id, ua_string) for User-Agent OS map


# ── helpers ───────────────────────────────────────────────────────────────────

def _lookup_class(name: str) -> int:
    for i, c in enumerate(fp_os_classes):
        if c.lower() == name.lower():
            return i
    raise ValueError(f"Unknown OS class '{name}'")


def _lookup_name(name: str) -> int:
    """Look up or register an OS/app name, returning its index."""
    for i, n in enumerate(fp_os_names):
        if n.lower() == name.lower():
            return i
    fp_os_names.append(name)
    return len(fp_os_names) - 1


def _simple_hash(data: bytes, seed: int = 0) -> int:
    """
    FNV-1a inspired 32-bit hash that gives the same bucketing as p0f's
    hash32().  We only need consistency within one run, so any stable
    non-cryptographic hash is fine.
    """
    h = seed ^ 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _opt_hash(opt_layout: List[int]) -> int:
    return _simple_hash(bytes(opt_layout))


def _parse_sys(val: str) -> List[int]:
    """Parse a 'sys = ...' value into a list of encoded IDs."""
    result = []
    for part in val.split(','):
        part = part.strip()
        if not part:
            continue
        if part.startswith('@'):
            cname = part[1:]
            cid = _lookup_class(cname)
            result.append(cid | SYS_CLASS_FLAG)
        else:
            result.append(_lookup_name(part))
    return result


# ── TCP signature parser ──────────────────────────────────────────────────────

def _parse_tcp_sig(val: str, line_no: int) -> TcpSig:
    """
    Parse a TCP sig line:
    ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
    """
    parts = val.split(':', 7)
    if len(parts) != 8:
        raise ValueError(f"Line {line_no}: TCP sig needs 8 colon-separated fields, got {len(parts)}: {val!r}")

    ver_s, ittl_s, olen_s, mss_s, win_s, olayout_s, quirks_s, pclass_s = parts

    # ip version
    if ver_s == '*':
        ip_ver = -1
    elif ver_s == '4':
        ip_ver = 4
    elif ver_s == '6':
        ip_ver = 6
    else:
        raise ValueError(f"Line {line_no}: unknown IP ver '{ver_s}'")

    # initial TTL
    bad_ttl = ittl_s.endswith('-')
    ittl = int(ittl_s.rstrip('-'))

    # IP option length
    ip_opt_len = int(olen_s)

    # MSS
    if mss_s == '*':
        mss = -1
    else:
        mss = int(mss_s)

    # window size + scale  (format: "wsize,scale")
    win_scale_parts = win_s.split(',', 1)
    if len(win_scale_parts) != 2:
        raise ValueError(f"Line {line_no}: bad wsize,scale field: {win_s!r}")
    wsize_s, scale_s = win_scale_parts

    if wsize_s == '*':
        win = 0; win_type = WIN_TYPE_ANY; win_param = 0
    elif wsize_s.startswith('mss*'):
        win = 0; win_type = WIN_TYPE_MSS; win_param = int(wsize_s[4:])
    elif wsize_s.startswith('mtu*'):
        win = 0; win_type = WIN_TYPE_MTU; win_param = int(wsize_s[4:])
    elif wsize_s.startswith('%'):
        win = 0; win_type = WIN_TYPE_MOD; win_param = int(wsize_s[1:])
    else:
        win = int(wsize_s); win_type = WIN_TYPE_NORMAL; win_param = 0

    if scale_s == '*':
        wscale = -1
    else:
        wscale = int(scale_s)

    # TCP option layout
    opt_layout = []
    opt_eol_pad = 0
    if olayout_s:
        pos = 0
        tokens = olayout_s.split(',')
        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok.startswith('eol+'):
                opt_layout.append(TCPOPT_EOL)
                opt_eol_pad = int(tok[4:])
            elif tok.startswith('?'):
                opt_layout.append(int(tok[1:]))
            elif tok in OPT_NAME_MAP:
                opt_layout.append(OPT_NAME_MAP[tok])
            else:
                raise ValueError(f"Line {line_no}: unknown TCP option '{tok}'")

    # quirks
    quirks = 0
    if quirks_s:
        qmap = {
            'df':     QUIRK_DF,
            'id+':    QUIRK_NZ_ID,
            'id-':    QUIRK_ZERO_ID,
            'ecn':    QUIRK_ECN,
            '0+':     QUIRK_NZ_MBZ,
            'flow':   QUIRK_FLOW,
            'seq-':   QUIRK_ZERO_SEQ,
            'ack+':   QUIRK_NZ_ACK,
            'ack-':   QUIRK_ZERO_ACK,
            'uptr+':  QUIRK_NZ_URG,
            'urgf+':  QUIRK_URG,
            'pushf+': QUIRK_PUSH,
            'ts1-':   QUIRK_OPT_ZERO_TS1,
            'ts2+':   QUIRK_OPT_NZ_TS2,
            'opt+':   QUIRK_OPT_EOL_NZ,
            'exws':   QUIRK_OPT_EXWS,
            'bad':    QUIRK_OPT_BAD,
        }
        for q in quirks_s.split(','):
            q = q.strip()
            if q not in qmap:
                raise ValueError(f"Line {line_no}: unknown quirk '{q}'")
            quirks |= qmap[q]

    # payload class
    if pclass_s == '0':
        pay_class = 0
    elif pclass_s == '+':
        pay_class = 1
    elif pclass_s == '*':
        pay_class = -1
    else:
        raise ValueError(f"Line {line_no}: unknown pclass '{pclass_s}'")

    sig = TcpSig(
        ip_ver=ip_ver, ittl=ittl, bad_ttl=bad_ttl, ip_opt_len=ip_opt_len,
        mss=mss, win=win, win_type=win_type, win_param=win_param,
        wscale=wscale, opt_layout=opt_layout, opt_eol_pad=opt_eol_pad,
        quirks=quirks, pay_class=pay_class,
    )
    sig.opt_hash = _opt_hash(opt_layout)
    return sig


# ── HTTP signature parser ─────────────────────────────────────────────────────

def _parse_http_sig(val: str, line_no: int) -> HttpSig:
    """
    Parse an HTTP sig line:
    ver:horder:habsent:expsw
    """
    parts = val.split(':', 3)
    if len(parts) != 4:
        raise ValueError(f"Line {line_no}: HTTP sig needs 4 colon-separated fields")

    ver_s, horder_s, habsent_s, expsw_s = parts

    if ver_s == '*':
        http_ver = -1
    elif ver_s == '0':
        http_ver = 0
    elif ver_s == '1':
        http_ver = 1
    else:
        raise ValueError(f"Line {line_no}: unknown HTTP version '{ver_s}'")

    headers: List[HttpHdr] = []
    if horder_s.strip():
        # Tokenise respecting [...] brackets so commas inside values are preserved
        tokens: List[str] = []
        depth = 0
        current = ''
        for ch in horder_s:
            if ch == '[':
                depth += 1
                current += ch
            elif ch == ']':
                depth -= 1
                current += ch
            elif ch == ',' and depth == 0:
                tokens.append(current.strip())
                current = ''
            else:
                current += ch
        if current.strip():
            tokens.append(current.strip())

        for hdr_tok in tokens:
            optional = hdr_tok.startswith('?')
            if optional:
                hdr_tok = hdr_tok[1:]
            # check for value match:  Name=[value]
            m = re.match(r'^([^\[=]+)(?:=\[([^\]]*)\])?$', hdr_tok)
            if not m:
                raise ValueError(f"Line {line_no}: bad header token '{hdr_tok}'")
            hname = m.group(1).strip()
            hvalue = m.group(2)  # None if not present
            headers.append(HttpHdr(name=hname, value=hvalue, optional=optional))

    absent: List[str] = []
    if habsent_s.strip():
        absent = [h.strip() for h in habsent_s.split(',') if h.strip()]

    sw = expsw_s.strip() if expsw_s.strip() else None

    return HttpSig(http_ver=http_ver, headers=headers, absent=absent, sw=sw)


# ── MTU signature parser ──────────────────────────────────────────────────────

def _register_mtu(name: str, val: str, line_no: int):
    try:
        mtu = int(val.strip())
    except ValueError:
        raise ValueError(f"Line {line_no}: bad MTU value '{val}'")
    if mtu <= 0 or mtu > 65535:
        raise ValueError(f"Line {line_no}: MTU value out of range")
    mtu_sigs.append(MtuSigRecord(name=name, mtu=mtu))


# ── ua_os parser ──────────────────────────────────────────────────────────────

def _parse_ua_os(val: str, line_no: int):
    """Parse ua_os = Linux,Windows,iOS=[iPad],..."""
    for part in val.split(','):
        part = part.strip()
        if not part:
            continue
        m = re.match(r'^([^\[=]+)(?:=\[([^\]]*)\])?$', part)
        if not m:
            raise ValueError(f"Line {line_no}: bad ua_os entry '{part}'")
        os_name = m.group(1).strip()
        ua_str  = m.group(2) if m.group(2) else os_name
        name_id = _lookup_name(os_name)
        ua_map.append((name_id, ua_str))


# ── label parser ──────────────────────────────────────────────────────────────

def _parse_label(val: str, mod_type: int, line_no: int):
    """
    Returns (generic, class_id, name_id, flavor).
    For MTU the format is just a free-form name.
    """
    if mod_type == CF_MOD_MTU:
        return False, -1, _lookup_name(val.strip()), ''

    # format: g|s:class:name:flavor
    m = re.match(r'^([gs]):([^:]+):([^:]+):(.*)$', val)
    if not m:
        raise ValueError(f"Line {line_no}: malformed label '{val}'")

    generic   = (m.group(1) == 'g')
    class_str = m.group(2).strip()
    name_str  = m.group(3).strip()
    flavor    = m.group(4).strip()

    if class_str == '!':
        class_id = -1
    else:
        class_id = _lookup_class(class_str)

    name_id = _lookup_name(name_str)
    return generic, class_id, name_id, flavor


# ── main reader ───────────────────────────────────────────────────────────────

def read_fp(path: str):
    """
    Parse a p0f.fp file and populate the global signature stores.
    Call this once at startup before any fingerprinting.
    """
    global fp_os_classes, fp_os_names, tcp_sigs, http_sigs, mtu_sigs, ua_map

    # reset
    fp_os_classes.clear()
    fp_os_names.clear()
    tcp_sigs[0].clear();  tcp_sigs[1].clear()
    http_sigs[0].clear(); http_sigs[1].clear()
    mtu_sigs.clear()
    ua_map.clear()

    mod_type   = -1
    mod_to_srv = True    # True = client→server (request), False = server→client
    generic    = False
    class_id   = -1
    name_id    = 0
    flavor     = ''
    label_id   = 0
    cur_sys: List[int] = []
    mtu_label  = ''

    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.strip()

            # skip comments and blanks
            if not line or line.startswith(';'):
                continue

            # ── section header ────────────────────────────────────────────
            if line.startswith('['):
                inner = line[1:].rstrip(']')
                if inner == 'mtu':
                    mod_type = CF_MOD_MTU
                else:
                    colon = inner.find(':')
                    if colon == -1:
                        raise ValueError(f"Line {line_no}: bad section '{line}'")
                    module_name = inner[:colon]
                    direction   = inner[colon+1:]
                    if module_name == 'tcp':
                        mod_type = CF_MOD_TCP
                    elif module_name == 'http':
                        mod_type = CF_MOD_HTTP
                    else:
                        raise ValueError(f"Line {line_no}: unknown module '{module_name}'")
                    mod_to_srv = (direction == 'request')
                cur_sys = []
                continue

            # ── key = value ───────────────────────────────────────────────
            eq = line.find('=')
            if eq == -1:
                continue
            key = line[:eq].strip()
            val = line[eq+1:].strip()

            if key == 'classes':
                for c in val.split(','):
                    c = c.strip()
                    if c:
                        fp_os_classes.append(c)

            elif key == 'ua_os':
                _parse_ua_os(val, line_no)

            elif key == 'label':
                generic, class_id, name_id, flavor = _parse_label(
                    val, mod_type, line_no)
                if mod_type == CF_MOD_MTU:
                    mtu_label = fp_os_names[name_id]
                cur_sys = []
                label_id += 1

            elif key == 'sys':
                cur_sys = _parse_sys(val)

            elif key == 'sig':
                if mod_type == CF_MOD_MTU:
                    _register_mtu(mtu_label, val, line_no)

                elif mod_type == CF_MOD_TCP:
                    try:
                        sig = _parse_tcp_sig(val, line_no)
                    except ValueError as e:
                        # skip bad sigs but keep going
                        import sys
                        print(f"[!] Skipping TCP sig at line {line_no}: {e}", file=sys.stderr)
                        continue
                    rec = TcpSigRecord(
                        generic=generic, class_id=class_id, name_id=name_id,
                        flavor=flavor, label_id=label_id, sys=list(cur_sys),
                        line_no=line_no, bad_ttl=sig.bad_ttl, sig=sig,
                    )
                    idx = 0 if mod_to_srv else 1
                    tcp_sigs[idx].append(rec)

                elif mod_type == CF_MOD_HTTP:
                    try:
                        sig = _parse_http_sig(val, line_no)
                    except ValueError as e:
                        import sys
                        print(f"[!] Skipping HTTP sig at line {line_no}: {e}", file=sys.stderr)
                        continue
                    rec = HttpSigRecord(
                        generic=generic, class_id=class_id, name_id=name_id,
                        flavor=flavor, label_id=label_id, sys=list(cur_sys),
                        line_no=line_no, sig=sig,
                    )
                    idx = 0 if mod_to_srv else 1
                    http_sigs[idx].append(rec)
