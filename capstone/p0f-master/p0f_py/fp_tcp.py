"""
fp_tcp.py - TCP SYN / SYN+ACK passive OS fingerprinting.

Mirrors the logic in fp_tcp.c:
  - packet_to_sig()   : convert raw packet fields to a TcpSig for matching
  - tcp_find_match()  : compare against every loaded TcpSigRecord
  - fingerprint_tcp() : entry point called by process.py
  - guess_dist()      : estimate hop distance from observed TTL
"""

from typing import Optional, Tuple
import time

from fp_reader import (
    TcpSig, TcpSigRecord,
    WIN_TYPE_NORMAL, WIN_TYPE_ANY, WIN_TYPE_MOD, WIN_TYPE_MSS, WIN_TYPE_MTU,
    QUIRK_DF, QUIRK_NZ_ID, QUIRK_ZERO_ID, QUIRK_ECN, QUIRK_FLOW,
    QUIRK_OPT_EXWS,
    tcp_sigs, fp_os_names, fp_os_classes,
    _opt_hash,
)

# minimum header sizes (mirrors tcp.h)
MIN_TCP4 = 20 + 20   # IPv4 hdr + TCP hdr
MIN_TCP6 = 40 + 20   # IPv6 hdr + TCP hdr

MAX_DIST = 35        # from config.h


# ── TTL distance estimation ────────────────────────────────────────────────────

def guess_dist(ttl: int) -> int:
    """Mirror of guess_dist() in fp_tcp.c."""
    if ttl <= 32:  return 32 - ttl
    if ttl <= 64:  return 64 - ttl
    if ttl <= 128: return 128 - ttl
    return 255 - ttl


# ── window-size multiplier detection ──────────────────────────────────────────

def detect_win_multi(win: int, mss: int, ts1: int,
                     ip_ver: int, tot_hdr: int,
                     syn_mss: int = 0) -> Tuple[int, bool]:
    """
    Mirror of detect_win_multi() in fp_tcp.c.
    Returns (multiplier, use_mtu).  Returns (-1, False) if no pattern found.
    """
    if not win or mss < 100:
        return -1, False

    mss12 = mss - 12

    def check(divisor, use_mtu):
        if divisor and (win % divisor) == 0:
            return win // divisor, use_mtu
        return None

    r = check(mss, False);          
    if r: return r
    if ts1:
        r = check(mss12, False)
        if r: return r

    r = check(1500 - MIN_TCP4, False)
    if r: return r
    r = check(1500 - MIN_TCP4 - 12, False)
    if r: return r

    if ip_ver == 6:
        r = check(1500 - MIN_TCP6, False)
        if r: return r
        r = check(1500 - MIN_TCP6 - 12, False)
        if r: return r

    r = check(mss + MIN_TCP4, True)
    if r: return r
    r = check(mss + tot_hdr, True)
    if r: return r
    if ip_ver == 6:
        r = check(mss + MIN_TCP6, True)
        if r: return r
    r = check(1500, True)
    if r: return r

    if syn_mss:
        r = check(syn_mss, False)
        if r: return r
        r = check(syn_mss - 12, False)
        if r: return r

    return -1, False


# ── live-packet → TcpSig ──────────────────────────────────────────────────────

def packet_to_sig(pk: dict) -> TcpSig:
    """
    Convert a parsed packet dict (from process.py) into a TcpSig
    suitable for matching against loaded signatures.

    pk keys: ip_ver, ttl, ip_opt_len, mss, win, wscale, opt_layout,
             opt_eol_pad, quirks, pay_len, tot_hdr, ts1
    """
    sig = TcpSig(
        ip_ver      = pk['ip_ver'],
        ittl        = pk['ttl'],
        bad_ttl     = False,
        ip_opt_len  = pk['ip_opt_len'],
        mss         = pk.get('mss', -1),
        win         = pk['win'],
        win_type    = WIN_TYPE_NORMAL,
        win_param   = 0,
        wscale      = pk.get('wscale', -1),
        opt_layout  = list(pk.get('opt_layout', [])),
        opt_eol_pad = pk.get('opt_eol_pad', 0),
        quirks      = pk.get('quirks', 0),
        pay_class   = 1 if pk.get('pay_len', 0) > 0 else 0,
    )
    sig.opt_hash = _opt_hash(sig.opt_layout)
    return sig


# ── signature matching ────────────────────────────────────────────────────────

def _win_matches(sig: TcpSig, ref: TcpSig, syn_mss: int) -> bool:
    """
    Return True if the observed window size (sig) matches the database
    record (ref) according to its WIN_TYPE.
    """
    if ref.win_type == WIN_TYPE_ANY:
        return True

    if ref.win_type == WIN_TYPE_MOD:
        return (sig.win % ref.win_param) == 0

    if ref.win_type == WIN_TYPE_MSS:
        mss = sig.mss if sig.mss > 0 else syn_mss
        if mss <= 0:
            return False
        return sig.win == mss * ref.win_param

    if ref.win_type == WIN_TYPE_MTU:
        mss = sig.mss if sig.mss > 0 else syn_mss
        if mss <= 0:
            return False
        mtu_val = mss + (MIN_TCP4 if sig.ip_ver == 4 else MIN_TCP6)
        return sig.win == mtu_val * ref.win_param

    # WIN_TYPE_NORMAL
    return sig.win == ref.win


def tcp_find_match(
    to_srv: bool,
    sig: TcpSig,
    syn_mss: int = 0,
) -> Optional[Tuple[TcpSigRecord, bool]]:
    """
    Search loaded TCP signatures for a match against *sig*.
    Returns (TcpSigRecord, fuzzy) or None.
    Mirrors tcp_find_match() in fp_tcp.c.
    """
    idx = 0 if to_srv else 1
    candidates = tcp_sigs[idx]

    best_specific: Optional[Tuple[TcpSigRecord, bool]] = None
    best_generic:  Optional[Tuple[TcpSigRecord, bool]] = None

    for rec in candidates:
        rs = rec.sig

        # option-layout hash must match
        if rs.opt_hash != sig.opt_hash:
            continue

        fuzzy = False

        # ── quirk comparison ──────────────────────────────────────────────────
        ref_quirks = rs.quirks

        # strip protocol-specific quirks when ip_ver != sig
        if rs.ip_ver == -1:
            if sig.ip_ver == 4:
                ref_quirks &= ~QUIRK_FLOW
            else:
                ref_quirks &= ~(QUIRK_DF | QUIRK_NZ_ID | QUIRK_ZERO_ID)

        if ref_quirks != sig.quirks:
            deleted = (ref_quirks ^ sig.quirks) & ref_quirks
            added   = (ref_quirks ^ sig.quirks) & sig.quirks
            # allow fuzzy: df/id+ disappear, id-/ecn appear
            allowed_del = QUIRK_DF | QUIRK_NZ_ID
            allowed_add = QUIRK_ZERO_ID | QUIRK_ECN
            if (deleted & ~allowed_del) or (added & ~allowed_add):
                continue
            fuzzy = True

        # ── IP version ────────────────────────────────────────────────────────
        if rs.ip_ver != -1 and rs.ip_ver != sig.ip_ver:
            continue

        # ── TTL ───────────────────────────────────────────────────────────────
        dist = guess_dist(sig.ittl)
        if rs.bad_ttl:
            # random TTL — accept anything up to ittl
            if sig.ittl > rs.ittl:
                continue
        else:
            reconstructed = sig.ittl + dist
            if reconstructed != rs.ittl:
                # fuzzy TTL check
                if abs(reconstructed - rs.ittl) <= 1 or (
                        rs.ittl - dist) > 0 and (rs.ittl - dist) <= sig.ittl:
                    fuzzy = True
                else:
                    continue

        # ── IP option length ──────────────────────────────────────────────────
        if rs.ip_opt_len != sig.ip_opt_len:
            continue

        # ── MSS ───────────────────────────────────────────────────────────────
        if rs.mss != -1 and rs.mss != sig.mss:
            continue

        # ── window size ───────────────────────────────────────────────────────
        if not _win_matches(sig, rs, syn_mss):
            continue

        # ── window scale ──────────────────────────────────────────────────────
        if rs.wscale != -1 and rs.wscale != sig.wscale:
            continue

        # ── EOL padding ───────────────────────────────────────────────────────
        if rs.opt_eol_pad != sig.opt_eol_pad:
            continue

        # ── payload class ─────────────────────────────────────────────────────
        if rs.pay_class != -1 and rs.pay_class != sig.pay_class:
            continue

        # ── match! ────────────────────────────────────────────────────────────
        match = (rec, fuzzy)
        if rec.generic:
            if best_generic is None:
                best_generic = match
        else:
            if best_specific is None:
                best_specific = match

    return best_specific or best_generic


# ── public entry point ────────────────────────────────────────────────────────

def fingerprint_tcp(to_srv: bool, pk: dict, syn_mss: int = 0) -> dict:
    """
    Main entry point.  Called by process.py for every SYN / SYN+ACK.

    Returns an observation dict:
      {
        'type':    'syn' | 'syn+ack',
        'src':     ip string,
        'dst':     ip string,
        'sport':   int,
        'dport':   int,
        'os':      str | None,
        'dist':    int,
        'params':  str,
        'raw_sig': str,
      }
    """
    sig = packet_to_sig(pk)

    result = tcp_find_match(to_srv, sig, syn_mss)

    dist  = guess_dist(pk['ttl'])
    os_str = None
    params = []
    fuzzy  = False

    if result:
        rec, fuzzy = result
        name = fp_os_names[rec.name_id] if rec.name_id < len(fp_os_names) else '?'
        flav = rec.flavor or ''
        os_str = f"{name} {flav}".strip()
        if rec.generic: params.append('generic')
        if fuzzy:       params.append('fuzzy')
        if rec.bad_ttl: params.append('random_ttl')

    if dist > MAX_DIST:
        params.append('excess_dist')
    if pk.get('tos', 0):
        params.append(f"tos:0x{pk['tos']:02x}")

    raw_sig = _build_raw_sig(pk, sig, syn_mss)

    return {
        'type':    'syn' if to_srv else 'syn+ack',
        'src':     pk.get('src', '?'),
        'dst':     pk.get('dst', '?'),
        'sport':   pk.get('sport', 0),
        'dport':   pk.get('dport', 0),
        'os':      os_str,
        'dist':    dist,
        'params':  ', '.join(params) if params else 'none',
        'raw_sig': raw_sig,
        'matched_rec': result[0] if result else None,
        'fuzzy':   fuzzy,
    }


# ── raw signature string builder (for display / logging) ─────────────────────

def _build_raw_sig(pk: dict, sig: TcpSig, syn_mss: int) -> str:
    """Build a human-readable signature string like p0f's dump_sig()."""
    dist = guess_dist(pk['ttl'])

    if dist > MAX_DIST:
        ttl_part = f"{pk['ip_ver']}:{pk['ttl']}+?:{pk['ip_opt_len']}:"
    else:
        ttl_part = f"{pk['ip_ver']}:{pk['ttl']}+{dist}:{pk['ip_opt_len']}:"

    mss = pk.get('mss', 0)
    mss_part = '*' if mss == 0 else str(mss)

    # window size
    win = pk['win']
    multi, use_mtu = detect_win_multi(
        win, mss or 0, pk.get('ts1', 0),
        pk['ip_ver'], pk.get('tot_hdr', 0), syn_mss)
    if multi > 0:
        win_part = f"{'mtu' if use_mtu else 'mss'}*{multi}"
    else:
        win_part = str(win)

    wscale = pk.get('wscale', 0)
    win_part = f"{win_part},{wscale}"

    # option layout
    opt_strs = []
    opt_layout = pk.get('opt_layout', [])
    opt_eol_pad = pk.get('opt_eol_pad', 0)
    from fp_reader import TCPOPT_EOL, TCPOPT_NOP, TCPOPT_MAXSEG, \
                          TCPOPT_WSCALE, TCPOPT_SACKOK, TCPOPT_SACK, TCPOPT_TSTAMP
    opt_map = {
        TCPOPT_EOL:    lambda: f"eol+{opt_eol_pad}",
        TCPOPT_NOP:    lambda: "nop",
        TCPOPT_MAXSEG: lambda: "mss",
        TCPOPT_WSCALE: lambda: "ws",
        TCPOPT_SACKOK: lambda: "sok",
        TCPOPT_SACK:   lambda: "sack",
        TCPOPT_TSTAMP: lambda: "ts",
    }
    for o in opt_layout:
        opt_strs.append(opt_map.get(o, lambda o=o: f"?{o}")())
    opt_part = ','.join(opt_strs)

    # quirks
    quirks = pk.get('quirks', 0)
    qlist = []
    from fp_reader import (QUIRK_DF, QUIRK_NZ_ID, QUIRK_ZERO_ID, QUIRK_ECN,
                            QUIRK_NZ_MBZ, QUIRK_FLOW, QUIRK_ZERO_SEQ,
                            QUIRK_NZ_ACK, QUIRK_ZERO_ACK, QUIRK_NZ_URG,
                            QUIRK_URG, QUIRK_PUSH, QUIRK_OPT_ZERO_TS1,
                            QUIRK_OPT_NZ_TS2, QUIRK_OPT_EOL_NZ,
                            QUIRK_OPT_EXWS, QUIRK_OPT_BAD)
    qbits = [
        (QUIRK_DF,           'df'),
        (QUIRK_NZ_ID,        'id+'),
        (QUIRK_ZERO_ID,      'id-'),
        (QUIRK_ECN,          'ecn'),
        (QUIRK_NZ_MBZ,       '0+'),
        (QUIRK_FLOW,         'flow'),
        (QUIRK_ZERO_SEQ,     'seq-'),
        (QUIRK_NZ_ACK,       'ack+'),
        (QUIRK_ZERO_ACK,     'ack-'),
        (QUIRK_NZ_URG,       'uptr+'),
        (QUIRK_URG,          'urgf+'),
        (QUIRK_PUSH,         'pushf+'),
        (QUIRK_OPT_ZERO_TS1, 'ts1-'),
        (QUIRK_OPT_NZ_TS2,   'ts2+'),
        (QUIRK_OPT_EOL_NZ,   'opt+'),
        (QUIRK_OPT_EXWS,     'exws'),
        (QUIRK_OPT_BAD,      'bad'),
    ]
    for bit, name in qbits:
        if quirks & bit:
            qlist.append(name)
    quirk_part = ','.join(qlist)

    pay_part = '+' if pk.get('pay_len', 0) > 0 else '0'

    return f"{ttl_part}{mss_part}:{win_part}:{opt_part}:{quirk_part}:{pay_part}"
