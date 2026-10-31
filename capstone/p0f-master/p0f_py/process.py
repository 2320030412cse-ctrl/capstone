"""
process.py - Packet parsing, host/flow cache, and fingerprint dispatcher.

Mirrors process.c:
  - parse_packet()   : decode a Scapy packet into a pk dict
  - flow_dispatch()  : route pk to TCP / MTU / HTTP fingerprinters
  - Host / Flow cache (dict-based, with idle expiry)

The output of every observation is sent to a caller-supplied callback
so that p0f.py can handle display, logging, etc.
"""

import time
import socket
from typing import Optional, Callable, Dict, List, Tuple, Any

# TCP flag bits
TCP_FIN  = 0x01
TCP_SYN  = 0x02
TCP_RST  = 0x04
TCP_PUSH = 0x08
TCP_ACK  = 0x10
TCP_URG  = 0x20
TCP_ECE  = 0x40
TCP_CWR  = 0x80
TCP_NS   = 0x100   # ns bit lives in the reserved nibble

# TCP option kinds
TCPOPT_EOL    = 0
TCPOPT_NOP    = 1
TCPOPT_MAXSEG = 2
TCPOPT_WSCALE = 3
TCPOPT_SACKOK = 4
TCPOPT_SACK   = 5
TCPOPT_TSTAMP = 8

# QUIRK flags (mirrors process.h)
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

# config constants (mirrors config.h)
MAX_FLOW_DATA   = 8192
CONN_MAX_AGE    = 30       # seconds
HOST_IDLE_LIMIT = 7200     # seconds (120 min)
MAX_CONN        = 1000
MAX_HOSTS       = 10000
EXPIRE_INTERVAL = 50       # expire cache every N packets

packet_cnt: int = 0


# ── host / flow caches ────────────────────────────────────────────────────────

# host_cache: (ip_str, ip_ver) → host_data dict
host_cache: Dict[Tuple[str, int], Dict] = {}
# flow_cache: (src, dst, sport, dport) → flow_data dict
flow_cache: Dict[Tuple, Dict] = {}


def _new_host(ip_str: str, ip_ver: int) -> Dict:
    now = int(time.time())
    return {
        'ip':         ip_str,
        'ip_ver':     ip_ver,
        'first_seen': now,
        'last_seen':  now,
        'total_conn': 0,
        'os':         None,
        'os_flavor':  None,
        'link_type':  None,
        'language':   None,
        'distance':   -1,
        'bad_sw':     False,
        'uptime_min': 0,
        'last_syn':   None,
        'last_synack':None,
    }


def _get_or_create_host(ip_str: str, ip_ver: int) -> Dict:
    key = (ip_str, ip_ver)
    if key not in host_cache:
        host_cache[key] = _new_host(ip_str, ip_ver)
        # prune if over limit
        if len(host_cache) > MAX_HOSTS:
            oldest = min(host_cache, key=lambda k: host_cache[k]['last_seen'])
            del host_cache[oldest]
    host_cache[key]['last_seen'] = int(time.time())
    return host_cache[key]


def _new_flow(src: str, dst: str, sport: int, dport: int,
              ip_ver: int) -> Dict:
    now = int(time.time())
    return {
        'src':          src,
        'dst':          dst,
        'sport':        sport,
        'dport':        dport,
        'ip_ver':       ip_ver,
        'created':      now,
        'acked':        False,
        'in_http':      0,      # 0=tbd, 1=yes, -1=no
        'http_req_done':False,
        'request':      b'',
        'response':     b'',
        'syn_mss':      0,
        'client':       None,   # filled below
        'server':       None,
        'os':           None,   # best OS guess for this flow (for HTTP ua_vs_os)
    }


def _get_or_create_flow(src: str, dst: str, sport: int, dport: int,
                        ip_ver: int) -> Dict:
    key = (src, dst, sport, dport)
    if key not in flow_cache:
        flow_cache[key] = _new_flow(src, dst, sport, dport, ip_ver)
        if len(flow_cache) > MAX_CONN:
            oldest = min(flow_cache, key=lambda k: flow_cache[k]['created'])
            del flow_cache[oldest]
    return flow_cache[key]


def _expire_cache():
    now = int(time.time())
    # expire old flows
    dead_flows = [k for k, v in flow_cache.items()
                  if now - v['created'] > CONN_MAX_AGE]
    for k in dead_flows:
        del flow_cache[k]
    # expire idle hosts
    dead_hosts = [k for k, v in host_cache.items()
                  if now - v['last_seen'] > HOST_IDLE_LIMIT]
    for k in dead_hosts:
        del host_cache[k]


# ── TCP option parser ─────────────────────────────────────────────────────────

def _parse_tcp_options(opt_bytes: bytes) -> Dict:
    """
    Walk the TCP options blob and extract:
      opt_layout, opt_eol_pad, mss, wscale, ts1, ts2, quirks
    """
    opt_layout: List[int] = []
    opt_eol_pad = 0
    mss = 0
    wscale = 0
    ts1 = 0
    ts2 = 0
    quirks = 0

    i = 0
    n = len(opt_bytes)

    while i < n:
        kind = opt_bytes[i]
        i += 1

        if kind == TCPOPT_EOL:
            opt_layout.append(TCPOPT_EOL)
            # count remaining padding bytes
            opt_eol_pad = n - i
            if opt_eol_pad > 0 and any(opt_bytes[i:] != b'\x00' * opt_eol_pad):
                quirks |= QUIRK_OPT_EOL_NZ
            break

        if kind == TCPOPT_NOP:
            opt_layout.append(TCPOPT_NOP)
            continue

        # all other options have a length byte
        if i >= n:
            quirks |= QUIRK_OPT_BAD
            break
        length = opt_bytes[i]
        i += 1

        payload_len = length - 2
        if payload_len < 0 or i + payload_len > n:
            quirks |= QUIRK_OPT_BAD
            break

        opt_data = opt_bytes[i: i + payload_len]
        i += payload_len

        if kind == TCPOPT_MAXSEG:
            opt_layout.append(TCPOPT_MAXSEG)
            if len(opt_data) >= 2:
                mss = int.from_bytes(opt_data[:2], 'big')

        elif kind == TCPOPT_WSCALE:
            opt_layout.append(TCPOPT_WSCALE)
            if opt_data:
                wscale = opt_data[0]
                if wscale > 14:
                    quirks |= QUIRK_OPT_EXWS

        elif kind == TCPOPT_SACKOK:
            opt_layout.append(TCPOPT_SACKOK)

        elif kind == TCPOPT_SACK:
            opt_layout.append(TCPOPT_SACK)

        elif kind == TCPOPT_TSTAMP:
            opt_layout.append(TCPOPT_TSTAMP)
            if len(opt_data) >= 8:
                ts1 = int.from_bytes(opt_data[:4], 'big')
                ts2 = int.from_bytes(opt_data[4:8], 'big')
                if not ts1:
                    quirks |= QUIRK_OPT_ZERO_TS1

        else:
            opt_layout.append(kind)

    return {
        'opt_layout':  opt_layout,
        'opt_eol_pad': opt_eol_pad,
        'mss':         mss,
        'wscale':      wscale,
        'ts1':         ts1,
        'ts2':         ts2,
        'opt_quirks':  quirks,
    }


# ── Scapy packet → pk dict ────────────────────────────────────────────────────

def parse_packet(pkt) -> Optional[Dict]:
    """
    Convert a Scapy packet into a flat pk dict for the fingerprinters.

    Returns None if the packet is not a TCP/IP packet we care about,
    or if it is malformed.
    """
    try:
        from scapy.layers.inet  import IP,  TCP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        raise ImportError("Scapy is required. Run: pip install scapy")

    pk: Dict[str, Any] = {
        'ip_ver':     0,
        'src':        '',
        'dst':        '',
        'sport':      0,
        'dport':      0,
        'ttl':        0,
        'tos':        0,
        'ip_opt_len': 0,
        'tcp_type':   0,
        'seq':        0,
        'ack_num':    0,
        'win':        0,
        'flags':      0,
        'quirks':     0,
        'mss':        0,
        'wscale':     0,
        'ts1':        0,
        'ts2':        0,
        'opt_layout': [],
        'opt_eol_pad':0,
        'pay_len':    0,
        'payload':    b'',
        'tot_hdr':    0,
    }

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        pk['ip_ver'] = 4
        pk['src']    = ip.src
        pk['dst']    = ip.dst
        pk['ttl']    = ip.ttl
        pk['tos']    = (ip.tos >> 2) & 0x3F

        # IP flags / id quirks
        flags_off = (ip.flags.value << 13) | ip.frag
        if ip.flags.DF:
            pk['quirks'] |= QUIRK_DF
            if ip.id != 0:
                pk['quirks'] |= QUIRK_NZ_ID
        else:
            if ip.id == 0:
                pk['quirks'] |= QUIRK_ZERO_ID

        if ip.tos & 0x03:     # ECN bits
            pk['quirks'] |= QUIRK_ECN

        # IP options length
        ihl_bytes = ip.ihl * 4
        pk['ip_opt_len'] = max(0, ihl_bytes - 20)
        pk['tot_hdr']    = ihl_bytes

        # fragmented packets — skip
        if ip.frag != 0 or (ip.flags.value & 0x1):   # MF
            return None

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        pk['ip_ver']     = 6
        pk['src']        = ip6.src
        pk['dst']        = ip6.dst
        pk['ttl']        = ip6.hlim
        pk['tos']        = (ip6.tc >> 2) & 0x3F
        pk['ip_opt_len'] = 0
        pk['tot_hdr']    = 40   # fixed IPv6 header

        if ip6.fl:
            pk['quirks'] |= QUIRK_FLOW
        if ip6.tc & 0x03:
            pk['quirks'] |= QUIRK_ECN
    else:
        return None   # not IP

    # ── TCP ───────────────────────────────────────────────────────────────────
    if not pkt.haslayer(TCP):
        return None

    tcp = pkt[TCP]
    flags = int(tcp.flags)

    pk['sport']   = tcp.sport
    pk['dport']   = tcp.dport
    pk['seq']     = tcp.seq
    pk['ack_num'] = tcp.ack
    pk['win']     = tcp.window
    pk['flags']   = flags

    tcp_type = flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST)
    pk['tcp_type'] = tcp_type

    # drop nonsensical flag combos
    if ((flags & TCP_SYN) and (flags & (TCP_FIN | TCP_RST))) or \
       ((flags & TCP_FIN) and (flags & TCP_RST)) or \
       (tcp_type == 0):
        return None

    # ECN quirks from TCP flags
    if flags & (TCP_ECE | TCP_CWR):
        pk['quirks'] |= QUIRK_ECN

    # sequence / ACK quirks
    if tcp.seq == 0:
        pk['quirks'] |= QUIRK_ZERO_SEQ

    if flags & TCP_ACK:
        if tcp.ack == 0:
            pk['quirks'] |= QUIRK_ZERO_ACK
    else:
        if tcp.ack != 0 and not (flags & TCP_RST):
            pk['quirks'] |= QUIRK_NZ_ACK

    if flags & TCP_URG:
        pk['quirks'] |= QUIRK_URG
    else:
        if tcp.urgptr != 0:
            pk['quirks'] |= QUIRK_NZ_URG

    if flags & TCP_PUSH:
        pk['quirks'] |= QUIRK_PUSH

    # TCP header size
    tcp_hdr_len = tcp.dataofs * 4
    pk['tot_hdr'] += tcp_hdr_len

    # parse TCP options
    try:
        raw_opts = bytes(tcp.options)   # Scapy pre-parsed; re-serialise
    except Exception:
        raw_opts = b''

    # Scapy gives us options as a list of (kind, data) tuples; re-encode raw
    opt_raw = b''
    try:
        for opt in tcp.options:
            kind = opt[0]
            data = opt[1] if opt[1] is not None else b''
            if isinstance(data, int):
                # single-byte value fields
                if kind == TCPOPT_WSCALE:
                    data = bytes([data])
                elif kind == TCPOPT_MAXSEG:
                    data = data.to_bytes(2, 'big')
                else:
                    data = bytes([data])
            elif not isinstance(data, (bytes, bytearray)):
                data = b''
            if kind == TCPOPT_EOL:
                opt_raw += bytes([TCPOPT_EOL])
            elif kind == TCPOPT_NOP:
                opt_raw += bytes([TCPOPT_NOP])
            else:
                opt_raw += bytes([kind, len(data) + 2]) + bytes(data)
    except Exception:
        pk['quirks'] |= QUIRK_OPT_BAD

    opt_info = _parse_tcp_options(opt_raw)
    pk['quirks']     |= opt_info['opt_quirks']
    pk['opt_layout']  = opt_info['opt_layout']
    pk['opt_eol_pad'] = opt_info['opt_eol_pad']
    pk['mss']         = opt_info['mss']
    pk['wscale']      = opt_info['wscale']
    pk['ts1']         = opt_info['ts1']
    pk['ts2']         = opt_info['ts2']

    # TS2 non-zero on SYN is a quirk
    if (flags & TCP_SYN) and not (flags & TCP_ACK) and opt_info['ts2']:
        pk['quirks'] |= QUIRK_OPT_NZ_TS2

    # payload
    try:
        payload = bytes(tcp.payload)
    except Exception:
        payload = b''
    pk['payload'] = payload
    pk['pay_len'] = len(payload)

    return pk


# ── flow dispatch ─────────────────────────────────────────────────────────────

def flow_dispatch(
    pk: Dict,
    callback: Callable[[Dict], None],
    log_file=None,
):
    """
    Route a parsed packet dict to the appropriate fingerprinting modules
    and call *callback* with each observation dict produced.
    """
    from fp_tcp  import fingerprint_tcp
    from fp_mtu  import fingerprint_mtu
    from fp_http import fingerprint_http

    flags    = pk['tcp_type']
    is_syn   = bool(flags & TCP_SYN) and not bool(flags & TCP_ACK)
    is_synack = bool(flags & TCP_SYN) and bool(flags & TCP_ACK)
    is_data  = bool(flags & TCP_ACK) and not bool(flags & TCP_SYN)

    src, dst   = pk['src'], pk['dst']
    sport, dport = pk['sport'], pk['dport']
    ip_ver = pk['ip_ver']

    # ── SYN (client → server) ─────────────────────────────────────────────────
    if is_syn:
        host = _get_or_create_host(src, ip_ver)
        host['total_conn'] += 1

        flow = _get_or_create_flow(src, dst, sport, dport, ip_ver)
        flow['client'] = host
        flow['server'] = _get_or_create_host(dst, ip_ver)
        flow['syn_mss'] = pk.get('mss', 0)

        # TCP fingerprint
        obs = fingerprint_tcp(to_srv=True, pk=pk, syn_mss=0)
        if obs['os']:
            host['os']       = obs['os']
            host['distance'] = obs['dist']
            flow['os']       = obs['os']
        _emit(obs, callback, log_file)

        # MTU fingerprint
        link = fingerprint_mtu(pk)
        if link:
            host['link_type'] = link
            mtu_obs = {
                'type':    'mtu',
                'src':     src, 'dst': dst,
                'sport':   sport, 'dport': dport,
                'link':    link,
                'raw_mtu': pk.get('mss', 0) + (40 if ip_ver == 4 else 60),
            }
            _emit(mtu_obs, callback, log_file)

    # ── SYN+ACK (server → client) ─────────────────────────────────────────────
    elif is_synack:
        host = _get_or_create_host(src, ip_ver)

        # look up the corresponding SYN flow (client side is dst:dport→src:sport)
        syn_key = (dst, src, dport, sport)
        flow = flow_cache.get(syn_key)
        if flow is None:
            flow = _get_or_create_flow(src, dst, sport, dport, ip_ver)
            flow['server'] = host
            flow['client'] = _get_or_create_host(dst, ip_ver)
        flow['acked'] = True

        syn_mss = flow.get('syn_mss', 0)
        obs = fingerprint_tcp(to_srv=False, pk=pk, syn_mss=syn_mss)
        if obs['os']:
            host['os']       = obs['os']
            host['distance'] = obs['dist']
        _emit(obs, callback, log_file)

        # MTU on SYN+ACK too
        link = fingerprint_mtu(pk)
        if link:
            host['link_type'] = link
            mtu_obs = {
                'type':    'mtu',
                'src':     src, 'dst': dst,
                'sport':   sport, 'dport': dport,
                'link':    link,
                'raw_mtu': pk.get('mss', 0) + (40 if ip_ver == 4 else 60),
            }
            _emit(mtu_obs, callback, log_file)

    # ── data packets: try HTTP fingerprinting ─────────────────────────────────
    elif is_data and pk['pay_len'] > 0:
        # client→server data
        fwd_key = (src, dst, sport, dport)
        rev_key = (dst, src, dport, sport)

        flow = flow_cache.get(fwd_key) or flow_cache.get(rev_key)
        if flow is None:
            return   # no flow context, skip

        # determine direction
        to_srv = (fwd_key == (flow['src'], flow['dst'],
                               flow['sport'], flow['dport']))

        if to_srv:
            # accumulate request data
            if len(flow['request']) < MAX_FLOW_DATA:
                flow['request'] += pk['payload']
                data = flow['request']
            else:
                return
        else:
            # accumulate response data
            if len(flow['response']) < MAX_FLOW_DATA:
                flow['response'] += pk['payload']
                data = flow['response']
            else:
                return

        # only attempt HTTP once we have enough data
        if len(data) < 16:
            return

        if flow.get('in_http') == -1:
            return   # confirmed non-HTTP

        obs = fingerprint_http(to_srv=to_srv, payload=data, flow=flow)
        if obs is None:
            flow['in_http'] = -1
            return

        flow['in_http'] = 1

        # propagate language to host
        client_host = flow.get('client')
        server_host = flow.get('server')
        if to_srv and client_host and obs.get('lang') and obs['lang'] != 'none':
            client_host['language'] = obs['lang']
        if not to_srv and server_host and obs.get('lang') and obs['lang'] != 'none':
            server_host['language'] = obs['lang']

        _emit(obs, callback, log_file)


def _emit(obs: Dict, callback: Callable[[Dict], None], log_file=None):
    """Send an observation to the callback and optionally write to a log file."""
    callback(obs)
    if log_file:
        _write_log(obs, log_file)


def _write_log(obs: Dict, log_file):
    """Write a grep-friendly pipe-delimited log line (mirrors p0f -o format)."""
    import datetime
    ts = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    t  = obs.get('type', '?')
    src = f"{obs.get('src','?')}/{obs.get('sport',0)}"
    dst = f"{obs.get('dst','?')}/{obs.get('dport',0)}"

    if t in ('syn', 'syn+ack'):
        line = (f"[{ts}] mod=tcp|cli={src}|srv={dst}|subj={'cli' if t=='syn' else 'srv'}"
                f"|os={obs.get('os') or '?'}|dist={obs.get('dist',0)}"
                f"|params={obs.get('params','none')}|raw_sig={obs.get('raw_sig','')}\n")
    elif t == 'mtu':
        line = (f"[{ts}] mod=mtu|cli={src}|srv={dst}|subj=cli"
                f"|link={obs.get('link','?')}|raw_mtu={obs.get('raw_mtu',0)}\n")
    elif t in ('http request', 'http response'):
        subj = 'cli' if t == 'http request' else 'srv'
        line = (f"[{ts}] mod=http|cli={src}|srv={dst}|subj={subj}"
                f"|app={obs.get('app') or '?'}|lang={obs.get('lang','none')}"
                f"|params={obs.get('params','none')}|raw_sig={obs.get('raw_sig','')}\n")
    else:
        return

    try:
        log_file.write(line)
        log_file.flush()
    except Exception:
        pass


# ── main process_packet entry point ──────────────────────────────────────────

def process_packet(pkt, callback: Callable[[Dict], None], log_file=None):
    """
    Top-level entry point called for each Scapy-captured packet.
    Parses, dispatches, and periodically expires the cache.
    """
    global packet_cnt
    packet_cnt += 1

    if packet_cnt % EXPIRE_INTERVAL == 0:
        _expire_cache()

    pk = parse_packet(pkt)
    if pk is None:
        return

    flow_dispatch(pk, callback, log_file)
