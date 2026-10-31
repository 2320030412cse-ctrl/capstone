"""
p0f.py - Windows-native passive OS fingerprinter (Python port of p0f v3).

Usage:
    python p0f.py [-i IFACE] [-r FILE] [-f FP_FILE] [-o LOG] [-L] [-p]

Requires:
    pip install scapy
    Npcap (Windows packet capture driver): https://npcap.com/
"""

import sys
import os
import argparse
import signal
import time
from typing import Optional

# ── ensure p0f_py directory is on the path ────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── colour / formatting constants ─────────────────────────────────────────────
_RESET  = '\033[0m'
_BOLD   = '\033[1m'
_GREEN  = '\033[32m'
_CYAN   = '\033[36m'
_YELLOW = '\033[33m'
_RED    = '\033[31m'
_GREY   = '\033[90m'

_USE_COLOR = sys.stdout.isatty() and os.name == 'nt' or os.name != 'nt'

def _c(color: str, text: str) -> str:
    if _USE_COLOR:
        return color + text + _RESET
    return text


# ── pretty-print an observation ───────────────────────────────────────────────

def _print_obs(obs: dict):
    t = obs.get('type', '?')
    src = f"{obs.get('src','?')}/{obs.get('sport',0)}"
    dst = f"{obs.get('dst','?')}/{obs.get('dport',0)}"

    print(_c(_CYAN, f"\n.-[ {src} -> {dst} ({t}) ]-"))
    print(_c(_CYAN, "|"))

    if t in ('syn', 'syn+ack'):
        subj_ip = obs.get('src', '?')
        print(_c(_CYAN, "|") + f" {'client' if t == 'syn' else 'server':<9}= {_c(_BOLD, subj_ip)}")
        os_str = obs.get('os') or _c(_GREY, 'unknown')
        print(_c(_CYAN, "|") + f" {'os':<9}= {_c(_GREEN, os_str) if obs.get('os') else os_str}")
        print(_c(_CYAN, "|") + f" {'dist':<9}= {obs.get('dist', '?')}")
        print(_c(_CYAN, "|") + f" {'params':<9}= {obs.get('params', 'none')}")
        print(_c(_CYAN, "|") + f" {'raw_sig':<9}= {_c(_GREY, obs.get('raw_sig',''))}")

    elif t == 'mtu':
        print(_c(_CYAN, "|") + f" {'client':<9}= {obs.get('src','?')}")
        link = obs.get('link') or _c(_GREY, 'unknown')
        print(_c(_CYAN, "|") + f" {'link':<9}= {_c(_YELLOW, link) if obs.get('link') else link}")
        print(_c(_CYAN, "|") + f" {'raw_mtu':<9}= {obs.get('raw_mtu', '?')}")

    elif t in ('http request', 'http response'):
        subj = 'client' if t == 'http request' else 'server'
        print(_c(_CYAN, "|") + f" {subj:<9}= {obs.get('src','?')}")
        app = obs.get('app') or _c(_GREY, 'unknown')
        print(_c(_CYAN, "|") + f" {'app':<9}= {_c(_GREEN, app) if obs.get('app') else app}")
        print(_c(_CYAN, "|") + f" {'lang':<9}= {obs.get('lang','none')}")
        print(_c(_CYAN, "|") + f" {'params':<9}= {obs.get('params','none')}")
        print(_c(_CYAN, "|") + f" {'raw_sig':<9}= {_c(_GREY, obs.get('raw_sig',''))}")
        sw = obs.get('sw')
        if sw:
            # truncate long UA strings
            sw_disp = (sw[:80] + '...') if len(sw) > 80 else sw
            print(_c(_CYAN, "|") + f" {'sw':<9}= {sw_disp}")

    print(_c(_CYAN, "`----"))
    sys.stdout.flush()


# ── list network interfaces ───────────────────────────────────────────────────

def list_interfaces():
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        print("\n-- Available interfaces --\n")
        for i, iface in enumerate(ifaces):
            name = iface.get('name', '?')
            desc = iface.get('description', '-')
            ips  = iface.get('ips', [])
            ip   = ips[0] if ips else '(none)'
            print(f"  {i:3d}: Name        : {name}")
            print(f"       Description : {desc}")
            print(f"       IP address  : {ip}\n")
    except Exception:
        # fallback
        from scapy.all import get_if_list
        ifaces = get_if_list()
        print("\n-- Available interfaces --\n")
        for i, name in enumerate(ifaces):
            print(f"  {i:3d}: {name}")
    print()


# ── argument parsing ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='p0f.py',
        description='p0f v3 - passive OS fingerprinter (Windows Python port)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python p0f.py -L                         list interfaces
  python p0f.py -i "Wi-Fi" -p              live capture on Wi-Fi
  python p0f.py -r capture.pcap            read from pcap file
  python p0f.py -i "Ethernet" -o p0f.log  live capture + log file
  python p0f.py -i "Wi-Fi" "port 80"      capture only port 80

Requires Npcap for live capture: https://npcap.com/
        """
    )
    p.add_argument('-i', metavar='IFACE',   help='Listen on network interface')
    p.add_argument('-r', metavar='FILE',    help='Read packets from pcap file')
    p.add_argument('-f', metavar='FP_FILE', help='Fingerprint database (default: ../p0f.fp)',
                   default=None)
    p.add_argument('-o', metavar='LOG',     help='Append log data to file')
    p.add_argument('-L', action='store_true', help='List interfaces and exit')
    p.add_argument('-p', action='store_true', help='Put interface in promiscuous mode')
    p.add_argument('filter', nargs='?', default=None,
                   help='BPF filter expression (e.g. "port 80")')
    return p


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    # Enable ANSI colours on Windows 10+
    if os.name == 'nt':
        os.system('')

    parser = build_parser()
    args   = parser.parse_args()

    # ── list interfaces and exit ──────────────────────────────────────────────
    if args.L:
        list_interfaces()
        sys.exit(0)

    # ── locate fingerprint database ───────────────────────────────────────────
    if args.f:
        fp_path = args.f
    else:
        # default: look next to this script, then one level up
        candidates = [
            os.path.join(_HERE, '..', 'p0f.fp'),
            os.path.join(_HERE, 'p0f.fp'),
            'p0f.fp',
        ]
        fp_path = None
        for c in candidates:
            if os.path.isfile(c):
                fp_path = os.path.normpath(c)
                break
        if not fp_path:
            print("[-] Cannot find p0f.fp. Use -f to specify its location.",
                  file=sys.stderr)
            sys.exit(1)

    # ── load signatures ───────────────────────────────────────────────────────
    print(f"[+] Loading fingerprint database from {fp_path!r} ...")
    from fp_reader import read_fp, tcp_sigs, http_sigs, mtu_sigs
    read_fp(fp_path)
    tcp_req  = len(tcp_sigs[0])
    tcp_resp = len(tcp_sigs[1])
    http_req = len(http_sigs[0])
    http_resp= len(http_sigs[1])
    mtu_cnt  = len(mtu_sigs)
    print(f"[+] Loaded: {tcp_req} TCP-SYN, {tcp_resp} TCP-SYN+ACK, "
          f"{http_req} HTTP-req, {http_resp} HTTP-resp, {mtu_cnt} MTU sigs.")

    # ── open log file ─────────────────────────────────────────────────────────
    log_file = None
    if args.o:
        try:
            log_file = open(args.o, 'a', encoding='utf-8')
            print(f"[+] Logging to {args.o!r}")
        except OSError as e:
            print(f"[-] Cannot open log file: {e}", file=sys.stderr)
            sys.exit(1)

    # ── import scapy (late, so -L / -h work without it) ──────────────────────
    try:
        import scapy.all as scapy
        # suppress scapy's own warnings on Windows
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except ImportError:
        print("[-] Scapy not found. Install it with:  pip install scapy",
              file=sys.stderr)
        sys.exit(1)

    from process import process_packet

    # ── build BPF filter ──────────────────────────────────────────────────────
    base_filter = 'tcp'
    if args.filter:
        bpf = f"tcp and ({args.filter})"
    else:
        bpf = base_filter

    # ── Ctrl-C handler ────────────────────────────────────────────────────────
    stop = [False]
    def _sigint(sig, frame):
        if stop[0]:
            sys.exit(1)
        stop[0] = True
        print("\n[*] Interrupted — stopping capture...")

    signal.signal(signal.SIGINT, _sigint)

    # ── callback for observations ─────────────────────────────────────────────
    def on_observation(obs: dict):
        _print_obs(obs)

    # ── read from pcap file ───────────────────────────────────────────────────
    if args.r:
        if not os.path.isfile(args.r):
            print(f"[-] File not found: {args.r}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Reading from {args.r!r} ...")
        try:
            pkts = scapy.rdpcap(args.r)
        except Exception as e:
            print(f"[-] Failed to read pcap: {e}", file=sys.stderr)
            sys.exit(1)
        for pkt in pkts:
            if stop[0]:
                break
            process_packet(pkt, on_observation, log_file)
        print(f"\n[+] Done. Processed {len(pkts)} packets.")

    # ── live capture ──────────────────────────────────────────────────────────
    else:
        iface = args.i
        promisc = args.p

        if iface:
            print(f"[+] Intercepting traffic on interface {iface!r}"
                  f"{' (promiscuous)' if promisc else ''} ...")
        else:
            print(f"[+] Intercepting traffic on default interface"
                  f"{' (promiscuous)' if promisc else ''} ...")
        print(f"[+] BPF filter: {bpf}")
        print( "[*] p0f running — press Ctrl-C to stop.\n")

        def _pkt_handler(pkt):
            if stop[0]:
                raise KeyboardInterrupt
            process_packet(pkt, on_observation, log_file)

        try:
            scapy.sniff(
                iface   = iface,
                filter  = bpf,
                prn     = _pkt_handler,
                store   = False,
                promisc = promisc,
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\n[-] Capture error: {e}", file=sys.stderr)
            if 'Npcap' in str(e) or 'winpcap' in str(e).lower() or \
               'No such device' in str(e):
                print("    Make sure Npcap is installed: https://npcap.com/",
                      file=sys.stderr)
            sys.exit(1)

    if log_file:
        log_file.close()

    print("[+] Finished.")


if __name__ == '__main__':
    main()
