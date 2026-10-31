"""
p0f_gui.py  -  Passive OS Fingerprinter GUI
  . Live packet capture & TCP/HTTP/MTU fingerprinting
  . Per-IP risk / safety rating
  . DNS query tracking  (which sites each device visited)
  . Device name resolution  (reverse DNS + NetBIOS)
  . WiFi Users tab  -  ARP scan, MAC, vendor, OS, domains, risk per user

Run:   python p0f_gui.py
Needs: pip install scapy  +  Npcap (https://npcap.com/)
"""

import sys, os, threading, queue, time, ipaddress, socket
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
from collections import defaultdict

try:
    from mac_vendor import lookup as mac_lookup, vendor_icon
except ImportError:
    def mac_lookup(mac): return "Unknown"
    def vendor_icon(v):  return ""

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── palette ────────────────────────────────────────────────────────────────────
BG     = "#0d1117"; BG2 = "#161b22"; BG3 = "#21262d"
ACCENT = "#58a6ff"; GREEN = "#3fb950"; RED = "#f78166"
ORANGE = "#d29922"; YELLOW = "#e3b341"; PURPLE = "#d2a8ff"
CYAN   = "#79c0ff"; TEXT = "#c9d1d9"; DIM = "#6e7681"; BORDER = "#30363d"
RISK_COLORS = {"SAFE": GREEN, "LOW": CYAN, "MEDIUM": YELLOW,
               "HIGH": ORANGE, "CRITICAL": RED}

_PRIVATE = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
             "127.0.0.0/8","169.254.0.0/16")]

def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _PRIVATE)
    except Exception:
        return False

RISKY_PORTS = {
    21:"FTP (cleartext)", 23:"Telnet (cleartext)", 25:"SMTP",
    53:"DNS", 110:"POP3", 143:"IMAP", 445:"SMB",
    1433:"MSSQL", 3306:"MySQL", 3389:"RDP",
    4444:"Metasploit", 5900:"VNC", 6379:"Redis",
    8080:"HTTP-alt", 8443:"HTTPS-alt", 9200:"Elasticsearch",
    27017:"MongoDB",
}
OS_NOTES = {
    "windows xp":   ("CRITICAL","End-of-life OS"),
    "windows 2000": ("CRITICAL","End-of-life OS"),
    "windows nt":   ("HIGH",    "Very old Windows"),
    "windows 7":    ("HIGH",    "End-of-life since Jan 2020"),
    "windows vista":("CRITICAL","End-of-life OS"),
    "windows 95":   ("CRITICAL","End-of-life OS"),
    "windows 98":   ("CRITICAL","End-of-life OS"),
}
SUSPICIOUS_DOMAINS = [
    ("onion",      "Tor / dark-web domain"),
    ("bit.ly",     "URL shortener"),
    ("tinyurl",    "URL shortener"),
    ("pastebin",   "Paste site — common C2 channel"),
    ("ngrok",      "Tunnel service — possible C2"),
    ("no-ip",      "Dynamic DNS — common in malware"),
    ("duckdns",    "Dynamic DNS — common in malware"),
    ("ddns",       "Dynamic DNS"),
    (".xyz",       "High-abuse TLD"),
    (".top",       "High-abuse TLD"),
    (".tk",        "High-abuse TLD"),
    (".cf",        "High-abuse TLD"),
    (".ml",        "High-abuse TLD"),
    ("metasploit", "Penetration testing framework"),
    ("cobalt",     "Possible Cobalt Strike beacon"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  Risk engine
# ══════════════════════════════════════════════════════════════════════════════

def compute_risk(ip_info: dict) -> dict:
    score = 0; factors = []; advice = []
    ip = ip_info.get("ip", "")

    if _is_private(ip):
        factors.append("Private / internal IP address")
    else:
        score += 10
        factors.append("Public IP address — external device")
        advice.append("Verify this external IP is an expected connection")

    os_str = (ip_info.get("os") or "").lower()
    hit = False
    for pat, (lvl, note) in OS_NOTES.items():
        if pat in os_str:
            score += {"CRITICAL":50,"HIGH":35,"MEDIUM":20}.get(lvl,10)
            factors.append(f"OS: {note}")
            advice.append(f"Upgrade or isolate this device ({ip_info.get('os')})")
            hit = True; break
    if not hit and os_str:
        factors.append(f"OS identified: {ip_info.get('os')}")

    if not os_str or os_str == "?":
        score += 15
        factors.append("OS could not be fingerprinted")
        advice.append("Investigate — may be using a custom TCP stack")

    for port in ip_info.get("ports_seen", []):
        if port in RISKY_PORTS:
            score += 12
            factors.append(f"Sensitive port {port} ({RISKY_PORTS[port]})")
            advice.append(f"Confirm port {port} is authorised")

    params = " ".join(ip_info.get("params_seen", []))
    if "dishonest_ua" in params:
        score += 20; factors.append("Dishonest User-Agent detected")
        advice.append("Possible spoofed software version")
    if "via" in params:
        score += 10; factors.append("Via / X-Forwarded-For seen (proxy/NAT)")
        advice.append("Traffic is being proxied")
    if "ua_vs_os" in params:
        score += 15; factors.append("User-Agent OS mismatch with TCP fingerprint")
        advice.append("Possible OS spoofing or VPN/VM")
    if "fuzzy" in params:
        score += 8; factors.append("TCP signature fuzzy match")
    if "random_ttl" in params:
        score += 12; factors.append("Random TTL — likely a scanning tool")
        advice.append("Block or investigate immediately")

    conn = ip_info.get("conn_count", 0)
    if conn > 50:
        score += 20; factors.append(f"High connection count ({conn}) — possible scan/DDoS")
        advice.append("Rate-limit or block if unexpected")
    elif conn > 20:
        score += 8; factors.append(f"Elevated connection count ({conn})")

    dist = ip_info.get("dist", 0) or 0
    if dist > 25:
        score += 8; factors.append(f"Large TTL distance ({dist} hops)")

    link = (ip_info.get("link_type") or "").lower()
    if any(k in link for k in ("vpn","tunnel","ipsec")):
        score += 8; factors.append(f"VPN/tunnel link detected ({ip_info.get('link_type')})")
        advice.append("Confirm this VPN is authorised")

    for domain in ip_info.get("domains_queried", []):
        for pat, desc in SUSPICIOUS_DOMAINS:
            if pat in domain.lower():
                score += 18
                factors.append(f"Suspicious domain: {domain}  ({desc})")
                advice.append(f"Investigate DNS query for {domain}")
                break

    score = min(score, 100)
    level = ("SAFE" if score == 0 else "LOW" if score <= 15 else
             "MEDIUM" if score <= 35 else "HIGH" if score <= 60 else "CRITICAL")
    if not factors: factors.append("No anomalies detected")
    if not advice:  advice.append("No action required")
    return {"score": score, "level": level,
            "bar": "X"*round(score/5) + "."*(20-round(score/5)),
            "factors": factors, "advice": advice}

# ══════════════════════════════════════════════════════════════════════════════
#  Network helpers
# ══════════════════════════════════════════════════════════════════════════════

def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def _netbios_name(ip: str) -> str:
    try:
        query  = bytes([0xAB,0xCD,0x00,0x00,0x00,0x01,
                        0x00,0x00,0x00,0x00,0x00,0x00])
        query += bytes([0x20])
        query += bytes([0x43,0x4B] + [0x41]*30)
        query += bytes([0x00,0x00,0x21,0x00,0x01])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) < 57: return ""
        num_names = data[56]; offset = 57; names = []
        for _ in range(num_names):
            if offset + 18 > len(data): break
            raw = data[offset:offset+15].rstrip(b"\x00 ")
            names.append(raw.decode("ascii", errors="replace").strip())
            offset += 18
        return names[0] if names else ""
    except Exception:
        return ""

def _get_local_subnets() -> list:
    """
    Return a list of local IPv4 /24 networks for ARP scanning.
    Uses scapy's conf.ifaces to find addresses.
    """
    subnets = []
    try:
        import scapy.all as sc
        for iface in sc.conf.ifaces.values():
            ip = getattr(iface, "ip", None) or getattr(iface, "IPv4", None)
            if not ip or ip == "0.0.0.0":
                continue
            try:
                net = ipaddress.ip_interface(f"{ip}/24").network
                if _is_private(ip):
                    subnets.append(net)
            except Exception:
                pass
    except Exception:
        pass
    # fallback: use socket to find local IP
    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.ip_interface(f"{local_ip}/24").network
            subnets.append(net)
        except Exception:
            pass
    return subnets

# ══════════════════════════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════════════════════════

class P0fGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("p0f  -  OS Fingerprinter  .  Risk Analyser  .  WiFi Users")
        self.root.geometry("1340x860")
        self.root.configure(bg=BG)
        self.root.minsize(1000, 660)

        self._running        = False
        self._capture_thread = None
        self._dns_thread     = None
        self._obs_queue      = queue.Queue()
        self._row_count      = 0
        self._stats          = {"syn":0,"syn+ack":0,"mtu":0,"http":0,"matched":0,"total":0}
        self._log_file       = None
        self._iface_map      = {}

        self._ip_data: dict        = {}
        self._ip_dns: dict         = defaultdict(set)
        self._ip_names: dict       = {}
        self._resolve_queue        = queue.Queue()

        # WiFi Users
        self._wifi_users: dict     = {}   # ip -> user dict
        self._arp_mac: dict        = {}   # ip -> mac (passive ARP)
        self._arp_scanning         = False

        self._setup_styles()
        self._build_ui()
        self._load_interfaces()
        self.root.after(100, self._poll_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        threading.Thread(target=self._resolver_worker, daemon=True).start()

    # ── styles ─────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, fieldbackground=BG3,
                    bordercolor=BORDER, troughcolor=BG2,
                    selectbackground=ACCENT, selectforeground=BG,
                    font=("Consolas", 10))
        s.configure("Treeview", background=BG2, foreground=TEXT,
                    fieldbackground=BG2, rowheight=24, borderwidth=0,
                    font=("Consolas", 10))
        s.configure("Treeview.Heading", background=BG3, foreground=ACCENT,
                    borderwidth=0, font=("Consolas",10,"bold"), relief="flat")
        s.map("Treeview", background=[("selected",ACCENT)],
              foreground=[("selected",BG)])
        s.map("Treeview.Heading", background=[("active",BG3)])
        s.configure("TCombobox", background=BG3, foreground=TEXT,
                    arrowcolor=ACCENT, bordercolor=BORDER,
                    fieldbackground=BG3, selectbackground=BG3,
                    selectforeground=TEXT)
        s.map("TCombobox", fieldbackground=[("readonly",BG3)],
              selectbackground=[("readonly",BG3)])
        s.configure("TScrollbar", background=BG3, troughcolor=BG2,
                    arrowcolor=DIM, bordercolor=BORDER)
        s.configure("TNotebook", background=BG2, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=DIM,
                    padding=[12,4], font=("Consolas",10))
        s.map("TNotebook.Tab", background=[("selected",BG2)],
              foreground=[("selected",ACCENT)])

    # ── UI ─────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        top = tk.Frame(self.root, bg=BG, pady=6, padx=12); top.pack(fill=tk.X)
        tk.Label(top, text="p0f", font=("Consolas",16,"bold"),
                 fg=ACCENT, bg=BG).pack(side=tk.LEFT, padx=(0,14))
        tk.Label(top, text="Passive OS Fingerprinter  .  Risk Analyser  .  WiFi Users",
                 font=("Consolas",10), fg=DIM, bg=BG).pack(side=tk.LEFT)
        self._build_ctrlbar()
        self._build_statsbar()
        self._build_main()

    def _build_ctrlbar(self):
        ctrl = tk.Frame(self.root, bg=BG2, pady=8, padx=10); ctrl.pack(fill=tk.X)

        def lbl(t, c):
            tk.Label(ctrl, text=t, fg=DIM, bg=BG2,
                     font=("Consolas",10)).grid(row=0, column=c, padx=(0,4))
        def ent(v, w, c):
            tk.Entry(ctrl, textvariable=v, width=w, bg=BG3, fg=TEXT,
                     insertbackground=TEXT, relief="flat", font=("Consolas",10),
                     highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT).grid(row=0, column=c, padx=(0,10))

        lbl("Interface:", 0)
        self._iface_var = tk.StringVar()
        self._iface_cb  = ttk.Combobox(ctrl, textvariable=self._iface_var,
                                        state="readonly", width=32,
                                        font=("Consolas",10))
        self._iface_cb.grid(row=0, column=1, padx=(0,10))
        lbl("Filter:", 2); self._filter_var = tk.StringVar(); ent(self._filter_var, 18, 3)
        lbl("PCAP:",   4); self._pcap_var   = tk.StringVar(); ent(self._pcap_var,   16, 5)
        tk.Button(ctrl, text="...", command=self._browse_pcap,
                  bg=BG3, fg=TEXT, relief="flat", cursor="hand2",
                  font=("Consolas",10), padx=4).grid(row=0, column=6, padx=(0,10))
        lbl("Log:", 7); self._logpath_var = tk.StringVar(value="p0f.log"); ent(self._logpath_var, 12, 8)
        self._promisc_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text="Promisc", variable=self._promisc_var,
                       bg=BG2, fg=TEXT, selectcolor=BG3,
                       activebackground=BG2, activeforeground=TEXT,
                       font=("Consolas",10)).grid(row=0, column=9, padx=(0,10))
        self._start_btn = tk.Button(ctrl, text="Start",
            command=self._start_capture, bg=GREEN, fg=BG,
            font=("Consolas",10,"bold"), relief="flat",
            cursor="hand2", padx=12, pady=2)
        self._start_btn.grid(row=0, column=10, padx=(0,6))
        self._stop_btn = tk.Button(ctrl, text="Stop",
            command=self._stop_capture, bg=RED, fg=BG,
            font=("Consolas",10,"bold"), relief="flat",
            cursor="hand2", padx=12, pady=2, state=tk.DISABLED)
        self._stop_btn.grid(row=0, column=11, padx=(0,6))
        tk.Button(ctrl, text="Clear", command=self._clear_all,
                  bg=BG3, fg=TEXT, font=("Consolas",10),
                  relief="flat", cursor="hand2", padx=8, pady=2
                  ).grid(row=0, column=12)

    def _build_statsbar(self):
        bar = tk.Frame(self.root, bg=BG3, pady=5, padx=10); bar.pack(fill=tk.X)
        self._stat_labels = {}
        defs = [("total","Packets",TEXT),("syn","SYN",ACCENT),
                ("syn+ack","SYN+ACK",PURPLE),("mtu","MTU",ORANGE),
                ("http","HTTP",CYAN),("matched","Matched",GREEN)]
        for col,(k,label,c) in enumerate(defs):
            f = tk.Frame(bar, bg=BG3, padx=18); f.grid(row=0, column=col)
            tk.Label(f, text=label, fg=DIM, bg=BG3, font=("Consolas",9)).pack()
            lbl = tk.Label(f, text="0", fg=c, bg=BG3, font=("Consolas",14,"bold"))
            lbl.pack(); self._stat_labels[k] = lbl
        self._status_var = tk.StringVar(value="Ready — select interface and press Start")
        tk.Label(bar, textvariable=self._status_var, fg=DIM, bg=BG3,
                 font=("Consolas",9)).grid(row=0, column=len(defs),
                 sticky="e", padx=(20,0))
        bar.columnconfigure(len(defs), weight=1)

    def _build_main(self):
        outer = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                               bg=BORDER, sashwidth=4, sashrelief="flat")
        outer.pack(fill=tk.BOTH, expand=True)
        left = tk.Frame(outer, bg=BG); outer.add(left, minsize=520)
        self._build_packet_table(left)
        right = tk.Frame(outer, bg=BG); outer.add(right, minsize=360)
        self._build_right_tabs(right)

    def _build_packet_table(self, parent):
        hdr = tk.Frame(parent, bg=BG3, pady=4, padx=8); hdr.pack(fill=tk.X)
        tk.Label(hdr, text="LIVE PACKETS", fg=ACCENT, bg=BG3,
                 font=("Consolas",10,"bold")).pack(side=tk.LEFT)
        cols = ("#","Time","Type","Source","Destination","OS / App","Dist","Link","Params")
        self._tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, [40,80,80,150,150,175,40,95,145]):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, minwidth=30, stretch=(c=="OS / App"))
        for tag,col in [("syn",ACCENT),("synack",PURPLE),("mtu",ORANGE),
                         ("http",CYAN),("matched",GREEN)]:
            self._tree.tag_configure(tag, foreground=col)
        self._tree.tag_configure("odd",  background=BG2)
        self._tree.tag_configure("even", background=BG)
        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y); hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._tree.pack(fill=tk.BOTH, expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)
        self._obs_store = {}

    def _build_right_tabs(self, parent):
        self._nb = ttk.Notebook(parent); self._nb.pack(fill=tk.BOTH, expand=True)

        # Tab 0 - Detail
        df = tk.Frame(self._nb, bg=BG); self._nb.add(df, text="  Detail  ")
        self._detail_text = scrolledtext.ScrolledText(
            df, bg=BG2, fg=TEXT, font=("Consolas",10), relief="flat",
            wrap=tk.WORD, state=tk.DISABLED, insertbackground=TEXT)
        self._detail_text.pack(fill=tk.BOTH, expand=True)
        for tag,c in [("key",ACCENT),("val",TEXT),("match",GREEN),("dim",DIM),
                       ("warn",ORANGE),("crit",RED)]:
            self._detail_text.tag_configure(tag, foreground=c)

        # Tab 1 - Risk
        rf = tk.Frame(self._nb, bg=BG); self._nb.add(rf, text="  Risk  ")
        self._build_risk_tab(rf)

        # Tab 2 - DNS & Devices
        dd = tk.Frame(self._nb, bg=BG); self._nb.add(dd, text="  DNS & Devices  ")
        self._build_dns_tab(dd)

        # Tab 3 - WiFi Users
        wu = tk.Frame(self._nb, bg=BG); self._nb.add(wu, text="  WiFi Users  ")
        self._build_wifi_users_tab(wu)

        # Tab 4 - Raw Log
        lf = tk.Frame(self._nb, bg=BG); self._nb.add(lf, text="  Raw Log  ")
        self._log_text = scrolledtext.ScrolledText(
            lf, bg=BG2, fg=DIM, font=("Consolas",9), relief="flat",
            wrap=tk.NONE, state=tk.DISABLED, insertbackground=TEXT)
        self._log_text.pack(fill=tk.BOTH, expand=True)

    # ── risk tab ───────────────────────────────────────────────────────────────
    def _build_risk_tab(self, parent):
        hdr = tk.Frame(parent, bg=BG3, pady=4, padx=8); hdr.pack(fill=tk.X)
        tk.Label(hdr, text="NETWORK DEVICE RISK RATINGS", fg=RED, bg=BG3,
                 font=("Consolas",10,"bold")).pack(side=tk.LEFT)
        tk.Button(hdr, text="Refresh", command=self._refresh_risk_table,
                  bg=BG3, fg=CYAN, relief="flat", cursor="hand2",
                  font=("Consolas",9), padx=6).pack(side=tk.RIGHT)
        risk_cols = ("IP Address","Device Name","Risk","Score","OS","Conns","Risk Bar")
        self._risk_tree = ttk.Treeview(parent, columns=risk_cols,
                                        show="headings", selectmode="browse", height=9)
        for c,w in zip(risk_cols,[120,120,65,45,130,45,140]):
            self._risk_tree.heading(c, text=c)
            self._risk_tree.column(c, width=w, minwidth=30, stretch=(c=="OS"))
        for lvl,c in RISK_COLORS.items():
            self._risk_tree.tag_configure(f"risk_{lvl}", foreground=c)
        self._risk_tree.tag_configure("odd",  background=BG2)
        self._risk_tree.tag_configure("even", background=BG)
        rvsb = ttk.Scrollbar(parent, orient="vertical", command=self._risk_tree.yview)
        self._risk_tree.configure(yscrollcommand=rvsb.set)
        rvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._risk_tree.pack(fill=tk.X)
        self._risk_tree.bind("<<TreeviewSelect>>", self._on_risk_select)
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, pady=3)
        tk.Label(parent, text="RISK BREAKDOWN  -  click a row above",
                 fg=DIM, bg=BG, font=("Consolas",9,"bold")).pack(anchor="w", padx=8)
        self._risk_detail = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=TEXT, font=("Consolas",10), relief="flat",
            wrap=tk.WORD, state=tk.DISABLED, insertbackground=TEXT, height=14)
        self._risk_detail.pack(fill=tk.BOTH, expand=True)
        for tag,c in [("ip",ACCENT),("level_SAFE",GREEN),("level_LOW",CYAN),
                       ("level_MEDIUM",YELLOW),("level_HIGH",ORANGE),
                       ("level_CRITICAL",RED),("bullet",TEXT),
                       ("advice",YELLOW),("dim",DIM)]:
            self._risk_detail.tag_configure(tag, foreground=c)
        self._risk_store = {}

    # ── DNS tab ────────────────────────────────────────────────────────────────
    def _build_dns_tab(self, parent):
        hdr = tk.Frame(parent, bg=BG3, pady=4, padx=8); hdr.pack(fill=tk.X)
        tk.Label(hdr, text="DEVICE  ->  DNS QUERIES  (websites visited)",
                 fg=CYAN, bg=BG3, font=("Consolas",10,"bold")).pack(side=tk.LEFT)
        tk.Button(hdr, text="Refresh", command=self._refresh_dns_table,
                  bg=BG3, fg=CYAN, relief="flat", cursor="hand2",
                  font=("Consolas",9), padx=6).pack(side=tk.RIGHT)
        dns_cols = ("IP Address","Device Name","OS","Domains Queried","Last Domain")
        self._dns_tree = ttk.Treeview(parent, columns=dns_cols,
                                       show="headings", selectmode="browse", height=9)
        for c,w in zip(dns_cols,[120,130,120,60,200]):
            self._dns_tree.heading(c, text=c)
            self._dns_tree.column(c, width=w, minwidth=30, stretch=(c=="Last Domain"))
        self._dns_tree.tag_configure("odd",  background=BG2)
        self._dns_tree.tag_configure("even", background=BG)
        self._dns_tree.tag_configure("suspicious", foreground=RED)
        dvsb = ttk.Scrollbar(parent, orient="vertical", command=self._dns_tree.yview)
        self._dns_tree.configure(yscrollcommand=dvsb.set)
        dvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._dns_tree.pack(fill=tk.X)
        self._dns_tree.bind("<<TreeviewSelect>>", self._on_dns_select)
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, pady=3)
        tk.Label(parent, text="LIVE DNS EVENTS",
                 fg=DIM, bg=BG, font=("Consolas",9,"bold")).pack(anchor="w", padx=8)
        self._dns_detail = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=TEXT, font=("Consolas",10), relief="flat",
            wrap=tk.WORD, state=tk.DISABLED, insertbackground=TEXT, height=14)
        self._dns_detail.pack(fill=tk.BOTH, expand=True)
        for tag,c in [("ip",ACCENT),("domain",GREEN),("suspicious",RED),
                       ("dim",DIM),("ts",PURPLE),("device",CYAN)]:
            self._dns_detail.tag_configure(tag, foreground=c)
        self._dns_store = {}

    # ══════════════════════════════════════════════════════════════════════════
    # WiFi Users Tab
    # ══════════════════════════════════════════════════════════════════════════

    def _build_wifi_users_tab(self, parent):
        # header
        hdr = tk.Frame(parent, bg=BG3, pady=5, padx=10); hdr.pack(fill=tk.X)
        tk.Label(hdr, text="WIFI USERS ON THIS NETWORK",
                 fg=GREEN, bg=BG3, font=("Consolas",10,"bold")).pack(side=tk.LEFT)
        self._scan_status = tk.Label(hdr,
                 text="Press ARP Scan to discover devices",
                 fg=DIM, bg=BG3, font=("Consolas",9))
        self._scan_status.pack(side=tk.RIGHT, padx=(0,8))
        self._scan_btn = tk.Button(hdr, text="ARP Scan",
            command=self._start_arp_scan,
            bg=ACCENT, fg=BG, font=("Consolas",10,"bold"),
            relief="flat", cursor="hand2", padx=10, pady=1)
        self._scan_btn.pack(side=tk.RIGHT, padx=(0,4))
        tk.Button(hdr, text="Refresh Table",
            command=self._refresh_wifi_table,
            bg=BG3, fg=CYAN, font=("Consolas",9),
            relief="flat", cursor="hand2", padx=8, pady=1
        ).pack(side=tk.RIGHT, padx=(0,4))

        # user table
        cols = ("IP Address","MAC Address","Vendor","Hostname",
                "OS","Risk","Pkts","Domains","First Seen","Last Seen")
        self._wifi_tree = ttk.Treeview(parent, columns=cols,
                                        show="headings", selectmode="browse", height=12)
        widths = [115,135,140,115,120,65,45,55,78,78]
        for c, w in zip(cols, widths):
            self._wifi_tree.heading(c, text=c,
                command=lambda _c=c: self._sort_wifi(_c))
            self._wifi_tree.column(c, width=w, minwidth=30,
                                   stretch=(c=="Vendor"))
        for lvl, col in RISK_COLORS.items():
            self._wifi_tree.tag_configure(f"u_{lvl}", foreground=col)
        self._wifi_tree.tag_configure("odd",  background=BG2)
        self._wifi_tree.tag_configure("even", background=BG)
        wvsb = ttk.Scrollbar(parent, orient="vertical",   command=self._wifi_tree.yview)
        whsb = ttk.Scrollbar(parent, orient="horizontal", command=self._wifi_tree.xview)
        self._wifi_tree.configure(yscrollcommand=wvsb.set, xscrollcommand=whsb.set)
        wvsb.pack(side=tk.RIGHT, fill=tk.Y)
        whsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._wifi_tree.pack(fill=tk.X)
        self._wifi_tree.bind("<<TreeviewSelect>>", self._on_wifi_select)
        self._wifi_store = {}

        # detail panel
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, pady=3)
        tk.Label(parent, text="USER DETAIL  -  click a row above",
                 fg=DIM, bg=BG, font=("Consolas",9,"bold")).pack(anchor="w", padx=8)
        self._wifi_detail = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=TEXT, font=("Consolas",10),
            relief="flat", wrap=tk.WORD,
            state=tk.DISABLED, insertbackground=TEXT, height=13)
        self._wifi_detail.pack(fill=tk.BOTH, expand=True)
        for tag, col in [
            ("ip",ACCENT), ("mac",CYAN), ("vendor",GREEN),
            ("hostname",PURPLE), ("os",GREEN), ("dim",DIM),
            ("domain",CYAN), ("susp",RED), ("bullet",TEXT),
            ("advice",YELLOW), ("safe",GREEN), ("low",CYAN),
            ("medium",YELLOW), ("high",ORANGE), ("critical",RED),
        ]:
            self._wifi_detail.tag_configure(tag, foreground=col)

    # ── ARP scan ───────────────────────────────────────────────────────────────

    def _start_arp_scan(self):
        if self._arp_scanning: return
        self._arp_scanning = True
        self._scan_btn.config(state=tk.DISABLED)
        self._scan_status.config(text="Scanning...", fg=YELLOW)
        threading.Thread(target=self._run_arp_scan, daemon=True).start()

    def _run_arp_scan(self):
        try:
            import scapy.all as sc
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

            subnets = _get_local_subnets()
            found   = {}

            for subnet in subnets:
                try:
                    ans, _ = sc.arping(str(subnet), timeout=2, verbose=False)
                    for _sent, received in ans:
                        ip  = received.psrc
                        mac = received.hwsrc.upper()
                        found[ip] = mac
                except Exception:
                    pass

            # merge passively seen ARP
            found.update(self._arp_mac)

            for ip, mac in found.items():
                self._obs_queue.put({"_wifi_user": True, "ip": ip, "mac": mac})

            self._obs_queue.put({"_scan_done": True, "count": len(found)})

        except Exception as e:
            self._obs_queue.put({"_scan_done": True, "count": 0, "error": str(e)})
        finally:
            self._arp_scanning = False
            self.root.after(0, lambda: self._scan_btn.config(state=tk.NORMAL))

    # ── passive ARP listener ───────────────────────────────────────────────────

    def _run_arp_listener(self, iface: str):
        try:
            import scapy.all as sc
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            def handler(pkt):
                if not self._running: raise KeyboardInterrupt
                if pkt.haslayer(sc.ARP) and pkt[sc.ARP].op == 2:
                    ip  = pkt[sc.ARP].psrc
                    mac = pkt[sc.ARP].hwsrc.upper()
                    if ip and mac:
                        self._arp_mac[ip] = mac
                        self._obs_queue.put({"_wifi_user": True,
                                             "ip": ip, "mac": mac})
            sc.sniff(iface=iface, filter="arp", prn=handler,
                     store=False, promisc=False)
        except KeyboardInterrupt: pass
        except Exception: pass

    # ── handle discovered WiFi user ────────────────────────────────────────────

    def _handle_wifi_user(self, ip: str, mac: str):
        now = datetime.now().strftime("%H:%M:%S")
        if ip not in self._wifi_users:
            vendor   = mac_lookup(mac)
            icon     = vendor_icon(vendor)
            hostname = self._ip_names.get(ip, "")
            if not hostname and ip not in self._ip_names:
                self._ip_names[ip] = ""
                self._resolve_queue.put(ip)
            self._wifi_users[ip] = {
                "ip": ip, "mac": mac, "vendor": vendor, "icon": icon,
                "hostname": hostname, "os": "",
                "risk_level": "SAFE", "risk_score": 0,
                "pkt_count": 0, "first_seen": now, "last_seen": now,
            }
        else:
            u = self._wifi_users[ip]
            u["mac"] = mac; u["last_seen"] = now
            u["vendor"] = mac_lookup(mac)
            u["icon"]   = vendor_icon(u["vendor"])

        # update from ip_data if available
        u = self._wifi_users[ip]
        if ip in self._ip_data:
            d = self._ip_data[ip]; r = compute_risk(d)
            u["os"]         = d.get("os") or u["os"]
            u["risk_level"] = r["level"]
            u["risk_score"] = r["score"]
            u["pkt_count"]  = d.get("conn_count", 0)
            u["hostname"]   = (d.get("device_name")
                               or self._ip_names.get(ip, u["hostname"]))
        self._refresh_wifi_table()

    # ── refresh WiFi table ─────────────────────────────────────────────────────

    def _refresh_wifi_table(self):
        for iid in self._wifi_tree.get_children():
            self._wifi_tree.delete(iid)
        self._wifi_store.clear()
        rows = sorted(self._wifi_users.values(),
                      key=lambda u: (-u["risk_score"], u["ip"]))
        for i, u in enumerate(rows):
            ip  = u["ip"]
            lvl = u.get("risk_level", "SAFE")
            vendor_disp = (u.get("icon","") + " " + u.get("vendor","Unknown")).strip()
            iid = self._wifi_tree.insert("", "end", values=(
                ip,
                u["mac"],
                vendor_disp,
                u.get("hostname","")[:18],
                (u.get("os") or "unknown")[:18],
                lvl,
                u.get("pkt_count", 0),
                len(self._ip_dns.get(ip, set())),
                u.get("first_seen",""),
                u.get("last_seen",""),
            ), tags=(f"u_{lvl}", "odd" if i % 2 else "even"))
            self._wifi_store[iid] = ip

    def _sort_wifi(self, col: str):
        key_map = {
            "IP Address":  lambda u: u["ip"],
            "MAC Address": lambda u: u["mac"],
            "Vendor":      lambda u: u.get("vendor",""),
            "Hostname":    lambda u: u.get("hostname",""),
            "OS":          lambda u: u.get("os",""),
            "Risk":        lambda u: -u.get("risk_score",0),
            "Pkts":        lambda u: -u.get("pkt_count",0),
            "Domains":     lambda u: -len(self._ip_dns.get(u["ip"],set())),
            "First Seen":  lambda u: u.get("first_seen",""),
            "Last Seen":   lambda u: u.get("last_seen",""),
        }
        if col not in key_map: return
        for iid in self._wifi_tree.get_children():
            self._wifi_tree.delete(iid)
        self._wifi_store.clear()
        rows = sorted(self._wifi_users.values(), key=key_map[col])
        for i, u in enumerate(rows):
            ip  = u["ip"]; lvl = u.get("risk_level","SAFE")
            vendor_disp = (u.get("icon","") + " " + u.get("vendor","Unknown")).strip()
            iid = self._wifi_tree.insert("","end", values=(
                ip, u["mac"], vendor_disp,
                u.get("hostname","")[:18], (u.get("os") or "unknown")[:18],
                lvl, u.get("pkt_count",0),
                len(self._ip_dns.get(ip,set())),
                u.get("first_seen",""), u.get("last_seen",""),
            ), tags=(f"u_{lvl}", "odd" if i%2 else "even"))
            self._wifi_store[iid] = ip

    def _on_wifi_select(self, event):
        sel = self._wifi_tree.selection()
        if not sel: return
        ip = self._wifi_store.get(sel[0])
        if not ip: return
        u = self._wifi_users.get(ip, {})
        d = self._ip_data.get(ip, {})
        r = compute_risk(d) if d else {"level":"SAFE","score":0,
                                       "bar":"."*20,"factors":[],"advice":[]}
        self._show_wifi_detail(ip, u, d, r)

    def _show_wifi_detail(self, ip, u, d, r):
        self._wifi_detail.config(state=tk.NORMAL)
        self._wifi_detail.delete("1.0", tk.END)
        W = self._wifi_detail

        def ins(text, tag="bullet"): W.insert(tk.END, text, tag)

        lvl = r["level"]
        ins(f"  +-- USER PROFILE {'─'*35}\n","dim")
        ins(f"  |  IP Address   : ","dim"); ins(f"{ip}\n","ip")
        ins(f"  |  MAC Address  : ","dim"); ins(f"{u.get('mac','?')}\n","mac")
        vendor = u.get("vendor","Unknown")
        ins(f"  |  Manufacturer : ","dim")
        ins(f"{u.get('icon','')} {vendor}\n","vendor")
        ins(f"  |  Hostname     : ","dim")
        host = u.get("hostname") or self._ip_names.get(ip,"") or "(resolving...)"
        ins(f"{host}\n","hostname")
        ins(f"  |  OS           : ","dim")
        ins(f"{u.get('os') or 'unknown'}\n", "os" if u.get("os") else "dim")
        ins(f"  |  First Seen   : ","dim"); ins(f"{u.get('first_seen','?')}\n","bullet")
        ins(f"  |  Last Seen    : ","dim"); ins(f"{u.get('last_seen','?')}\n","bullet")
        ins(f"  |  Connections  : ","dim"); ins(f"{u.get('pkt_count',0)}\n","bullet")

        ports = sorted(d.get("ports_seen", set()))
        ins(f"  |  Ports Seen   : ","dim")
        port_str = ", ".join(str(p) for p in ports[:10])
        if len(ports) > 10: port_str += f" ... +{len(ports)-10} more"
        ins((port_str or "none") + "\n","bullet")

        ins(f"  +-- RISK {'─'*44}\n","dim")
        ins(f"  |  Level        : ","dim")
        ins(f"{lvl}  ({r['score']}/100)\n", lvl.lower())
        ins(f"  |  Bar          : [","dim")
        ins(r["bar"].replace("X","#"), lvl.lower())
        ins("]\n","dim")

        ins(f"  +-- RISK FACTORS {'─'*36}\n","dim")
        for f_ in (r["factors"] or ["None"]):
            ins(f"  |  * {f_}\n","bullet")

        ins(f"  +-- RECOMMENDATIONS {'─'*33}\n","dim")
        for a in (r["advice"] or ["No action required"]):
            ins(f"  |  -> {a}\n","advice")

        # websites visited
        domains = sorted(self._ip_dns.get(ip, set()))
        ins(f"  +-- WEBSITES VISITED ({len(domains)}) {'─'*27}\n","dim")
        if domains:
            for dm in domains[:25]:
                susp = next((desc for pat, desc in SUSPICIOUS_DOMAINS
                             if pat in dm.lower()), None)
                ins(f"  |  * ","dim")
                ins(dm, "susp" if susp else "domain")
                if susp: ins(f"  ! {susp}","susp")
                ins("\n")
            if len(domains) > 25:
                ins(f"  |  ... and {len(domains)-25} more domains\n","dim")
        else:
            ins(f"  |  No DNS queries captured yet\n","dim")
            ins(f"  |  Start capture then browse — DNS queries appear here\n","dim")

        ins(f"  +{'─'*53}\n","dim")
        self._wifi_detail.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════════
    # Interface / capture / queue
    # ══════════════════════════════════════════════════════════════════════════

    def _load_interfaces(self):
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list(); display = []
            for iface in ifaces:
                name = iface.get("name",""); desc = iface.get("description","")
                ips  = iface.get("ips",[])
                ip   = next((i for i in ips if "." in i), ips[0] if ips else "")
                label = f"{name}  [{ip or desc[:28]}]"
                display.append(label); self._iface_map[label] = name
            self._iface_cb["values"] = display
            default = next((d for d in display
                            if "wi-fi" in d.lower() or "wifi" in d.lower()), None)
            self._iface_var.set(default or (display[0] if display else ""))
        except Exception as e:
            self._iface_cb["values"] = ["(error)"]
            self._status_var.set(f"Interface load error: {e}")

    def _browse_pcap(self):
        p = filedialog.askopenfilename(title="Open PCAP",
            filetypes=[("PCAP","*.pcap *.pcapng *.cap"),("All","*.*")])
        if p: self._pcap_var.set(p)

    def _start_capture(self):
        if self._running: return
        logpath = self._logpath_var.get().strip()
        if logpath:
            try: self._log_file = open(logpath, "a", encoding="utf-8")
            except Exception as e: messagebox.showerror("Log error", str(e)); return
        self._running = True
        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        pcap = self._pcap_var.get().strip()
        if pcap:
            self._status_var.set(f"Reading {os.path.basename(pcap)} ...")
            t = threading.Thread(target=self._run_pcap, args=(pcap,), daemon=True)
        else:
            label   = self._iface_var.get()
            iface   = self._iface_map.get(label, label.split()[0])
            filt    = self._filter_var.get().strip()
            promisc = self._promisc_var.get()
            self._status_var.set(f"Capturing on {iface} ...")
            # DNS sniffer
            self._dns_thread = threading.Thread(
                target=self._run_dns_sniffer, args=(iface, promisc), daemon=True)
            self._dns_thread.start()
            # ARP listener for passive WiFi user detection
            threading.Thread(target=self._run_arp_listener,
                             args=(iface,), daemon=True).start()
            t = threading.Thread(target=self._run_live,
                                 args=(iface, filt, promisc), daemon=True)
        self._capture_thread = t; t.start()

    def _stop_capture(self):
        self._running = False
        self._start_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED)
        self._status_var.set("Stopped.")
        if self._log_file:
            try: self._log_file.close()
            except: pass
            self._log_file = None

    def _run_live(self, iface, filt, promisc):
        try:
            import scapy.all as sc, logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            from process import process_packet
            bpf = f"tcp and ({filt})" if filt else "tcp"
            def handler(pkt):
                if not self._running: raise KeyboardInterrupt
                process_packet(pkt, self._obs_callback, self._log_file)
            sc.sniff(iface=iface, filter=bpf, prn=handler,
                     store=False, promisc=promisc)
        except KeyboardInterrupt: pass
        except Exception as e: self._obs_queue.put({"_error": str(e)})
        finally:
            self._running = False
            self.root.after(0, lambda: self._start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self._stop_btn.config(state=tk.DISABLED))

    def _run_pcap(self, path):
        try:
            import scapy.all as sc, logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            from process import process_packet
            pkts = sc.rdpcap(path)
            self._process_pcap_dns(pkts)
            self._process_pcap_arp(pkts)
            for pkt in pkts:
                if not self._running: break
                process_packet(pkt, self._obs_callback, self._log_file)
            self._obs_queue.put({"_done": f"Done - {len(pkts)} packets from {os.path.basename(path)}"})
        except Exception as e: self._obs_queue.put({"_error": str(e)})
        finally:
            self._running = False
            self.root.after(0, lambda: self._start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self._stop_btn.config(state=tk.DISABLED))

    def _process_pcap_dns(self, pkts):
        try:
            from scapy.layers.dns import DNS, DNSQR
            for pkt in pkts:
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    self._handle_dns_pkt(pkt)
        except Exception: pass

    def _process_pcap_arp(self, pkts):
        try:
            import scapy.all as sc
            for pkt in pkts:
                if pkt.haslayer(sc.ARP) and pkt[sc.ARP].op == 2:
                    ip  = pkt[sc.ARP].psrc
                    mac = pkt[sc.ARP].hwsrc.upper()
                    if ip and mac:
                        self._arp_mac[ip] = mac
                        self._obs_queue.put({"_wifi_user": True,
                                             "ip": ip, "mac": mac})
        except Exception: pass

    def _run_dns_sniffer(self, iface, promisc):
        try:
            import scapy.all as sc, logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            def handler(pkt):
                if not self._running: raise KeyboardInterrupt
                self._handle_dns_pkt(pkt)
            sc.sniff(iface=iface, filter="udp port 53",
                     prn=handler, store=False, promisc=promisc)
        except KeyboardInterrupt: pass
        except Exception: pass

    def _handle_dns_pkt(self, pkt):
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
            if not pkt.haslayer(IP): return
            dns = pkt[DNS]
            if dns.qr != 0: return
            src_ip = pkt[IP].src
            qname  = dns[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace").rstrip(".")
            if not qname: return
            self._obs_queue.put({"_dns": True, "src": src_ip, "domain": qname})
        except Exception: pass

    def _obs_callback(self, obs):
        self._obs_queue.put(obs)

    # ── queue poll ─────────────────────────────────────────────────────────────
    def _poll_queue(self):
        try:
            while True:
                obs = self._obs_queue.get_nowait()
                if "_error" in obs:
                    self._status_var.set(f"Error: {obs['_error']}")
                    messagebox.showerror("Capture error", obs["_error"])
                elif "_done" in obs:
                    self._status_var.set(obs["_done"])
                elif "_resolved" in obs:
                    ip   = obs["ip"]; name = obs["name"]
                    self._ip_names[ip] = name
                    if ip in self._ip_data:
                        self._ip_data[ip]["device_name"] = name
                    if ip in self._wifi_users:
                        self._wifi_users[ip]["hostname"] = name
                        self._refresh_wifi_table()
                elif "_dns" in obs:
                    self._handle_dns_event(obs)
                elif "_wifi_user" in obs:
                    self._handle_wifi_user(obs["ip"], obs["mac"])
                elif "_scan_done" in obs:
                    count = obs.get("count", 0)
                    err   = obs.get("error","")
                    if err:
                        self._scan_status.config(
                            text=f"Scan error: {err[:55]}", fg=RED)
                    else:
                        self._scan_status.config(
                            text=f"Scan complete - {count} device(s) found",
                            fg=GREEN)
                        self._nb.select(3)   # jump to WiFi Users tab
                else:
                    self._add_row(obs)
                    self._update_ip_data(obs)
                    # live-update any existing wifi user entry
                    ip = obs.get("src")
                    if ip and ip in self._wifi_users:
                        u = self._wifi_users[ip]
                        d = self._ip_data.get(ip, {})
                        r = compute_risk(d)
                        u["os"]         = d.get("os") or u.get("os","")
                        u["risk_level"] = r["level"]
                        u["risk_score"] = r["score"]
                        u["pkt_count"]  = d.get("conn_count", 0)
                        u["last_seen"]  = datetime.now().strftime("%H:%M:%S")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_dns_event(self, obs: dict):
        src = obs["src"]; domain = obs["domain"]
        self._ip_dns[src].add(domain)
        if src in self._ip_data:
            self._ip_data[src]["domains_queried"] = list(self._ip_dns[src])
        if src not in self._ip_names:
            self._ip_names[src] = ""
            self._resolve_queue.put(src)
        ts   = datetime.now().strftime("%H:%M:%S")
        name = self._ip_names.get(src,"")
        disp = f"[{name}]" if name else ""
        susp = next((desc for pat,desc in SUSPICIOUS_DOMAINS
                     if pat in domain.lower()), None)
        self._dns_detail.config(state=tk.NORMAL)
        self._dns_detail.insert(tk.END, f"[{ts}] ","ts")
        self._dns_detail.insert(tk.END, src,"ip")
        if disp: self._dns_detail.insert(tk.END, f"  {disp}","device")
        self._dns_detail.insert(tk.END, "  ->  ","dim")
        self._dns_detail.insert(tk.END, domain, "suspicious" if susp else "domain")
        if susp: self._dns_detail.insert(tk.END, f"  ! {susp}","suspicious")
        self._dns_detail.insert(tk.END, "\n")
        self._dns_detail.see(tk.END)
        self._dns_detail.config(state=tk.DISABLED)

    def _resolver_worker(self):
        resolved = set()
        while True:
            try:
                ip = self._resolve_queue.get(timeout=1)
                if ip in resolved: continue
                resolved.add(ip)
                name = _rdns(ip)
                if not name and _is_private(ip):
                    name = _netbios_name(ip)
                if name:
                    self._obs_queue.put({"_resolved": True,
                                         "ip": ip, "name": name})
            except queue.Empty:
                pass

    def _update_ip_data(self, obs: dict):
        for role in ("src","dst"):
            ip = obs.get(role)
            if not ip: continue
            if ip not in self._ip_data:
                self._ip_data[ip] = {
                    "ip": ip, "os": None, "dist": 0, "link_type": None,
                    "conn_count": 0, "ports_seen": set(),
                    "params_seen": [], "domains_queried": [],
                    "device_name": self._ip_names.get(ip,""),
                }
                if ip not in self._ip_names:
                    self._ip_names[ip] = ""
                    self._resolve_queue.put(ip)
            d = self._ip_data[ip]
            t = obs.get("type","")
            if t in ("syn","syn+ack") and role == "src":
                d["conn_count"] += 1
                if obs.get("os"):
                    d["os"] = obs["os"]; d["dist"] = obs.get("dist",0)
                if obs.get("params") and obs["params"] != "none":
                    d["params_seen"].append(obs["params"])
            if t == "mtu" and obs.get("link") and role == "src":
                d["link_type"] = obs["link"]
            port = obs.get("dport",0) if role=="src" else obs.get("sport",0)
            if port: d["ports_seen"].add(port)
            if "http" in t and obs.get("params") and obs["params"] != "none":
                d["params_seen"].append(obs["params"])
            if ip in self._ip_dns:
                d["domains_queried"] = list(self._ip_dns[ip])

    def _add_row(self, obs: dict):
        t = obs.get("type","?"); self._row_count += 1; self._stats["total"] += 1
        if t=="syn":        tag="syn";    self._stats["syn"]+=1
        elif t=="syn+ack":  tag="synack"; self._stats["syn+ack"]+=1
        elif t=="mtu":      tag="mtu";    self._stats["mtu"]+=1
        elif "http" in t:   tag="http";   self._stats["http"]+=1
        else:               tag="odd"
        os_str = obs.get("os") or obs.get("app") or ""
        if os_str and os_str != "?":
            self._stats["matched"] += 1; tag = "matched"
        ts  = datetime.now().strftime("%H:%M:%S")
        src = f"{obs.get('src','?')}:{obs.get('sport',0)}"
        dst = f"{obs.get('dst','?')}:{obs.get('dport',0)}"
        dist = str(obs.get("dist","")) if t not in ("mtu",) else ""
        iid = self._tree.insert("","end",
            values=(self._row_count,ts,t.upper(),src,dst,
                    os_str or "-",dist,obs.get("link",""),obs.get("params","")),
            tags=(tag,"odd" if self._row_count%2 else "even"))
        self._obs_store[iid] = obs
        for k,lbl in self._stat_labels.items(): lbl.config(text=str(self._stats[k]))
        self._tree.see(iid)
        self._append_raw_log(obs)

    def _refresh_risk_table(self):
        for iid in self._risk_tree.get_children(): self._risk_tree.delete(iid)
        self._risk_store.clear()
        scored = sorted([(ip,d,compute_risk(d)) for ip,d in self._ip_data.items()],
                        key=lambda x: x[2]["score"], reverse=True)
        for i,(ip,d,r) in enumerate(scored):
            lvl  = r["level"]
            name = (d.get("device_name") or self._ip_names.get(ip,""))[:18]
            os_s = (d.get("os") or "unknown")[:18]
            iid  = self._risk_tree.insert("","end",
                values=(ip,name,lvl,r["score"],os_s,d.get("conn_count",0),r["bar"]),
                tags=(f"risk_{lvl}","odd" if i%2 else "even"))
            self._risk_store[iid] = ip

    def _on_risk_select(self, event):
        sel = self._risk_tree.selection()
        if not sel: return
        ip = self._risk_store.get(sel[0])
        if ip and ip in self._ip_data:
            self._show_risk_detail(ip, self._ip_data[ip], compute_risk(self._ip_data[ip]))

    def _show_risk_detail(self, ip, d, r):
        self._risk_detail.config(state=tk.NORMAL)
        self._risk_detail.delete("1.0", tk.END)
        W = self._risk_detail
        def ins(t, tag="bullet"): W.insert(tk.END, t, tag)
        ins(f"  +- RISK REPORT {'─'*37}\n","dim")
        ins(f"  |  IP Address   : ","dim"); ins(f"{ip}\n","ip")
        name = d.get("device_name") or self._ip_names.get(ip,"—")
        ins(f"  |  Device Name  : ","dim"); ins(f"{name}\n","bullet")
        ins(f"  |  Risk Level   : ","dim")
        ins(f"{r['level']}  ({r['score']}/100)\n",f"level_{r['level']}")
        ins(f"  |  OS Detected  : ","dim"); ins(f"{d.get('os') or 'unknown'}\n","bullet")
        ins(f"  |  Connections  : ","dim"); ins(f"{d.get('conn_count',0)}\n","bullet")
        ports = sorted(d.get("ports_seen",set()))
        ins(f"  |  Ports Seen   : ","dim")
        ins(", ".join(str(p) for p in ports[:12])+("\n" if ports else "none\n"),"bullet")
        doms = list(d.get("domains_queried",[]))
        ins(f"  |  Domains ({len(doms):3d}) : ","dim")
        ins((", ".join(doms[:4])+("..." if len(doms)>4 else ""))+"\n","bullet")
        ins(f"  +- RISK FACTORS {'─'*33}\n","dim")
        for f_ in r["factors"]: ins(f"  |  * {f_}\n","bullet")
        ins(f"  +- RECOMMENDATIONS {'─'*30}\n","dim")
        for a in r["advice"]: ins(f"  |  -> {a}\n","advice")
        ins(f"  +{'─'*53}\n","dim")
        self._risk_detail.config(state=tk.DISABLED)

    def _refresh_dns_table(self):
        for iid in self._dns_tree.get_children(): self._dns_tree.delete(iid)
        self._dns_store.clear()
        rows = []
        for ip, domains in self._ip_dns.items():
            d    = self._ip_data.get(ip,{})
            name = d.get("device_name") or self._ip_names.get(ip,"")
            os_s = (d.get("os") or "")[:18]
            susp = any(pat in dm.lower() for dm in domains for pat,_ in SUSPICIOUS_DOMAINS)
            last = sorted(domains)[-1] if domains else ""
            rows.append((ip,name,os_s,len(domains),last,susp))
        rows.sort(key=lambda x: x[3], reverse=True)
        for i,(ip,name,os_s,cnt,last,susp) in enumerate(rows):
            tags = ["suspicious" if susp else ("odd" if i%2 else "even")]
            iid = self._dns_tree.insert("","end",
                values=(ip,name[:18],os_s,cnt,last[:50]), tags=tags)
            self._dns_store[iid] = ip

    def _on_dns_select(self, event):
        sel = self._dns_tree.selection()
        if not sel: return
        ip = self._dns_store.get(sel[0])
        if not ip: return
        domains = sorted(self._ip_dns.get(ip,set()))
        d       = self._ip_data.get(ip,{})
        name    = d.get("device_name") or self._ip_names.get(ip,"—")
        self._dns_detail.config(state=tk.NORMAL)
        self._dns_detail.delete("1.0", tk.END)
        W = self._dns_detail
        W.insert(tk.END, f"  DNS HISTORY FOR {ip} — {name}\n","ip")
        W.insert(tk.END, f"  Total queries: {len(domains)}\n","dim")
        for dm in domains:
            susp = next((desc for pat,desc in SUSPICIOUS_DOMAINS if pat in dm.lower()),None)
            W.insert(tk.END, f"  * ","dim")
            W.insert(tk.END, dm, "suspicious" if susp else "domain")
            if susp: W.insert(tk.END, f"  ! {susp}","suspicious")
            W.insert(tk.END, "\n")
        self._dns_detail.config(state=tk.DISABLED)

    def _on_row_select(self, event):
        sel = self._tree.selection()
        if not sel: return
        obs = self._obs_store.get(sel[0],{})
        self._show_packet_detail(obs)
        ip = obs.get("src")
        if ip and ip in self._ip_data:
            self._show_risk_detail(ip, self._ip_data[ip], compute_risk(self._ip_data[ip]))
            self._nb.select(1)

    def _show_packet_detail(self, obs):
        t = obs.get("type","?")
        self._detail_text.config(state=tk.NORMAL)
        self._detail_text.delete("1.0", tk.END)
        src = obs.get("src","?"); dst = obs.get("dst","?")
        name = self._ip_names.get(src,"")
        def kv(k,v,vt="val"):
            self._detail_text.insert(tk.END, f"  {k:<14}","key")
            self._detail_text.insert(tk.END, f"= {v}\n",vt)
        self._detail_text.insert(tk.END,
            f"[ {src}:{obs.get('sport',0)} -> {dst}:{obs.get('dport',0)}  ({t.upper()}) ]\n","dim")
        if name: self._detail_text.insert(tk.END, f"  device: {name}\n","dim")
        if t in ("syn","syn+ack"):
            kv("client" if t=="syn" else "server", src)
            kv("device_name", name or "-")
            kv("os", obs.get("os") or "unknown","match" if obs.get("os") else "dim")
            kv("dist",str(obs.get("dist","?")))
            kv("params",obs.get("params","none"))
            kv("raw_sig",obs.get("raw_sig",""))
        elif t == "mtu":
            kv("client",src); kv("link",obs.get("link") or "unknown")
            kv("raw_mtu",str(obs.get("raw_mtu","?")))
        elif "http" in t:
            kv("client" if t=="http request" else "server", src)
            kv("device_name",name or "-")
            kv("app",obs.get("app") or "unknown","match" if obs.get("app") else "dim")
            kv("lang",obs.get("lang") or "none")
            kv("params",obs.get("params","none"))
            kv("raw_sig",obs.get("raw_sig",""))
            if obs.get("sw"): kv("sw",obs["sw"][:100])
        domains = sorted(self._ip_dns.get(src,set()))
        if domains:
            self._detail_text.insert(tk.END,f"  Domains ({len(domains)}):\n","dim")
            for dm in domains[:8]:
                self._detail_text.insert(tk.END,f"    * {dm}\n","val")
            if len(domains)>8:
                self._detail_text.insert(tk.END,f"    ... +{len(domains)-8} more\n","dim")
        self._detail_text.config(state=tk.DISABLED)

    def _append_raw_log(self, obs):
        t  = obs.get("type","?")
        ts = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        src = f"{obs.get('src','?')}/{obs.get('sport',0)}"
        dst = f"{obs.get('dst','?')}/{obs.get('dport',0)}"
        if t in ("syn","syn+ack"):
            subj = "cli" if t=="syn" else "srv"
            line = (f"[{ts}] mod=tcp|cli={src}|srv={dst}|subj={subj}"
                    f"|os={obs.get('os') or '?'}|dist={obs.get('dist',0)}"
                    f"|params={obs.get('params','none')}"
                    f"|raw_sig={obs.get('raw_sig','')}\n")
        elif t == "mtu":
            line = (f"[{ts}] mod=mtu|cli={src}|srv={dst}"
                    f"|link={obs.get('link','?')}|raw_mtu={obs.get('raw_mtu',0)}\n")
        elif "http" in t:
            subj = "cli" if t=="http request" else "srv"
            line = (f"[{ts}] mod=http|cli={src}|srv={dst}|subj={subj}"
                    f"|app={obs.get('app') or '?'}|lang={obs.get('lang','none')}"
                    f"|params={obs.get('params','none')}"
                    f"|raw_sig={obs.get('raw_sig','')}\n")
        else:
            return
        self._log_text.config(state=tk.NORMAL)
        self._log_text.insert(tk.END, line)
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)
        if self._log_file:
            try: self._log_file.write(line); self._log_file.flush()
            except: pass

    def _clear_all(self):
        for tree in (self._tree, self._risk_tree, self._dns_tree, self._wifi_tree):
            for iid in tree.get_children(): tree.delete(iid)
        self._obs_store.clear(); self._risk_store.clear()
        self._dns_store.clear(); self._wifi_store.clear()
        self._ip_data.clear(); self._ip_dns.clear()
        self._ip_names.clear(); self._wifi_users.clear(); self._arp_mac.clear()
        self._row_count = 0
        for k in self._stats: self._stats[k] = 0
        for lbl in self._stat_labels.values(): lbl.config(text="0")
        for w in (self._log_text, self._detail_text,
                  self._risk_detail, self._dns_detail, self._wifi_detail):
            w.config(state=tk.NORMAL); w.delete("1.0",tk.END); w.config(state=tk.DISABLED)

    def _on_close(self):
        self._running = False; self._arp_scanning = False
        if self._log_file:
            try: self._log_file.close()
            except: pass
        self.root.destroy()


# ── entry point ────────────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    try:
        from fp_reader import read_fp
        fp_path = os.path.normpath(os.path.join(_HERE, "..", "p0f.fp"))
        if os.path.isfile(fp_path):
            read_fp(fp_path)
    except Exception as e:
        messagebox.showerror("Signature load error", f"Could not load p0f.fp:\n{e}")
    P0fGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
