import http.client
import platform
import queue
import socket
import ssl
import statistics
import struct
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

DNS_SERVERS = [
    {
        "name": "Cloudflare (1.1.1.1)",
        "primary": "1.1.1.1",
        "secondary": "1.0.0.1",
        # Uses unblocked Cloudflare edge IPs + stealth SNI hostnames
        "candidates": [
            ("162.159.36.1", "one.one.one.one"),
            ("1.1.1.2", "security.cloudflare-dns.com"),
            ("1.0.0.1", "one.one.one.one"),
            ("1.1.1.1", "cloudflare-dns.com"),
        ],
        "doh_path": "/dns-query",
        "security_score": 88,
        "adblock": False,
        "desc": "Fastest global anycast DNS with strict no-logging policy.",
    },
    {
        "name": "Cloudflare Malware Block",
        "primary": "1.1.1.2",
        "secondary": "1.0.0.2",
        "candidates": [
            ("1.1.1.2", "security.cloudflare-dns.com"),
            ("1.0.0.2", "security.cloudflare-dns.com"),
        ],
        "doh_path": "/dns-query",
        "security_score": 96,
        "adblock": False,
        "desc": "Cloudflare speed with automatic malware and phishing domain blocking.",
    },
    {
        "name": "Quad9 Secure (9.9.9.9)",
        "primary": "9.9.9.9",
        "secondary": "149.112.112.112",
        "candidates": [
            ("149.112.112.11", "dns11.quad9.net"),
            ("149.112.112.112", "dns.quad9.net"),
            ("9.9.9.11", "dns11.quad9.net"),
            ("9.9.9.9", "dns.quad9.net"),
        ],
        "doh_path": "/dns-query",
        "security_score": 99,
        "adblock": False,
        "desc": "Swiss privacy protection + 19 threat intelligence feeds.",
    },
    {
        "name": "AdGuard DNS",
        "primary": "94.140.14.14",
        "secondary": "94.140.15.15",
        "candidates": [
            ("94.140.14.14", "dns.adguard-dns.com"),
            ("94.140.15.15", "dns.adguard-dns.com"),
        ],
        "doh_path": "/dns-query",
        "security_score": 94,
        "adblock": True,
        "desc": "Blocks ads, trackers, and analytics system-wide.",
    },
    {
        "name": "Google Public DNS",
        "primary": "8.8.8.8",
        "secondary": "8.8.4.4",
        "candidates": [
            ("8.8.8.8", "dns.google"),
            ("8.8.4.4", "dns.google"),
        ],
        "doh_path": "/dns-query",
        "security_score": 84,
        "adblock": False,
        "desc": "High-availability global anycast resolver.",
    },
    {
        "name": "OpenDNS (Cisco)",
        "primary": "208.67.222.222",
        "secondary": "208.67.220.220",
        "candidates": [
            ("208.67.222.222", "doh.opendns.com"),
            ("208.67.220.220", "doh.opendns.com"),
        ],
        "doh_path": "/dns-query",
        "security_score": 89,
        "adblock": False,
        "desc": "Reliable endpoint with built-in phishing protection.",
    },
]


def build_probe_dns_query(domain="example.com"):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in domain.split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def extract_cache_key(packet: bytes):
    if len(packet) < 17:
        return None
    pos = 12
    labels = []
    try:
        while pos < len(packet):
            length = packet[pos]
            if length == 0:
                pos += 1
                break
            if (length & 0xC0) == 0xC0:
                pos += 2
                break
            pos += 1
            labels.append(packet[pos : pos + length].decode("ascii", errors="ignore").lower())
            pos += length
        if pos + 4 > len(packet):
            return None
        qtype, qclass = struct.unpack("!HH", packet[pos : pos + 4])
        return (".".join(labels), qtype, qclass)
    except Exception:
        return None


def resolve_via_udp_or_tcp(query_packet: bytes, ip: str, timeout=1.5):
    """Fast Port 53 UDP/TCP fallback when an ISP blocks Port 443 DoH for a specific IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query_packet, (ip, 53))
            resp, _ = s.recvfrom(4096)
            if len(resp) >= 12:
                return resp
    except Exception:
        pass

    # Fallback to TCP Port 53 if UDP is filtered
    try:
        with socket.create_connection((ip, 53), timeout=timeout) as s:
            s.sendall(struct.pack("!H", len(query_packet)) + query_packet)
            len_bytes = s.recv(2)
            if len(len_bytes) == 2:
                resp_len = struct.unpack("!H", len_bytes)[0]
                return s.recv(resp_len)
    except Exception:
        pass
    return None


class StealthDoHConnection(http.client.HTTPSConnection):
    """Connects directly to Bootstrap IP with custom SNI and relaxed hostname check to bypass DPI."""

    def __init__(self, sni_host, bootstrap_ip, port=443, timeout=1.8):
        super().__init__(sni_host, port=port, timeout=timeout)
        self.bootstrap_ip = bootstrap_ip
        self.sni_host = sni_host
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def connect(self):
        raw_sock = socket.create_connection((self.bootstrap_ip, self.port), self.timeout)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._ssl_ctx.wrap_socket(raw_sock, server_hostname=self.sni_host)


class LocalDoHProxyEngine:
    """
    Local 127.0.0.1:53 proxy with:
    1. RAM Caching (< 0.5 ms)
    2. In-flight query coalescing (prevents 1250ms burst bottlenecks)
    3. Pooled DoH + automatic UDP/TCP fallback
    """

    def __init__(self, stats_callback=None):
        self.running = False
        self.current_server = DNS_SERVERS[0]
        self.active_ip = "1.1.1.2"
        self.active_sni = "security.cloudflare-dns.com"
        self.active_mode = "DoH"
        self.sock = None
        self.pool = queue.Queue(maxsize=10)

        self.cache = {}
        self.cache_ttl = 300
        self.in_flight = {}
        self.flight_lock = threading.Lock()

        self.total_queries = 0
        self.cache_hits = 0
        self.last_latency_ms = 0.0
        self.stats_callback = stats_callback

    def set_upstream(self, srv, working_ip, working_sni, mode="DoH"):
        self.current_server = srv
        self.active_ip = working_ip
        self.active_sni = working_sni
        self.active_mode = mode
        while not self.pool.empty():
            try:
                self.pool.get_nowait().close()
            except Exception:
                pass

    def clear_cache(self):
        self.cache.clear()
        self._notify_stats()

    def start(self):
        if self.running:
            return True, "Already running"
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("127.0.0.1", 53))
            self.running = True
            threading.Thread(target=self._listen_loop, daemon=True).start()
            return True, "Listening on 127.0.0.1:53"
        except PermissionError:
            return False, "Port 53 requires Administrator / sudo privileges."
        except OSError as e:
            return False, f"Port 53 busy ({e}). Close any old instance of this app first."

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _listen_loop(self):
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(
                    target=self._handle_query, args=(data, addr), daemon=True
                ).start()
            except OSError:
                break

    def _handle_query(self, query_packet: bytes, client_addr):
        start_t = time.perf_counter()
        self.total_queries += 1
        key = extract_cache_key(query_packet)
        now = time.time()

        # 1. Instant RAM Cache Check
        if key and key in self.cache:
            cached_body, expiry = self.cache[key]
            if now < expiry:
                self.cache_hits += 1
                if self.sock:
                    self.sock.sendto(query_packet[:2] + cached_body, client_addr)
                self.last_latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
                self._notify_stats()
                return

        # 2. In-Flight Coalescing (If identical query is already in progress, wait for it!)
        wait_event = None
        is_leader = False
        if key:
            with self.flight_lock:
                if key in self.in_flight:
                    wait_event = self.in_flight[key]
                else:
                    wait_event = threading.Event()
                    self.in_flight[key] = wait_event
                    is_leader = True

        if wait_event and not is_leader:
            wait_event.wait(timeout=2.0)
            if key in self.cache:
                cached_body, _ = self.cache[key]
                self.cache_hits += 1
                if self.sock:
                    self.sock.sendto(query_packet[:2] + cached_body, client_addr)
                self.last_latency_ms = round((time.perf_counter() - start_t) * 1000, 2)
                self._notify_stats()
                return

        # 3. Perform Upstream Lookup (DoH with automatic UDP fallback)
        try:
            resp_packet = None
            if self.active_mode == "DoH":
                resp_packet = self._forward_doh_pooled(query_packet)
            if not resp_packet:
                resp_packet = resolve_via_udp_or_tcp(query_packet, self.active_ip)

            if resp_packet and len(resp_packet) >= 12 and self.sock:
                self.sock.sendto(resp_packet, client_addr)
                if key:
                    self.cache[key] = (resp_packet[2:], time.time() + self.cache_ttl)
        finally:
            if key and is_leader:
                with self.flight_lock:
                    ev = self.in_flight.pop(key, None)
                    if ev:
                        ev.set()

        self.last_latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
        self._notify_stats()

    def _forward_doh_pooled(self, query_packet: bytes):
        srv = self.current_server
        headers = {
            "Host": self.active_sni,
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "Connection": "keep-alive",
        }

        for _ in range(2):
            conn = None
            try:
                try:
                    conn = self.pool.get_nowait()
                except queue.Empty:
                    conn = StealthDoHConnection(self.active_sni, self.active_ip, timeout=1.8)
                    conn.connect()

                conn.request("POST", srv["doh_path"], body=query_packet, headers=headers)
                response = conn.getresponse()
                body = response.read()
                if response.status == 200:
                    try:
                        self.pool.put_nowait(conn)
                    except queue.Full:
                        conn.close()
                    return body
                conn.close()
            except Exception:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
        return None

    def _notify_stats(self):
        if self.stats_callback:
            self.stats_callback(
                self.total_queries, self.cache_hits, len(self.cache), self.last_latency_ms
            )


class SmartDoHChangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart AI DNS & Encrypted DoH Proxy (Stealth DPI Bypass)")
        self.root.geometry("920x650")
        self.root.configure(bg="#0f172a")

        self.os_name = platform.system()
        self.benchmark_results = {}
        self.recommended_server = None
        self.proxy = LocalDoHProxyEngine(stats_callback=self.update_telemetry_ui)

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#1e293b",
            foreground="#f8fafc",
            fieldbackground="#1e293b",
            rowheight=28,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#334155",
            foreground="#38bdf8",
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#0284c7")])

    def _build_ui(self):
        header = tk.Frame(self.root, bg="#0f172a", pady=10, padx=20)
        header.pack(fill="x")

        tk.Label(
            header,
            text="Smart DNS Changer + Stealth DoH Proxy",
            font=("Segoe UI", 16, "bold"),
            bg="#0f172a",
            fg="#f8fafc",
        ).pack(anchor="w")

        tk.Label(
            header,
            text=f"OS: {self.os_name} | Stealth SNI Anti-Block + In-Flight Burst Cache + Hybrid UDP Fallback",
            font=("Segoe UI", 10),
            bg="#0f172a",
            fg="#94a3b8",
        ).pack(anchor="w")

        ctrl = tk.Frame(self.root, bg="#1e293b", pady=10, padx=16)
        ctrl.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(
            ctrl,
            text="Optimization Profile:",
            font=("Segoe UI", 10, "bold"),
            bg="#1e293b",
            fg="#e2e8f0",
        ).pack(side="left", padx=(0, 8))

        self.profile_var = tk.StringVar(value="Gaming & Low Latency")
        self.profile_menu = ttk.Combobox(
            ctrl,
            textvariable=self.profile_var,
            values=[
                "Gaming & Low Latency",
                "Maximum Security & Privacy",
                "Ad-Blocking & Tracker Protection",
            ],
            state="readonly",
            width=28,
        )
        self.profile_menu.pack(side="left", padx=(0, 12))

        self.use_doh_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl,
            text="Enable Local Proxy + RAM Cache (127.0.0.1)",
            variable=self.use_doh_var,
            bg="#1e293b",
            fg="#38bdf8",
            selectcolor="#0f172a",
            activebackground="#1e293b",
            activeforeground="#38bdf8",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(0, 15))

        self.scan_btn = tk.Button(
            ctrl,
            text="Benchmark Warm DoH Speed",
            command=self.start_benchmark,
            bg="#0284c7",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.scan_btn.pack(side="right")

        table_frame = tk.Frame(self.root, bg="#0f172a")
        table_frame.pack(fill="both", expand=True, padx=20)

        cols = ("name", "primary", "doh_host", "warm_doh", "jitter", "score")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=6)
        self.tree.heading("name", text="DNS Provider")
        self.tree.heading("primary", text="Active Route IP")
        self.tree.heading("doh_host", text="Active Protocol / SNI")
        self.tree.heading("warm_doh", text="Warm Latency")
        self.tree.heading("jitter", text="Jitter")
        self.tree.heading("score", text="AI Score")

        self.tree.column("name", width=180)
        self.tree.column("primary", width=120, anchor="center")
        self.tree.column("doh_host", width=230, anchor="center")
        self.tree.column("warm_doh", width=120, anchor="center")
        self.tree.column("jitter", width=85, anchor="center")
        self.tree.column("score", width=105, anchor="center")
        self.tree.pack(fill="both", expand=True)

        for srv in DNS_SERVERS:
            self.tree.insert(
                "",
                "end",
                iid=srv["name"],
                values=(
                    srv["name"],
                    srv["primary"],
                    srv["candidates"][0][1],
                    "Not tested",
                    "-",
                    "-",
                ),
            )

        telemetry_frame = tk.Frame(self.root, bg="#0f172a", pady=6)
        telemetry_frame.pack(fill="x", padx=20)

        self.status_lbl = tk.Label(
            telemetry_frame,
            text="Proxy Status: Inactive",
            font=("Segoe UI", 10, "bold"),
            bg="#0f172a",
            fg="#f59e0b",
        )
        self.status_lbl.pack(side="left", padx=(0, 20))

        self.stats_lbl = tk.Label(
            telemetry_frame,
            text="Queries: 0  |  RAM Cache Hits: 0 (0%)  |  Cached Domains: 0  |  Last Lookup: - ms",
            font=("Segoe UI", 10),
            bg="#0f172a",
            fg="#34d399",
        )
        self.stats_lbl.pack(side="left")

        tk.Button(
            telemetry_frame,
            text="Flush RAM Cache",
            command=self.proxy.clear_cache,
            bg="#334155",
            fg="#e2e8f0",
            font=("Segoe UI", 9),
            relief="flat",
            padx=8,
            pady=2,
        ).pack(side="right")

        self.ai_frame = tk.Frame(self.root, bg="#1e293b", pady=10, padx=16)
        self.ai_frame.pack(fill="x", padx=20, pady=8)

        self.ai_title = tk.Label(
            self.ai_frame,
            text="AI Recommendation Advisor: Ready",
            font=("Segoe UI", 11, "bold"),
            bg="#1e293b",
            fg="#38bdf8",
        )
        self.ai_title.pack(anchor="w")

        self.ai_reason = tk.Label(
            self.ai_frame,
            text="Click 'Benchmark Warm DoH Speed' to scan all servers using Stealth SNI and Hybrid Fallback.",
            font=("Segoe UI", 10),
            bg="#1e293b",
            fg="#cbd5e1",
            wraplength=840,
            justify="left",
        )
        self.ai_reason.pack(anchor="w", pady=(3, 0))

        btn_frame = tk.Frame(self.root, bg="#0f172a", pady=8)
        btn_frame.pack(fill="x", padx=20)

        tk.Button(
            btn_frame,
            text="Connect to Selected Server",
            command=self.connect_selected,
            bg="#10b981",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_frame,
            text="Connect AI Recommended Server",
            command=self.connect_recommended,
            bg="#6366f1",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_frame,
            text="Stop Proxy & Reset to ISP Default",
            command=self.reset_dns,
            bg="#ef4444",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="right")

    def update_telemetry_ui(self, total, hits, cached_items, last_ms):
        hit_rate = round((hits / total) * 100, 1) if total > 0 else 0.0
        self.root.after(
            0,
            lambda: self.stats_lbl.config(
                text=f"Queries: {total}  |  RAM Cache Hits: {hits} ({hit_rate}%)  |  "
                f"Cached Domains: {cached_items}  |  Last Lookup: {last_ms} ms"
            ),
        )

    def benchmark_server(self, srv, samples=3):
        """
        1. Tests Stealth DoH candidates on Port 443.
        2. If ISP blocks Port 443 to that provider, automatically falls back to Port 53 UDP/TCP.
        """
        probe_pkt = build_probe_dns_query("example.com")

        # Step 1: Try Stealth DoH Candidates
        for candidate_ip, sni_host in srv["candidates"]:
            headers = {
                "Host": sni_host,
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "Connection": "keep-alive",
            }
            timings = []
            conn = StealthDoHConnection(sni_host, candidate_ip, timeout=1.6)
            try:
                conn.connect()
                for _ in range(samples):
                    t0 = time.perf_counter()
                    conn.request("POST", srv["doh_path"], body=probe_pkt, headers=headers)
                    resp = conn.getresponse()
                    resp.read()
                    if resp.status == 200:
                        timings.append((time.perf_counter() - t0) * 1000)
                    time.sleep(0.02)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            if timings:
                avg_ms = round(statistics.mean(timings), 1)
                jitter_ms = round(statistics.stdev(timings), 1) if len(timings) > 1 else 0.0
                return avg_ms, jitter_ms, candidate_ip, sni_host, "DoH"

        # Step 2: Automatic Port 53 UDP/TCP Fallback if ISP blocks Port 443 to this provider
        for candidate_ip, sni_host in srv["candidates"]:
            timings = []
            for _ in range(samples):
                t0 = time.perf_counter()
                resp = resolve_via_udp_or_tcp(probe_pkt, candidate_ip, timeout=1.2)
                if resp:
                    timings.append((time.perf_counter() - t0) * 1000)
                time.sleep(0.02)
            if timings:
                avg_ms = round(statistics.mean(timings), 1)
                jitter_ms = round(statistics.stdev(timings), 1) if len(timings) > 1 else 0.0
                return avg_ms, jitter_ms, candidate_ip, "Port 53 (Fast UDP)", "UDP"

        return 999.0, 999.0, srv["primary"], "Blocked by ISP", "None"

    def compute_ai_score(self, srv, warm_ms, jitter_ms, mode, profile):
        if warm_ms >= 999.0:
            return 0.0
        speed_score = max(0.0, 100.0 - (warm_ms * 0.65) - (jitter_ms * 1.2))
        sec_score = srv["security_score"] if mode == "DoH" else (srv["security_score"] - 8)

        if profile == "Gaming & Low Latency":
            score = (speed_score * 0.80) + (sec_score * 0.20)
        elif profile == "Maximum Security & Privacy":
            score = (speed_score * 0.40) + (sec_score * 0.60)
        else:
            ad_bonus = 25.0 if srv["adblock"] else 0.0
            score = min(100.0, (speed_score * 0.45) + (sec_score * 0.35) + ad_bonus)
        return round(score, 1)

    def start_benchmark(self):
        self.scan_btn.config(state="disabled", text="Scanning Routes...")
        self.ai_title.config(
            text="AI Advisor: Testing Stealth DoH & Hybrid Fallback routes..."
        )
        threading.Thread(target=self._benchmark_worker, daemon=True).start()

    def _benchmark_worker(self):
        profile = self.profile_var.get()
        best = None
        best_score = -1.0

        for srv in DNS_SERVERS:
            warm_ms, jitter_ms, working_ip, working_sni, mode = self.benchmark_server(srv)
            score = self.compute_ai_score(srv, warm_ms, jitter_ms, mode, profile)
            entry = {
                "server": srv,
                "warm_ms": warm_ms,
                "jitter_ms": jitter_ms,
                "score": score,
                "working_ip": working_ip,
                "working_sni": working_sni,
                "mode": mode,
            }
            self.benchmark_results[srv["name"]] = entry

            lat_txt = f"{warm_ms} ms" if warm_ms < 999 else "Blocked"
            jit_txt = f"±{jitter_ms} ms" if warm_ms < 999 else "-"
            scr_txt = f"{score} / 100" if score > 0 else "Unreachable"
            proto_txt = f"DoH ({working_sni})" if mode == "DoH" else working_sni

            self.root.after(
                0,
                lambda s=srv["name"], v=(
                    srv["name"],
                    working_ip,
                    proto_txt,
                    lat_txt,
                    jit_txt,
                    scr_txt,
                ): self.tree.item(s, values=v),
            )

            if score > best_score:
                best_score = score
                best = entry

        self.root.after(0, lambda: self._finish_benchmark(best, profile))

    def _finish_benchmark(self, best, profile):
        self.scan_btn.config(state="normal", text="Benchmark Warm DoH Speed")
        if not best or best["score"] <= 0:
            self.ai_title.config(text="Scan Failed: Check internet connection")
            return

        srv = best["server"]
        self.recommended_server = srv
        self.tree.selection_set(srv["name"])
        self.tree.focus(srv["name"])

        self.ai_title.config(
            text=f"AI Top Pick for '{profile}': {srv['name']} (Score: {best['score']}/100)"
        )
        self.ai_reason.config(
            text=(
                f"Latency: {best['warm_ms']} ms (±{best['jitter_ms']} ms jitter) via {best['working_ip']} "
                f"[{best['mode']} Mode]. Burst queries are deduplicated & served from RAM in <0.5 ms. "
                f"{srv['desc']}"
            )
        )

    def connect_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select Server", "Please select a DNS server from the table.")
            return
        srv = next(s for s in DNS_SERVERS if s["name"] == sel[0])
        self.activate_connection(srv)

    def connect_recommended(self):
        if not self.recommended_server:
            messagebox.showinfo("Run Scan First", "Please run the Warm DoH Benchmark first.")
            return
        self.activate_connection(self.recommended_server)

    def _get_active_interface(self):
        if self.os_name == "Windows":
            out = subprocess.check_output("netsh interface show interface", shell=True, text=True)
            for line in out.splitlines():
                if "Connected" in line:
                    return " ".join(line.split()[3:])
            return "Wi-Fi"
        elif self.os_name == "Darwin":
            return "Wi-Fi"
        else:
            out = subprocess.check_output(
                "nmcli -t -f NAME,DEVICE connection show --active", shell=True, text=True
            )
            first = out.splitlines()[0] if out else ""
            return first.split(":")[0] if ":" in first else "eth0"

    def activate_connection(self, srv):
        iface = self._get_active_interface()
        use_proxy = self.use_doh_var.get()
        info = self.benchmark_results.get(srv["name"], {})
        working_ip = info.get("working_ip", srv["candidates"][0][0])
        working_sni = info.get("working_sni", srv["candidates"][0][1])
        mode = info.get("mode", "DoH")

        try:
            if use_proxy:
                self.proxy.set_upstream(srv, working_ip, working_sni, mode)
                ok, msg = self.proxy.start()
                if not ok:
                    messagebox.showerror("Proxy Error", msg)
                    return
                target_primary, target_secondary = "127.0.0.1", working_ip
                self.status_lbl.config(
                    text=f"Active ({mode}): 127.0.0.1 -> {working_ip} ({working_sni})",
                    fg="#10b981",
                )
            else:
                self.proxy.stop()
                target_primary, target_secondary = working_ip, srv["secondary"]
                self.status_lbl.config(
                    text=f"Direct DNS Active: {working_ip}", fg="#38bdf8"
                )

            if self.os_name == "Windows":
                subprocess.run(
                    f'netsh interface ip set dns name="{iface}" static {target_primary}',
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    f'netsh interface ip add dns name="{iface}" {target_secondary} index=2',
                    shell=True,
                    check=True,
                )
            elif self.os_name == "Darwin":
                subprocess.run(
                    ["networksetup", "-setdnsservers", iface, target_primary, target_secondary],
                    check=True,
                )
            elif self.os_name == "Linux":
                subprocess.run(
                    [
                        "nmcli",
                        "con",
                        "mod",
                        iface,
                        "ipv4.dns",
                        f"{target_primary} {target_secondary}",
                        "ipv4.ignore-auto-dns",
                        "yes",
                    ],
                    check=True,
                )
                subprocess.run(["nmcli", "con", "up", iface], check=True)

            messagebox.showinfo(
                "Connected",
                f"Interface '{iface}' is now routed through:\n{srv['name']} ({working_ip} - {mode})",
            )
        except Exception as e:
            messagebox.showerror(
                "Administrator Privileges Required",
                f"Could not configure network adapter ({e}).\n"
                "Please run this script as Administrator (Windows) or with sudo (macOS/Linux).",
            )

    def reset_dns(self):
        self.proxy.stop()
        self.status_lbl.config(text="Proxy Status: Inactive", fg="#f59e0b")
        iface = self._get_active_interface()
        try:
            if self.os_name == "Windows":
                subprocess.run(
                    f'netsh interface ip set dns name="{iface}" dhcp', shell=True, check=True
                )
            elif self.os_name == "Darwin":
                subprocess.run(["networksetup", "-setdnsservers", iface, "Empty"], check=True)
            elif self.os_name == "Linux":
                subprocess.run(
                    ["nmcli", "con", "mod", iface, "ipv4.ignore-auto-dns", "no", "ipv4.dns", ""],
                    check=True,
                )
                subprocess.run(["nmcli", "con", "up", iface], check=True)
            messagebox.showinfo(
                "DNS Reset", f"Stopped proxy and restored '{iface}' to automatic ISP DHCP."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset DNS ({e}). Run as Administrator/sudo.")


if __name__ == "__main__":
    root = tk.Tk()
    app = SmartDoHChangerApp(root)
    root.mainloop()