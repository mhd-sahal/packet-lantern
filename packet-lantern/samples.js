/* Fictional demo captures. Only private (192.168/10) and documentation
   (198.51.100/203.0.113) addresses are used. No real infrastructure. */
(function (root) {
  const HEAD = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
  const esc = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));

  function build(kind) {
    const rows = [];
    let t = 0;
    const add = (s, d, p, l, i) => {
      t += 0.004 + ((rows.length * 7) % 11) / 400;
      rows.push([rows.length + 1, t.toFixed(6), s, d, p, l, i]);
    };
    const flow = (s, d, port, n, len) => {
      add(s, d, "TCP", 74, `50000 → ${port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`);
      for (let i = 1; i < n; i++) add(s, d, "TCP", len, `${50000} → ${port} [ACK] Seq=${i} Ack=1 Win=502 Len=${len - 66}`);
    };
    const background = () => {
      ["192.168.1.10", "192.168.1.11", "192.168.1.12"].forEach((c, k) => {
        for (let i = 0; i < 4; i++) add(c, "192.168.1.1", "DNS", 74, `Standard query 0x${(4096 + k * 16 + i).toString(16)} A www.example.com`);
        add(c, "ff:ff:ff:ff:ff:ff", "ARP", 42, `Who has 192.168.1.1? Tell ${c}`);
        flow(c, "203.0.113.10", 443, 14, 600 + k * 100);
        for (let i = 0; i < 6; i++) add(c, "198.51.100.20", "HTTP", 300, "GET /index.html HTTP/1.1");
      });
      for (let i = 0; i < 3; i++) add("192.168.1.10", "192.168.1.1", "ICMP", 98, `Echo (ping) request  id=0x0001, seq=${i + 1}/256, ttl=64`);
    };
    background();
    if (kind === "high") flow("192.168.1.25", "203.0.113.50", 443, 183, 1514);
    if (kind === "mixed") {
      flow("192.168.1.25", "203.0.113.50", 443, 70, 1514);
      for (let i = 0; i < 45; i++) add("192.168.1.40", "192.168.1.1", "ICMP", 98, `Echo (ping) request  id=0x0002, seq=${i + 1}/256, ttl=64`);
      for (let i = 1; i <= 24; i++) add("192.168.1.50", `10.0.0.${i}`, "TCP", 74, `${49152 + i} → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`);
      for (let p = 20; p < 34; p++) add("192.168.1.60", "10.0.0.5", "TCP", 74, `50100 → ${p} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`);
    }
    return [HEAD].concat(rows).map((r) => r.map(esc).join(",")).join("\n") + "\n";
  }

  const SAMPLES = { normal: build("normal"), high: build("high"), mixed: build("mixed") };
  if (typeof module !== "undefined") module.exports = SAMPLES;
  else root.SAMPLES = SAMPLES;
})(typeof window !== "undefined" ? window : globalThis);
