"use strict";
/* Packet Lantern: all analysis runs locally. This file makes no network requests.
   Untrusted CSV text is only ever inserted with textContent, never as HTML. */

const DEFAULTS = { pkts: 50, dests: 10, ports: 10, icmp: 30, dns: 30, pair: 40, syn: 20 };
const SEV = ["Informational", "Low", "Medium", "High"];
const PTS = [5, 10, 20, 30];
const MAX_ROWS = 200000, MAX_BYTES = 50 * 1024 * 1024;
const ALIASES = {
  src: ["source", "source ip", "source address", "src", "src ip", "src address", "ip.src", "ipv4.src"],
  dst: ["destination", "destination ip", "destination address", "dst", "dst ip", "dst address", "ip.dst", "ipv4.dst"],
  proto: ["protocol", "proto", "_ws.col.protocol", "ip.proto"],
  len: ["length", "len", "frame.len", "packet length", "bytes"],
  info: ["info", "information", "_ws.col.info"],
};
const BASE_STEPS = [
  "Identify the device that owns this address (asset inventory, DHCP leases).",
  "Decide whether this behaviour is expected for that device.",
  "Review the protocols and destination ports involved.",
  "Check whether the source is an authorised scanner or admin tool.",
  "Look at endpoint, firewall or DNS logs for the same time period.",
];
const RULES = {
  vol: { name: "High activity host", why: "A host sending far more traffic than its peers may be doing something unexpected, and it deserves a closer look.",
    benign: ["file transfer or backup", "software updates", "streaming or video calls", "automated scripts", "misconfiguration", "network scanning or other unwanted activity"], first: "Compare this host's volume with what is normal for its role." },
  scan: { name: "Possible host scanning", why: "One host talking to many different destinations in a short capture can be consistent with host discovery or network scanning.",
    benign: ["network management software", "vulnerability scanner", "asset discovery system", "monitoring software"], first: "Check whether the destinations form an address range (for example consecutive addresses)." },
  port: { name: "Possible port scanning", why: "One source contacting many different ports on the same destination can sometimes indicate port scanning.",
    benign: ["legitimate service discovery", "applications using many ports", "an administrator troubleshooting"], first: "List the ports and ask whether the destination normally offers them." },
  icmp: { name: "High ICMP activity", why: "A large number of ICMP packets from one host may indicate ping sweeps or discovery, but ICMP is also a normal diagnostic tool.",
    benign: ["troubleshooting with ping", "network monitoring", "ping sweeps or network discovery", "denial-of-service activity (less common)"], first: "Look at whether the ICMP goes to one target or many." },
  dns: { name: "High DNS activity", why: "Many DNS packets from one host could be ordinary use, or automated lookups such as beaconing.",
    benign: ["normal web browsing", "software updates", "automated applications", "misconfigured systems", "suspicious beaconing or automated lookups"], first: "Review which domain names are being requested (in Wireshark, filter on dns)." },
  pair: { name: "Repeated source-to-destination communication", why: "Many packets between the same two hosts may be normal application traffic, or automated activity worth understanding.",
    benign: ["a normal long-lived application session", "backups or file sync", "database or API traffic", "automated activity"], first: "Confirm what service the destination provides." },
  syn: { name: "TCP SYN heavy activity", why: "Many connection-opening (SYN) packets can come from ordinary connection attempts, but also from scanning or SYN flood behaviour. This tool does not decide which.",
    benign: ["normal connection attempts", "an unavailable service being retried", "network scanning", "SYN flood behaviour (less common)"], first: "Check whether the SYNs get answered (SYN, ACK) or are ignored." },
};

/* ---------- parsing ---------- */
function parseCSV(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], f = "", q = false;
  const endRow = () => { row.push(f); f = ""; if (row.length > 1 || row[0] !== "") rows.push(row); row = []; if (rows.length > MAX_ROWS + 1) throw new Error("This file has more than " + MAX_ROWS + " rows. Export a smaller capture or filter it in Wireshark first."); };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"' && f === "") q = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; endRow(); }
    else f += c;
  }
  if (f !== "" || row.length) endRow();
  return { rows, openQuote: q };
}
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9._ ]/g, " ").replace(/\s+/g, " ").trim();
function mapColumns(header) {
  const n = header.map(norm), idx = {};
  for (const k in ALIASES) idx[k] = n.findIndex((x) => ALIASES[k].includes(x));
  return idx;
}
function group(p) {
  const u = String(p || "").toUpperCase();
  if (!u) return "Other";
  if (u === "DNS" || u === "MDNS") return "DNS";
  if (u.startsWith("ICMP")) return "ICMP";
  if (u === "ARP") return "ARP";
  if (u === "HTTP" || u.startsWith("HTTP/")) return "HTTP";
  if (u.startsWith("TLS") || u === "SSL" || u === "HTTPS") return "HTTPS/TLS";
  return u === "TCP" || u === "UDP" ? u : "Other";
}
function buildPackets(rows, idx) {
  const get = (r, i) => (i >= 0 && r[i] !== undefined ? r[i].trim() : "");
  return rows.slice(1).map((r) => {
    const info = get(r, idx.info), m = /(\d{1,5})\s*(?:→|->|>)\s*(\d{1,5})/.exec(info), len = parseFloat(get(r, idx.len));
    return { src: get(r, idx.src), dst: get(r, idx.dst), proto: get(r, idx.proto), g: group(get(r, idx.proto)), len: isNaN(len) ? null : len,
      dport: m ? +m[2] : null, syn: /\[SYN\]/.test(info), hasFlags: /\[[A-Z, ]+\]/.test(info) };
  });
}

/* ---------- analysis ---------- */
const inc = (m, k, n = 1) => m.set(k, (m.get(k) || 0) + n);
const setOf = (m, k) => { if (!m.has(k)) m.set(k, new Set()); return m.get(k); };
const topN = (m, n = 10) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
const sevOf = (v, t, cap = 3) => Math.min(cap, v >= t * 5 ? 3 : v >= t * 2 ? 2 : v >= t * 1.25 ? 1 : 0);

function analyse(pk, has, th) {
  const srcC = new Map(), dstC = new Map(), gC = new Map(), pair = new Map(), srcDst = new Map(), srcG = new Map(),
    icmp = new Map(), dns = new Map(), syn = new Map(), synDst = new Map(), ports = new Map();
  let lenSum = 0, lenN = 0, portPk = 0, flagPk = 0;
  for (const p of pk) {
    if (p.len !== null) { lenSum += p.len; lenN++; }
    inc(gC, p.g);
    if (p.dst) inc(dstC, p.dst);
    if (!p.src) continue;
    inc(srcC, p.src); setOf(srcG, p.src).add(p.g);
    if (p.dst) {
      setOf(srcDst, p.src).add(p.dst);
      const k = p.src + "\u0000" + p.dst;
      if (!pair.has(k)) pair.set(k, { n: 0, g: new Map() });
      const e = pair.get(k); e.n++; inc(e.g, p.g);
      if (p.dport !== null && (p.g === "TCP" || p.g === "UDP" || p.g === "HTTPS/TLS" || p.g === "HTTP")) { portPk++; setOf(ports, k).add(p.dport); }
    }
    if (p.g === "ICMP") inc(icmp, p.src);
    if (p.g === "DNS") inc(dns, p.src);
    if (p.hasFlags) flagPk++;
    if (p.syn) { inc(syn, p.src); if (p.dst) setOf(synDst, p.src).add(p.dst); }
  }
  const alerts = [], notes = [];
  const add = (key, v, t, src, dst, observed, protos, cap) =>
    alerts.push({ key, name: RULES[key].name, sev: sevOf(v, t, cap), value: v, src, dst, threshold: t, observed, protos, why: RULES[key].why, benign: RULES[key].benign, steps: [RULES[key].first].concat(BASE_STEPS) });

  if (has.src) {
    for (const [s, n] of srcC) if (n > th.pkts) add("vol", n, th.pkts, s, "", [["Packets from this source", n]], [...(srcG.get(s) || [])]);
    if (has.dst) for (const [s, set] of srcDst) if (set.size > th.dests) add("scan", set.size, th.dests, s, "", [["Unique destination addresses", set.size]], [...srcG.get(s)]);
    if (has.proto) {
      for (const [s, n] of icmp) if (n > th.icmp) add("icmp", n, th.icmp, s, "", [["ICMP packets", n], ["Unique destinations", (srcDst.get(s) || new Set()).size]], ["ICMP"]);
      for (const [s, n] of dns) if (n > th.dns) add("dns", n, th.dns, s, "", [["DNS packets", n]], ["DNS"], 2);
    }
    if (has.info) for (const [s, n] of syn) if (n > th.syn) add("syn", n, th.syn, s, "", [["TCP SYN packets", n], ["Unique destinations", (synDst.get(s) || new Set()).size]], ["TCP"]);
  }
  if (has.src && has.dst) {
    for (const [k, e] of pair) {
      const [s, d] = k.split("\u0000"), pr = topN(e.g, 1)[0][0];
      if (e.n > th.pair) add("pair", e.n, th.pair, s, d, [["Packets", e.n], ["Most common protocol", pr]], [...e.g.keys()], 2);
    }
    for (const [k, set] of ports) if (set.size > th.ports) {
      const [s, d] = k.split("\u0000");
      add("port", set.size, th.ports, s, d, [["Unique destination ports", set.size], ["Example ports", [...set].sort((a, b) => a - b).slice(0, 8).join(", ")]], [...pair.get(k).g.keys()]);
    }
  }
  if (has.info && portPk === 0) notes.push("No destination ports could be read from the Info column, so the port scanning rule could not run.");
  if (has.info && flagPk === 0) notes.push("No TCP flags were found in the Info column, so the SYN rule could not run.");
  alerts.sort((a, b) => b.sev - a.sev || b.value / b.threshold - a.value / a.threshold);
  const parts = alerts.map((a) => ({ pts: PTS[a.sev], text: a.name + " (" + a.src + (a.dst ? " → " + a.dst : "") + ")" }));
  const score = parts.reduce((s, x) => s + x.pts, 0);
  const label = score === 0 ? "No threshold exceeded" : score < 25 ? "Mild Activity" : score < 60 ? "Elevated Activity" : "High Activity";
  return { total: pk.length, srcC, dstC, gC, topSrc: topN(srcC), topDst: topN(dstC), topProto: topN(gC, 1)[0], avgLen: lenN ? lenSum / lenN : null,
    uniqSrc: srcC.size, uniqDst: dstC.size, alerts, notes, parts, score, label };
}

if (typeof module !== "undefined") module.exports = { parseCSV, mapColumns, buildPackets, analyse, DEFAULTS, MAX_BYTES };

/* ---------- user interface ---------- */
function initUI() {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
  const ids = { pkts: "th-pkts", dests: "th-dests", ports: "th-ports", icmp: "th-icmp", dns: "th-dns", pair: "th-pair", syn: "th-syn" };
  const state = { packets: null, has: null, res: null };
  const readTh = () => { const t = {}; for (const k in ids) { const v = parseInt($(ids[k]).value, 10); t[k] = v > 0 ? v : DEFAULTS[k]; } return t; };

  function showStatus(kind, rows, problems) {
    const box = $("status"); clear(box); box.className = "status " + kind; box.hidden = false;
    const dl = el("dl");
    rows.forEach(([k, v]) => { dl.appendChild(el("dt", "", k)); dl.appendChild(el("dd", "", v)); });
    box.appendChild(dl);
    if (problems.length) { const ul = el("ul"); problems.forEach((p) => ul.appendChild(el("li", "", p))); box.appendChild(ul); }
  }

  function loadText(text, name, demo) {
    $("results").hidden = true;
    const base = [["File", name + (demo ? " (Demo Data)" : "")]];
    try {
      const { rows, openQuote } = parseCSV(text);
      if (rows.length < 2) return showStatus("bad", base.concat([["Parsed", "No"]]), ["The file has no packet rows. Export the packet list from Wireshark as CSV (File > Export Packet Dissections > As CSV)."]);
      const idx = mapColumns(rows[0]);
      if (Object.values(idx).every((i) => i < 0)) return showStatus("bad", base.concat([["Parsed", "No"]]), ["This does not look like a Wireshark packet-list export: none of the expected column names (Source, Destination, Protocol, Length, Info) were found in the first row."]);
      const has = { src: idx.src >= 0, dst: idx.dst >= 0, proto: idx.proto >= 0, len: idx.len >= 0, info: idx.info >= 0 };
      const problems = [];
      if (openQuote) problems.push("A quoted value was never closed, so the end of the file may be incomplete.");
      if (!has.src) problems.push("This CSV does not appear to contain a Source address column. Host-based rules cannot run.");
      if (!has.dst) problems.push("This CSV does not appear to contain a Destination address column. Scanning, port and repeated-communication rules cannot run.");
      if (!has.proto) problems.push("This CSV does not appear to contain a Protocol column. ICMP, DNS and the protocol chart are limited.");
      if (!has.len) problems.push("No Length column found, so average packet length is not shown.");
      if (!has.info) problems.push("No Info column found, so port scanning and SYN rules cannot run.");
      state.packets = buildPackets(rows, idx); state.has = has;
      showStatus(problems.length ? "warn" : "ok", base.concat([["Packets loaded", String(state.packets.length)], ["Parsed", problems.length ? "Yes, with missing fields" : "Yes"]]), problems);
      run(demo);
    } catch (e) {
      showStatus("bad", base.concat([["Parsed", "No"]]), [String(e && e.message ? e.message : e)]);
    }
  }

  async function loadFile(file) {
    if (!file) return;
    if (!/\.(csv|txt)$/i.test(file.name) && !/^text\//.test(file.type)) return showStatus("bad", [["File", file.name]], ["Only Wireshark .csv files are supported in this version (not .pcap or .pcapng)."]);
    if (file.size > MAX_BYTES) return showStatus("bad", [["File", file.name]], ["This file is larger than 50 MB. Export a smaller capture."]);
    loadText(await file.text(), file.name, false);
  }

  function bars(listEl, entries, total) {
    clear(listEl);
    const max = entries.length ? entries[0][1] : 1;
    entries.forEach(([k, n]) => {
      const li = el("li"), lab = el("span", "lab", k), track = el("span", "track"), fill = el("span", "fill"), cnt = el("span", "cnt", n + " packets");
      fill.style.width = Math.max(2, (n / max) * 100) + "%";
      track.appendChild(fill); [lab, track, cnt].forEach((x) => li.appendChild(x)); listEl.appendChild(li);
    });
    if (!entries.length) listEl.appendChild(el("li", "muted", "Not available for this file."));
  }

  function fillSelect(sel, values) {
    const keep = sel.value, first = sel.options[0];
    clear(sel); sel.appendChild(first);
    values.forEach((v) => { const o = el("option", "", v); o.value = v; sel.appendChild(o); });
    sel.value = values.includes(keep) ? keep : "";
  }

  function run(demo) {
    if (!state.packets) return;
    const r = analyse(state.packets, state.has, readTh()); state.res = r;
    $("results").hidden = false; $("demoTag").hidden = !demo;
    const cards = [["Total packets", r.total], ["Unique sources", state.has.src ? r.uniqSrc : "n/a"], ["Unique destinations", state.has.dst ? r.uniqDst : "n/a"],
      ["Most active source", r.topSrc[0] ? r.topSrc[0][0] : "n/a"], ["Most contacted destination", r.topDst[0] ? r.topDst[0][0] : "n/a"],
      ["Most common protocol", r.topProto ? r.topProto[0] : "n/a"], ["Average packet length", r.avgLen === null ? "n/a" : Math.round(r.avgLen) + " bytes"]];
    const c = $("cards"); clear(c);
    cards.forEach(([k, v]) => { const d = el("div", "card"); d.appendChild(el("p", "k", k)); d.appendChild(el("p", "v", String(v))); c.appendChild(d); });
    bars($("topSrc"), r.topSrc); bars($("topDst"), r.topDst); bars($("protoDist"), topN(r.gC, 20));
    $("scoreLabel").textContent = r.label + " (investigation score " + r.score + ")";
    const sl = $("scoreParts"); clear(sl);
    r.parts.forEach((p) => sl.appendChild(el("li", "", "+" + p.pts + "  " + p.text)));
    if (!r.parts.length) sl.appendChild(el("li", "muted", "Nothing exceeded a threshold. That does not prove the traffic is safe: thresholds only catch what they measure."));
    const nl = $("notes"); clear(nl); r.notes.forEach((n) => nl.appendChild(el("li", "", n)));
    fillSelect($("f-src"), [...new Set(r.alerts.map((a) => a.src))]); fillSelect($("f-dst"), [...new Set(r.alerts.map((a) => a.dst).filter(Boolean))]);
    fillSelect($("f-proto"), [...new Set(r.alerts.flatMap((a) => a.protos))]);
    renderAlerts();
  }

  function renderAlerts() {
    const r = state.res, box = $("alerts"); clear(box);
    const f = { sev: $("f-sev").value, src: $("f-src").value, dst: $("f-dst").value, pr: $("f-proto").value, q: $("f-q").value.trim().toLowerCase() };
    const list = r.alerts.filter((a) => (!f.sev || SEV[a.sev] === f.sev) && (!f.src || a.src === f.src) && (!f.dst || a.dst === f.dst) && (!f.pr || a.protos.includes(f.pr)) &&
      (!f.q || (a.name + " " + a.src + " " + a.dst + " " + a.protos.join(" ")).toLowerCase().includes(f.q)));
    $("alertCount").textContent = list.length + " of " + r.alerts.length + " alerts shown";
    if (!list.length) box.appendChild(el("p", "muted", r.alerts.length ? "No alerts match these filters." : "No rules triggered at the current thresholds."));
    list.forEach((a) => {
      const art = el("article", "alert sev" + a.sev), head = el("header");
      head.appendChild(el("h3", "", a.name)); head.appendChild(el("span", "badge", "Severity: " + SEV[a.sev]));
      art.appendChild(head);
      const dl = el("dl"), row = (k, v) => { dl.appendChild(el("dt", "", k)); dl.appendChild(el("dd", "", String(v))); };
      row("Source host", a.src); if (a.dst) row("Destination host", a.dst);
      a.observed.forEach(([k, v]) => row(k, v)); row("Configured threshold", a.threshold);
      art.appendChild(dl);
      art.appendChild(el("h4", "", "Why this could matter")); art.appendChild(el("p", "", a.why));
      art.appendChild(el("h4", "", "Possible benign explanations"));
      const ul = el("ul"); a.benign.forEach((b) => ul.appendChild(el("li", "", b))); art.appendChild(ul);
      art.appendChild(el("h4", "", "Suggested investigation"));
      const ol = el("ol"); a.steps.forEach((s) => ol.appendChild(el("li", "", s))); art.appendChild(ol);
      box.appendChild(art);
    });
  }

  const drop = $("drop");
  $("file").addEventListener("change", (e) => { loadFile(e.target.files[0]); e.target.value = ""; });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => loadFile(e.dataTransfer.files[0]));
  [["demo-normal", "normal", "normal-traffic.csv"], ["demo-high", "high", "high-volume-traffic.csv"], ["demo-mixed", "mixed", "mixed-soc-lab.csv"]]
    .forEach(([id, k, n]) => $(id).addEventListener("click", () => loadText(window.SAMPLES[k], n, true)));
  Object.values(ids).forEach((id) => $(id).addEventListener("input", () => run(!$("demoTag").hidden)));
  $("reset").addEventListener("click", () => { for (const k in ids) $(ids[k]).value = DEFAULTS[k]; run(!$("demoTag").hidden); });
  ["f-sev", "f-src", "f-dst", "f-proto"].forEach((id) => $(id).addEventListener("change", renderAlerts));
  $("f-q").addEventListener("input", renderAlerts);
  window.PacketLantern = { loadText };
}
if (typeof document !== "undefined") initUI();
