/**
 * csvAnalyzer.js — In-browser Network Bouncer analysis engine
 *
 * Exports both:
 *   analyzeCSV()     — single-call API (used when no Worker is available)
 *   parseCSV()       — step 1: parse text → {headers, rows}
 *   aggregateRows()  — step 2: group rows by srcip with optional progress cb
 *   applyRules()     — step 3: classify each IP and build report JSON
 */

/* ── Column name aliases ────────────────────────────────────────────────────── */
const SRC_ALIASES    = ['srcip','src_ip','source_ip','src'];
const DST_ALIASES    = ['dstip','dst_ip','dest_ip','destination_ip','dst'];
const DPORT_ALIASES  = ['dsport','dst_port','dest_port','dport'];
const PROTO_ALIASES  = ['proto','protocol'];
const STATE_ALIASES  = ['state'];
const STIME_ALIASES  = ['stime','Stime','start_time','timestamp'];
const SBYTES_ALIASES = ['sbytes','src_bytes','bytes'];
const SPKTS_ALIASES  = ['spkts','src_pkts','pkts'];
const SERVICE_ALIASES= ['service','srv'];
const LABEL_ALIASES  = ['Label','label','attack_label'];
const CAT_ALIASES    = ['attack_cat','attack_category','category'];

/* UNSW-NB15 column positions (0-indexed, headerless) */
const HL = {
  srcip:0, sport:1, dstip:2, dsport:3, proto:4, state:5,
  sbytes:7, spkts:16, service:13, Stime:28,
  attack_cat:47, Label:48,
};

function findCol(headers, aliases) {
  for (const a of aliases) {
    const idx = headers.findIndex(h => h.toLowerCase() === a.toLowerCase());
    if (idx !== -1) return idx;
  }
  return -1;
}

function makeGetter(headers, aliases, fallback) {
  if (headers) {
    const idx = findCol(headers, aliases);
    return idx !== -1 ? (row) => row[idx] : () => '';
  }
  return (row) => row[fallback] ?? '';
}

/* ── CSV line splitter (handles quoted commas) ──────────────────────────────── */
function splitLine(line) {
  const out = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQ = !inQ; }
    else if (c === ',' && !inQ) { out.push(cur.trim()); cur = ''; }
    else { cur += c; }
  }
  out.push(cur.trim());
  return out;
}

/* ── Step 1: Parse ──────────────────────────────────────────────────────────── */
export function parseCSV(text) {
  // Normalise line endings
  const raw = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Find first non-empty line to check for header
  const firstNL = raw.indexOf('\n');
  const firstLine = (firstNL === -1 ? raw : raw.substring(0, firstNL)).trim();
  const isHeadered = isNaN(parseFloat(firstLine.split(',')[0]?.trim()));

  let headers = null;
  let dataStart = 0;

  if (isHeadered) {
    headers   = splitLine(firstLine);
    dataStart = firstNL + 1;
  }

  // Return a lazy iterator so the worker can process chunk by chunk
  const dataText = raw.substring(dataStart);
  return { headers, dataText, isHeadered };
}

/* ── Step 2: Aggregate (with optional progress callback) ────────────────────── */
/**
 * @param {string}   dataText   Raw CSV data text (after header line)
 * @param {string[]|null} headers
 * @param {function} onProgress  (processedRows, totalEstimate) => void  — optional
 * @returns {Map<string, object>} ipMap
 */
export function aggregateRows(dataText, headers, onProgress) {
  const getSrc   = makeGetter(headers, SRC_ALIASES,    HL.srcip);
  const getDst   = makeGetter(headers, DST_ALIASES,    HL.dstip);
  const getDport = makeGetter(headers, DPORT_ALIASES,  HL.dsport);
  const getProto = makeGetter(headers, PROTO_ALIASES,  HL.proto);
  const getState = makeGetter(headers, STATE_ALIASES,  HL.state);
  const getStime = makeGetter(headers, STIME_ALIASES,  HL.Stime);
  const getSbytes= makeGetter(headers, SBYTES_ALIASES, HL.sbytes);
  const getSpkts = makeGetter(headers, SPKTS_ALIASES,  HL.spkts);
  const getSvc   = makeGetter(headers, SERVICE_ALIASES,HL.service);
  const getLabel = makeGetter(headers, LABEL_ALIASES,  HL.Label);
  const getCat   = makeGetter(headers, CAT_ALIASES,    HL.attack_cat);

  const ipMap = new Map();
  const CHUNK = 20_000;        // report progress every N rows
  let processed = 0;
  let pos = 0;
  const len = dataText.length;

  // Rough total estimate (avg bytes per line from first 200 chars)
  const sampleLen = Math.min(200, len);
  const sampleLines = (dataText.substring(0, sampleLen).match(/\n/g) || []).length;
  const avgLineLen  = sampleLines > 0 ? sampleLen / sampleLines : 80;
  const estTotal    = Math.max(1, Math.round(len / avgLineLen));

  while (pos < len) {
    // Find end of line
    let nl = dataText.indexOf('\n', pos);
    if (nl === -1) nl = len;
    const line = dataText.substring(pos, nl).trim();
    pos = nl + 1;

    if (!line) continue;

    const row = splitLine(line);
    const src = getSrc(row)?.trim();
    if (!src || src === 'srcip') continue;

    const dst    = getDst(row)?.trim()    || '';
    const dport  = getDport(row)?.trim()  || '0';
    const proto  = getProto(row)?.trim()  || '';
    const state  = getState(row)?.trim()  || '';
    const stime  = parseFloat(getStime(row))  || 0;
    const sbytes = parseInt(getSbytes(row))   || 0;
    const spkts  = parseInt(getSpkts(row))    || 0;
    const svc    = getSvc(row)?.trim()    || '';
    const label  = parseInt(getLabel(row))    || 0;
    const cat    = getCat(row)?.trim()    || '';

    let b = ipMap.get(src);
    if (!b) {
      b = {
        source_ip: src,
        total_connections: 0,
        total_bytes: 0,
        total_packets: 0,
        dsts: new Set(),
        ports: new Set(),
        protocols: new Set(),
        services: new Set(),
        states: {},
        times: [],
        labeled_attacks: 0,
        attack_cats: new Set(),
      };
      ipMap.set(src, b);
    }

    b.total_connections++;
    b.total_bytes   += sbytes;
    b.total_packets += spkts;
    if (dst)                       b.dsts.add(dst);
    if (dport && dport !== '0')    b.ports.add(dport);
    if (proto)                     b.protocols.add(proto);
    if (svc && svc !== '-')        b.services.add(svc);
    if (state)                     b.states[state] = (b.states[state] || 0) + 1;
    // Only store up to 2000 timestamps per IP to save memory on huge files
    if (stime && b.times.length < 2000) b.times.push(stime);
    if (label === 1)               { b.labeled_attacks++; if (cat) b.attack_cats.add(cat); }

    processed++;
    if (onProgress && processed % CHUNK === 0) {
      onProgress(processed, estTotal);
    }
  }

  if (onProgress) onProgress(processed, processed); // final
  return ipMap;
}

/* ── Step 3: Apply NIDS rules ───────────────────────────────────────────────── */
/**
 * @param {Map} ipMap
 * @param {string} filename
 * @returns {object} report JSON (same structure as report_data.json)
 */
export function applyRules(ipMap, filename = 'uploaded.csv') {
  const VERT_THRESH  = 20;
  const HORIZ_THRESH = 30;
  const STROBE_IPS   = 10;
  const STROBE_PORTS = 10;
  const RATE_THRESH  = 10;
  const FAIL_RATIO   = 0.80;
  const MIN_FAIL     = 20;   // min connections before applying fail ratio rule

  const allHosts = [];

  for (const [, b] of ipMap) {
    const uniqDsts  = b.dsts.size;
    const uniqPorts = b.ports.size;
    const conns     = b.total_connections;

    const states      = b.states;
    const failedConns = (states.REQ || 0) + (states.INT || 0) + (states.RST || 0);
    const failedRatio = failedConns / Math.max(conns, 1);

    const times    = b.times.length > 1 ? b.times.sort((a, z) => a - z) : b.times;
    const duration = times.length > 1 ? times[times.length - 1] - times[0] : 0;
    const rate     = duration > 0 ? conns / duration : 0;

    let classification = 'Normal Traffic';
    let severity       = 'Normal';
    const reasons      = [];
    let isSuspicious   = false;

    // Labeled attack
    if (b.labeled_attacks > 0) {
      const cats = [...b.attack_cats].join(', ');
      classification = cats
        ? `Suspicious (Attack: ${cats.charAt(0).toUpperCase() + cats.slice(1)})`
        : 'Suspicious (Labeled Attack)';
      severity     = 'High';
      reasons.push(`Labeled attack traffic in dataset (${b.labeled_attacks} flows)`);
      isSuspicious = true;
    }

    // Strobe
    if (!isSuspicious && uniqDsts >= STROBE_IPS && uniqPorts >= STROBE_PORTS) {
      classification = 'Suspicious (Strobe Port Scan)';
      severity       = 'High';
      reasons.push(`Strobe scan: ${uniqDsts} hosts × ${uniqPorts} ports`);
      isSuspicious   = true;
    }

    // Horizontal
    if (!isSuspicious && uniqDsts >= HORIZ_THRESH) {
      classification = 'Suspicious (Horizontal Port Scan)';
      severity       = 'High';
      reasons.push(`Scanned ${uniqDsts} unique destination IPs`);
      isSuspicious   = true;
    }

    // Vertical
    if (!isSuspicious && uniqPorts >= VERT_THRESH) {
      classification = 'Suspicious (Vertical Port Scan)';
      severity       = 'High';
      reasons.push(`Scanned ${uniqPorts} unique ports on target host(s)`);
      isSuspicious   = true;
    }

    // High rate
    if (!isSuspicious && rate >= RATE_THRESH) {
      classification = 'Suspicious (High Connection Rate)';
      severity       = 'Medium';
      reasons.push(`Connection rate ${rate.toFixed(2)} conns/sec exceeds threshold`);
      isSuspicious   = true;
    }

    // Stealth — high failed ratio
    if (!isSuspicious && conns >= MIN_FAIL && failedRatio >= FAIL_RATIO) {
      classification = 'Suspicious (Stealth Scan — High Failed Conn Ratio)';
      severity       = 'Medium';
      reasons.push(`High failed connection ratio: ${(failedRatio * 100).toFixed(0)}% (${failedConns}/${conns} flows)`);
      isSuspicious   = true;
    }

    // Critical upgrade: labeled + very high fail + beaconing
    if (isSuspicious && b.labeled_attacks > 0 && uniqDsts <= 2 && conns >= 50) {
      severity = 'Critical';
    }

    allHosts.push({
      source_ip: b.source_ip,
      total_connections: conns,
      unique_destinations: uniqDsts,
      unique_ports: uniqPorts,
      total_bytes: b.total_bytes,
      total_packets: b.total_packets,
      duration_sec: parseFloat(duration.toFixed(2)),
      conn_rate_per_sec: parseFloat(rate.toFixed(2)),
      peak_window_ips: uniqDsts,
      peak_window_ports: uniqPorts,
      protocols: [...b.protocols],
      services: [...b.services],
      states,
      classification,
      is_suspicious: isSuspicious,
      severity,
      reason: reasons.join('; '),
      advanced_classification: 'Normal Traffic',
      advanced_reason: '',
      labeled_attacks_count: b.labeled_attacks,
      true_attack_cat: [...b.attack_cats].join(', ') || 'None',
    });
  }

  const suspicious = allHosts.filter(h => h.is_suspicious);
  const totalIPs   = allHosts.length;

  const sevCounts = { Critical: 0, High: 0, Medium: 0, Normal: 0 };
  for (const h of allHosts) {
    if      (h.severity === 'Critical') sevCounts.Critical++;
    else if (h.severity === 'High')     sevCounts.High++;
    else if (h.severity === 'Medium')   sevCounts.Medium++;
    else                                sevCounts.Normal++;
  }

  return {
    dataset_name: filename,
    summary: {
      total_ips: totalIPs,
      suspicious_ips: suspicious.length,
      normal_ips: totalIPs - suspicious.length,
      severity_distribution: sevCounts,
    },
    hosts: allHosts,
    suspicious_hosts: suspicious,
  };
}

/* ── Combined single-call API (used when Worker unavailable) ────────────────── */
export function analyzeCSV(csvText, filename = 'uploaded.csv') {
  const { headers, dataText } = parseCSV(csvText);
  const ipMap = aggregateRows(dataText, headers, null);
  return applyRules(ipMap, filename);
}
