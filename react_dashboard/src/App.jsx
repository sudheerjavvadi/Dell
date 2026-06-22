import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, ShieldAlert, AlertTriangle, CheckCircle, Search,
  ShieldX, Terminal, Cpu, Database, Network, ArrowRight,
  RefreshCw, Info, Download, FileText, Sun, Moon, Activity,
  Zap, Eye, Lock, TrendingUp, Server, BarChart2, Sparkles,
  Copy, Check, ChevronUp, ChevronDown, ChevronsUpDown, Wifi,
  Menu, X, LayoutDashboard, FlaskConical
} from 'lucide-react';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement } from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import NewAnalysis from './pages/NewAnalysis';
import './App.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement);

/* ============================================================
   COPY TO CLIPBOARD HOOK
   ============================================================ */
function useCopyToClipboard(timeout = 2000) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback((text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), timeout);
    }).catch(() => {
      // fallback
      const el = document.createElement('textarea');
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), timeout);
    });
  }, [timeout]);
  return [copied, copy];
}

/* ============================================================
   SIDEBAR NAVIGATION
   ============================================================ */
const NAV_ITEMS = [
  { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },

  { id: 'analysis', label: 'New Analysis', icon: FlaskConical },
  { id: 'ml_dashboard', label: 'ML Model', icon: Cpu },
];

function Sidebar({ open, onClose, currentPage, onNavigate }) {
  return (
    <>
      {/* Backdrop */}
      {open && (
        <div
          className="sidebar-backdrop"
          onClick={onClose}
        />
      )}
      {/* Drawer */}
      <aside className={`sidebar-drawer ${open ? 'sidebar-drawer-open' : ''}`}>
        <div className="sidebar-header">
          <div className="topbar-logo">
            <div className="topbar-logo-icon"><Shield size={14} /></div>
            <span className="topbar-title">Network Bouncer</span>
          </div>
          <button className="topbar-btn topbar-btn-icon" onClick={onClose}>
            <X size={15} />
          </button>
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              className={`sidebar-nav-item ${currentPage === item.id ? 'sidebar-nav-item-active' : ''}`}
              onClick={() => { onNavigate(item.id); onClose(); }}
            >
              <item.icon size={16} />
              <span>{item.label}</span>
              {currentPage === item.id && <span className="sidebar-nav-active-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Network Bouncer NIDS v2.0</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Rule-Based Sliding-Window Engine</div>
        </div>
      </aside>
    </>
  );
}

/* ============================================================
   AI CO-PILOT: Rule-Based Incident Analysis
   ============================================================ */
function generateAIAnalysis(host) {
  if (!host || !host.is_suspicious) return null;

  const classification = host.classification || '';
  const severity = host.severity;
  const ip = host.source_ip;
  const ports = host.unique_ports;
  const dsts = host.unique_destinations;
  const rate = host.conn_rate_per_sec;
  const conns = host.total_connections;
  const states = host.states || {};
  const totalFailed = (states.REQ || 0) + (states.INT || 0) + (states.RST || 0);
  const failedRatio = totalFailed / Math.max(conns, 1);

  let attackExplanation = '';
  let prediction = '';
  let mitigation = '';
  let summary = '';

  if (classification.includes('Vertical')) {
    attackExplanation = `${ip} executed a Vertical Port Scan, probing ${ports} unique destination ports on a single target host within a 60-second sliding window. This pattern indicates targeted service discovery on one machine — a common precursor to exploiting known CVEs on open services.`;
    prediction = `HIGH — Vertical scans targeting ${ports} ports suggest the attacker is mapping all available services. Exploit attempt probability is high if follow-up connections occur.`;
    mitigation = `iptables -A INPUT -s ${ip} -j DROP`;
  } else if (classification.includes('Horizontal')) {
    attackExplanation = `${ip} performed a Horizontal Port Scan, sweeping ${dsts} destination hosts in a single time window. This is a classic network reconnaissance technique used to map live hosts before targeted exploitation.`;
    prediction = `HIGH — Sweeping ${dsts} hosts indicates active network reconnaissance. Lateral movement risk is elevated.`;
    mitigation = `iptables -A INPUT -s ${ip} -j DROP`;
  } else if (classification.includes('Strobe')) {
    attackExplanation = `${ip} ran a Strobe Port Scan, hitting multiple hosts and multiple ports simultaneously. This combined pattern suggests the attacker is scanning both horizontally and vertically to rapidly map the attack surface.`;
    prediction = `HIGH — Strobe scans combine breadth and depth, suggesting automated tooling (e.g., Nmap, Masscan). Immediate block recommended.`;
    mitigation = `iptables -A INPUT -s ${ip} -j DROP`;
  } else if (classification.includes('Stealth') || classification.includes('Failed')) {
    attackExplanation = `${ip} shows a high failed/interrupted connection ratio (${(failedRatio * 100).toFixed(0)}%) across ${conns.toLocaleString()} flows. Stealth scan techniques like SYN Half-Open, FIN, NULL, or XMAS scans intentionally avoid completing TCP handshakes to evade stateful firewalls and IDS logs.`;
    prediction = `MEDIUM — The high REQ/INT state ratio (${totalFailed.toLocaleString()} failed out of ${conns.toLocaleString()}) is consistent with SYN stealth scanning. The attacker is probing without establishing full sessions to avoid detection.`;
    mitigation = `iptables -A INPUT -s ${ip} --tcp-flags ALL SYN,FIN -j DROP`;
  } else if (classification.includes('Distributed')) {
    attackExplanation = `${ip} participated in a Distributed Scan Campaign — a coordinated probing pattern where multiple source IPs collectively target the same destination ports. This is a Botnet-coordinated reconnaissance signature designed to stay below individual detection thresholds.`;
    prediction = `MEDIUM — Distributed campaigns are significantly harder to block at the IP level. The attack coordinated ${dsts} unique target hosts and indicates botnet infrastructure.`;
    mitigation = `# Block coordinated campaign source\niptables -A INPUT -s ${ip} -j DROP\n# Enable geo-blocking if applicable`;
  } else if (classification.includes('High-Rate')) {
    attackExplanation = `${ip} generated a connection rate of ${rate} conns/sec (${conns.toLocaleString()} total flows), far exceeding normal baseline traffic. High-rate anomalies can indicate DDoS probes, brute-force attempts, or scanner tools running at maximum speed.`;
    prediction = `MEDIUM — The ${rate} conn/sec rate indicates automated scanning or attack tooling. Possible brute-force on identified services.`;
    mitigation = `iptables -A INPUT -s ${ip} -m limit --limit 10/min -j ACCEPT\niptables -A INPUT -s ${ip} -j DROP`;
  } else {
    attackExplanation = `${ip} has been flagged as suspicious based on anomalous network behavior patterns. Review the detection logic reasons for specific rule triggers.`;
    prediction = `${severity.toUpperCase()} — The host shows deviation from normal traffic profiles requiring further investigation.`;
    mitigation = `iptables -A INPUT -s ${ip} -j LOG --log-prefix "BOUNCER-SUSPECT"\niptables -A INPUT -s ${ip} -j DROP`;
  }

  summary = `On ${new Date().toLocaleDateString()}, source IP ${ip} was flagged by The Network Bouncer NIDS. ` +
    `The host established ${conns.toLocaleString()} flows targeting ${dsts} unique destinations on ${ports} distinct ports. ` +
    `Detection severity: ${severity}. Classification: ${classification.replace('Suspicious (', '').replace(')', '')}. ` +
    `Immediate firewall rule enforcement and log review are recommended.`;

  return { attackExplanation, prediction, mitigation, summary };
}

/* ============================================================
   MITIGATION BLOCK COMPONENT (copy-to-clipboard)
   ============================================================ */
function MitigationBlock({ command }) {
  const [copied, copy] = useCopyToClipboard();
  return (
    <div className="ai-command-wrap">
      <pre className="ai-command">{command}</pre>
      <button
        className={`copy-btn ${copied ? 'copy-btn-success' : ''}`}
        onClick={() => copy(command)}
        title={copied ? 'Copied!' : 'Copy to clipboard'}
      >
        {copied ? <Check size={12} /> : <Copy size={12} />}
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

/* ============================================================
   MAIN APP COMPONENT
   ============================================================ */
export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedIp, setSelectedIp] = useState(null);
  const [darkMode, setDarkMode] = useState(true);
  const [sortCol, setSortCol] = useState('total_connections');
  const [sortDir, setSortDir] = useState('desc');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Apply dark mode class
  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [darkMode]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const endpoint = currentPage === 'ml_dashboard' ? '/ml_report_data.json' : '/report_data.json';
      const response = await fetch(endpoint);
      if (!response.ok) throw new Error(`Could not load ${endpoint}. Run the analyzer script first.`);
      const data = await response.json();
      setReport(data);
      setLastUpdated(new Date());
      if (data.suspicious_hosts?.length > 0) {
        setSelectedIp(prev => prev || data.suspicious_hosts[0].source_ip);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [currentPage]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Sort helper
  const handleSort = (col) => {
    if (sortCol === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortCol(col);
      setSortDir('desc');
    }
  };

  const SortIcon = ({ col }) => {
    if (sortCol !== col) return <ChevronsUpDown size={10} style={{ opacity: 0.35 }} />;
    return sortDir === 'asc' ? <ChevronUp size={10} /> : <ChevronDown size={10} />;
  };

  const downloadCSV = () => {
    if (!report?.hosts) return;
    const headers = [
      'Source IP', 'Total Connections', 'Unique Destinations', 'Unique Ports',
      'Total Bytes', 'Total Packets', 'Duration (sec)', 'Connection Rate (per sec)',
      'Severity', 'Classification', 'Reason', 'Advanced Classification', 'Advanced Reason'
    ];
    const rows = report.hosts.map(h => [
      h.source_ip, h.total_connections, h.unique_destinations, h.unique_ports,
      h.total_bytes, h.total_packets, h.duration_sec, h.conn_rate_per_sec,
      h.severity, h.classification,
      h.reason ? h.reason.replace(/"/g, '""') : 'Normal traffic behavior',
      h.advanced_classification || 'Normal Traffic',
      h.advanced_reason ? h.advanced_reason.replace(/"/g, '""') : 'No advanced threat signatures detected'
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    let name = report.dataset_name ? report.dataset_name.split(/[/\\]/).pop().replace(/\.[^/.]+$/, '') : 'network_traffic';
    link.setAttribute('href', url);
    link.setAttribute('download', `bouncer_report_${name}.csv`);
    document.body.appendChild(link); link.click(); document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const downloadPDF = () => {
    if (!report) return;
    const date = new Date().toLocaleString();
    const sevColor = { Critical: '#dc2626', High: '#ea580c', Medium: '#d97706', Normal: '#059669' };
    const sevBg    = { Critical: '#fef2f2', High: '#fff7ed', Medium: '#fffbeb', Normal: '#f0fdf4' };

    const suspRows = report.hosts
      .filter(h => h.is_suspicious)
      .sort((a, b) => {
        const order = { Critical: 0, High: 1, Medium: 2, Normal: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      });

    const tableRows = suspRows.map(h => `
      <tr>
        <td style="font-family:monospace;font-weight:600;color:#111">${h.source_ip}</td>
        <td style="text-align:center">${h.total_connections.toLocaleString()}</td>
        <td style="text-align:center">${h.unique_destinations}</td>
        <td style="text-align:center">${h.unique_ports}</td>
        <td style="text-align:center">
          <span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;
            color:${sevColor[h.severity] || '#374151'};background:${sevBg[h.severity] || '#f9fafb'}">
            ${h.severity}
          </span>
        </td>
        <td style="font-size:12px;color:#374151">${(h.reason || 'Normal traffic behavior').substring(0, 120)}</td>
      </tr>`).join('');

    const dist = report.summary.severity_distribution;
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Network Bouncer Report — ${report.dataset_name}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; color: #111827; background: #fff; padding: 32px 40px; font-size: 13px; }
    h1 { font-size: 22px; font-weight: 800; color: #111; letter-spacing: -0.5px; }
    h2 { font-size: 14px; font-weight: 700; color: #374151; margin: 24px 0 10px; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }
    .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 2px solid #111; }
    .header-right { text-align: right; font-size: 12px; color: #6b7280; }
    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .meta-card { padding: 14px 16px; border-radius: 8px; border: 1px solid #e5e7eb; }
    .meta-card h3 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-bottom: 6px; }
    .meta-card p { font-size: 26px; font-weight: 800; color: #111; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: #f9fafb; padding: 9px 10px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; color: #6b7280; border-bottom: 2px solid #e5e7eb; }
    td { padding: 9px 10px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
    tr:nth-child(even) td { background: #fafafa; }
    .footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center; }
    @media print {
      body { padding: 16px 20px; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>🛡️ Network Bouncer NIDS</h1>
      <div style="font-size:13px;color:#6b7280;margin-top:4px">Sliding-Window Threat Analysis Report</div>
    </div>
    <div class="header-right">
      <div><strong>Generated:</strong> ${date}</div>
      <div><strong>Dataset:</strong> ${report.dataset_name}</div>
      <div><strong>Engine:</strong> In-Browser NIDS v2.0</div>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-card" style="border-left:4px solid #6b7280">
      <h3>Total Hosts</h3>
      <p>${report.summary.total_ips}</p>
    </div>
    <div class="meta-card" style="border-left:4px solid #dc2626">
      <h3>Suspicious</h3>
      <p style="color:#dc2626">${report.summary.suspicious_ips}</p>
    </div>
    <div class="meta-card" style="border-left:4px solid #ea580c">
      <h3>Critical + High</h3>
      <p style="color:#ea580c">${(dist.Critical || 0) + (dist.High || 0)}</p>
    </div>
    <div class="meta-card" style="border-left:4px solid #059669">
      <h3>Normal</h3>
      <p style="color:#059669">${report.summary.normal_ips}</p>
    </div>
  </div>

  <h2>Severity Breakdown</h2>
  <table style="width:auto;margin-bottom:20px">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
      <tr><td><span style="color:#dc2626;font-weight:700">● Critical</span></td><td>${dist.Critical || 0}</td></tr>
      <tr><td><span style="color:#ea580c;font-weight:700">● High</span></td><td>${dist.High || 0}</td></tr>
      <tr><td><span style="color:#d97706;font-weight:700">● Medium</span></td><td>${dist.Medium || 0}</td></tr>
      <tr><td><span style="color:#059669;font-weight:700">● Normal</span></td><td>${dist.Normal || 0}</td></tr>
    </tbody>
  </table>

  <h2>Suspicious Hosts — Full Report (${suspRows.length} flagged)</h2>
  ${suspRows.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>Source IP</th><th>Conns</th><th>Dsts</th><th>Ports</th>
        <th>Severity</th><th>Detection Reason</th>
      </tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>` : '<p style="color:#6b7280;padding:16px 0">No suspicious hosts detected in this dataset.</p>'}

  <div class="footer">
    This report was generated by The Network Bouncer NIDS &mdash; In-Browser Analysis Engine &mdash;
    &copy; ${new Date().getFullYear()}. All rights reserved.
  </div>
  <script>window.onload = () => { window.focus(); window.print(); };</script>
</body>
</html>`;

    const win = window.open('', '_blank', 'width=900,height=700');
    if (!win) {
      alert('Pop-up blocked. Please allow pop-ups for this site and try again.');
      return;
    }
    win.document.write(html);
    win.document.close();
  };

  /* ---- LOADING STATE ---- */
  if (loading) return (
    <div className="loading-screen">
      <div className="loading-card">
        <div className="loading-icon"><Terminal size={24} /></div>
        <div className="loading-title">Initializing NIDS Engine</div>
        <div className="loading-text">Reconstructing sliding-window state logs...</div>
      </div>
    </div>
  );

  /* ---- ERROR STATE ---- */
  if (error) return (
    <div className="error-screen">
      <div className="error-card">
        <div className="error-icon"><ShieldX size={24} /></div>
        <div className="error-title">Data Stream Failure</div>
        <div className="error-desc">{error}</div>
        <div className="code-block">python network_bouncer.py archive\UNSW-NB15_4.csv</div>
        <button onClick={fetchData} className="btn btn-primary">
          <RefreshCw size={14} /> Retry Connection
        </button>
      </div>
    </div>
  );

  /* ---- DATA COMPUTATIONS ---- */
  const sortedFilteredHosts = (() => {
    const filtered = report.hosts.filter(h => {
      const matchSearch = h.source_ip.toLowerCase().includes(searchTerm.toLowerCase());
      const matchSev = severityFilter === 'ALL' || h.severity === severityFilter;
      return matchSearch && matchSev;
    });
    return [...filtered].sort((a, b) => {
      const aVal = a[sortCol] ?? 0;
      const bVal = b[sortCol] ?? 0;
      if (sortDir === 'asc') return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
    });
  })();

  const selectedHost = report.hosts.find(h => h.source_ip === selectedIp);
  const aiAnalysis = selectedHost ? generateAIAnalysis(selectedHost) : null;
  const severityDist = report.summary.severity_distribution;

  // Aggregate stats across suspicious hosts
  const suspStats = report.suspicious_hosts.reduce((acc, h) => {
    acc.conns += h.total_connections || 0;
    acc.bytes += h.total_bytes || 0;
    acc.pkts += h.total_packets || 0;
    return acc;
  }, { conns: 0, bytes: 0, pkts: 0 });
  const fmtBytes = (b) => b > 1e9 ? (b / 1e9).toFixed(1) + 'GB' : b > 1e6 ? (b / 1e6).toFixed(1) + 'MB' : b > 1e3 ? (b / 1e3).toFixed(1) + 'KB' : b + 'B';

  /* ---- CHART CONFIGS ---- */
  const isDark = darkMode;
  const textColor = isDark ? '#A3A3A3' : '#6B7280';
  const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';

  const doughnutData = {
    labels: ['Critical', 'High', 'Medium', 'Normal'],
    datasets: [{
      data: [severityDist.Critical || 0, severityDist.High || 0, severityDist.Medium || 0, severityDist.Normal || 0],
      backgroundColor: ['#EF4444', '#F59E0B', '#FBBF24', '#10B981'],
      borderWidth: 0,
      borderRadius: 4
    }]
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    plugins: {
      legend: { position: 'bottom', labels: { color: textColor, font: { family: 'Inter', size: 11 }, padding: 14 } }
    }
  };

  const topSuspicious = [...report.suspicious_hosts].sort((a, b) => b.total_connections - a.total_connections).slice(0, 7);
  const barData = {
    labels: topSuspicious.map(h => h.source_ip),
    datasets: [
      { label: 'Connections', data: topSuspicious.map(h => h.total_connections), backgroundColor: isDark ? 'rgba(59,130,246,0.7)' : 'rgba(59,130,246,0.65)', borderRadius: 4 },
      { label: 'Unique Ports', data: topSuspicious.map(h => h.unique_ports), backgroundColor: isDark ? 'rgba(139,92,246,0.7)' : 'rgba(139,92,246,0.65)', borderRadius: 4 }
    ]
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    scales: {
      x: { grid: { color: gridColor }, ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 10 } } },
      y: { grid: { display: false }, ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 11 } } }
    },
    plugins: {
      legend: { position: 'top', labels: { color: textColor, font: { family: 'Inter', size: 11 }, boxWidth: 12, padding: 16 } }
    }
  };

  /* ---- RENDER ---- */
  return (
    <>
      {/* ---- SIDEBAR ---- */}
      <Sidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        currentPage={currentPage}
        onNavigate={setCurrentPage}
      />

      <div className="app-layout">
        <div className="main-content">

          {/* ---- TOPBAR ---- */}
          <header className="topbar">
            <div className="topbar-left">
              <button
                className="topbar-btn topbar-btn-icon hamburger-btn"
                onClick={() => setSidebarOpen(true)}
                title="Open menu"
              >
                <Menu size={16} />
              </button>
              <div className="topbar-logo">
                <div className="topbar-logo-icon">
                  <Shield size={15} />
                </div>
                <span className="topbar-title">Network Bouncer</span>
              </div>
              <div className="topbar-divider" />
              <span className="topbar-breadcrumb">
                {currentPage === 'dashboard' ? 'SOC Dashboard' : currentPage === 'ml_dashboard' ? 'ML Model Dashboard' : 'New Analysis'}
              </span>
            </div>
            <div className="topbar-right">
              {['dashboard', 'ml_dashboard'].includes(currentPage) && lastUpdated && (
                <span className="topbar-last-updated">
                  Updated {lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              )}
              {['dashboard', 'ml_dashboard'].includes(currentPage) && (
                <button onClick={fetchData} className="topbar-btn topbar-btn-icon" title="Refresh data">
                  <RefreshCw size={14} />
                </button>
              )}
              {['dashboard', 'ml_dashboard'].includes(currentPage) && (
                <button onClick={downloadCSV} className="topbar-btn">
                  <Download size={13} /> Export CSV
                </button>
              )}
              {['dashboard', 'ml_dashboard'].includes(currentPage) && (
                <button onClick={downloadPDF} className="topbar-btn">
                  <FileText size={13} /> Print PDF
                </button>
              )}
              <button onClick={() => setDarkMode(!darkMode)} className="topbar-btn topbar-btn-icon" title="Toggle theme">
                {darkMode ? <Sun size={14} /> : <Moon size={14} />}
              </button>
            </div>
          </header>

          {/* ---- NEW ANALYSIS PAGE ---- */}
          {currentPage === 'analysis' && (
            <NewAnalysis darkMode={darkMode} />
          )}

          {/* ---- SOC / ML DASHBOARD ---- */}
          {['dashboard', 'ml_dashboard'].includes(currentPage) && (
            <>

              {/* ---- PAGE HEADER ---- */}
              <div className="page-header">
                <div className="page-header-meta">
                  <div className="live-dot" />
                  <span className="page-header-label">Live Monitoring Active</span>
                </div>
                <h1 className="page-header-title">{currentPage === 'ml_dashboard' ? 'Deep Learning Anomaly Detection' : 'Security Operations Dashboard'}</h1>
                <p className="page-header-desc">{currentPage === 'ml_dashboard' ? 'Network Traffic Analyzer — Powered by Deep Neural Networks (MLPClassifier)' : 'Network Traffic Analyzer & Port Scanning Detection System — Powered by rule-based sliding-window heuristics'}</p>
                <div className="page-header-bottom">
                  <div className="dataset-pill">
                    <Database size={12} /> {report.dataset_name || 'Unknown Dataset'}
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <div className="dataset-pill">
                      <Activity size={12} /> {report.summary.total_ips} Total Hosts
                    </div>
                    <div className="dataset-pill" style={{ color: 'var(--color-critical)' }}>
                      <ShieldAlert size={12} /> {report.summary.suspicious_ips} Suspicious IPs
                    </div>
                  </div>
                </div>
              </div>

              <div className="page-content">

                {/* ---- THREAT STATS TICKER ---- */}
                {report.suspicious_hosts.length > 0 && (
                  <div className="stats-ticker">
                    <div className="stats-ticker-item">
                      <Wifi size={12} />
                      <span>{suspStats.conns.toLocaleString()} suspicious flows</span>
                    </div>
                    <div className="stats-ticker-sep">·</div>
                    <div className="stats-ticker-item">
                      <Activity size={12} />
                      <span>{fmtBytes(suspStats.bytes)} data volume</span>
                    </div>
                    <div className="stats-ticker-sep">·</div>
                    <div className="stats-ticker-item">
                      <BarChart2 size={12} />
                      <span>{suspStats.pkts.toLocaleString()} packets captured</span>
                    </div>
                  </div>
                )}

                {/* ---- ALERT CALLOUT ---- */}
                {(severityDist.Critical > 0 || severityDist.High > 0) ? (
                  <div className="callout callout-critical">
                    <div className="callout-icon">🚨</div>
                    <div className="callout-content">
                      <div className="callout-title">
                        Active Threats Detected — Immediate Review Required
                      </div>
                      <div className="callout-text">
                        {severityDist.Critical > 0 && `${severityDist.Critical} Critical severity host(s) detected. `}
                        {severityDist.High > 0 && `${severityDist.High} High risk scanner(s) actively probing. `}
                        {severityDist.Medium > 0 && `${severityDist.Medium} Medium risk stealth campaign IP(s) flagged. `}
                        Select any host in the directory table below to investigate and review AI-generated mitigation steps.
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="callout callout-success">
                    <div className="callout-icon">✅</div>
                    <div className="callout-content">
                      <div className="callout-title">Network Status: Normal</div>
                      <div className="callout-text">No critical threats detected in the current dataset. Monitoring is active.</div>
                    </div>
                  </div>
                )}

                {/* ---- SECURITY OVERVIEW CARDS ---- */}
                <section className="section-gap">
                  <div className="section-header">
                    <div>
                      <div className="section-title">
                        <div className="section-title-dot" style={{ background: 'var(--color-blue)' }} />
                        Security Overview
                      </div>
                    </div>
                  </div>
                  <div className="metrics-grid">
                    <div className="card card-critical">
                      <div className="card-header">
                        <span className="card-label">Critical Threats</span>
                        <div className="card-icon"><ShieldAlert size={16} /></div>
                      </div>
                      <div className="card-value">{severityDist.Critical || 0}</div>
                      <div className="card-desc">Immediate isolation required</div>
                    </div>
                    <div className="card card-high">
                      <div className="card-header">
                        <span className="card-label">High Risk</span>
                        <div className="card-icon"><AlertTriangle size={16} /></div>
                      </div>
                      <div className="card-value">{severityDist.High || 0}</div>
                      <div className="card-desc">Active scanners & probe events</div>
                    </div>
                    <div className="card card-medium">
                      <div className="card-header">
                        <span className="card-label">Medium Risk</span>
                        <div className="card-icon"><Shield size={16} /></div>
                      </div>
                      <div className="card-value">{severityDist.Medium || 0}</div>
                      <div className="card-desc">Stealth / rate anomalies</div>
                    </div>
                    <div className="card card-success">
                      <div className="card-header">
                        <span className="card-label">Normal Nodes</span>
                        <div className="card-icon"><CheckCircle size={16} /></div>
                      </div>
                      <div className="card-value">{report.summary.normal_ips}</div>
                      <div className="card-desc">Within baseline parameters</div>
                    </div>
                  </div>
                </section>

                {/* ---- CHARTS ---- */}
                <section className="section-gap">
                  <div className="section-header">
                    <div>
                      <div className="section-title">
                        <div className="section-title-dot" style={{ background: 'var(--color-purple)' }} />
                        Analytics
                      </div>
                    </div>
                  </div>
                  <div className="charts-grid">
                    <div className="chart-card">
                      <div className="chart-title">Threat Level Breakdown</div>
                      <div className="chart-subtitle">Severity distribution across all hosts</div>
                      <div className="chart-wrapper" style={{ height: 240 }}>
                        <Doughnut data={doughnutData} options={doughnutOptions} />
                      </div>
                    </div>
                    <div className="chart-card">
                      <div className="chart-title">Top Suspicious Source IPs</div>
                      <div className="chart-subtitle">Connection volume & unique ports targeted</div>
                      <div className="chart-wrapper" style={{ height: 260 }}>
                        <Bar data={barData} options={barOptions} />
                      </div>
                    </div>
                  </div>
                </section>

                {/* ---- HOST DIRECTORY + INSPECTOR ---- */}
                <section className="section-gap">
                  <div className="section-header">
                    <div>
                      <div className="section-title">
                        <div className="section-title-dot" style={{ background: 'var(--color-critical)' }} />
                        Port Scan Detection Center
                      </div>
                      <div className="section-subtitle">Click any host to run threat explainability & AI co-pilot analysis</div>
                    </div>
                    <div className="filter-bar">
                      <div className="search-box">
                        <Search size={13} className="search-box-icon" />
                        <input
                          type="text"
                          placeholder="Search IP address..."
                          value={searchTerm}
                          onChange={e => setSearchTerm(e.target.value)}
                          className="search-input"
                        />
                      </div>
                      <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="filter-select">
                        <option value="ALL">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Info">Normal</option>
                      </select>
                    </div>
                  </div>

                  <div className="content-grid">
                    {/* TABLE */}
                    <div>
                      <div className="data-table-wrap">
                        <table className="data-table">
                          <thead>
                            <tr>
                              <th style={{ width: '40px', textAlign: 'center', color: 'var(--text-tertiary)' }}>#</th>
                              <th className="sortable-th" onClick={() => handleSort('source_ip')}>
                                Source IP <SortIcon col="source_ip" />
                              </th>
                              <th className="sortable-th" style={{ textAlign: 'center' }} onClick={() => handleSort('total_connections')}>
                                Conns <SortIcon col="total_connections" />
                              </th>
                              <th className="sortable-th" style={{ textAlign: 'center' }} onClick={() => handleSort('unique_destinations')}>
                                Dst IPs <SortIcon col="unique_destinations" />
                              </th>
                              <th className="sortable-th" style={{ textAlign: 'center' }} onClick={() => handleSort('unique_ports')}>
                                Ports <SortIcon col="unique_ports" />
                              </th>
                              <th style={{ textAlign: 'center' }}>Severity</th>
                              <th>Classification</th>
                              <th style={{ textAlign: 'right' }}>Inspect</th>
                            </tr>
                          </thead>
                          <tbody>
                            {sortedFilteredHosts.length > 0 ? sortedFilteredHosts.map((host, idx) => (
                              <tr
                                key={host.source_ip}
                                onClick={() => setSelectedIp(host.source_ip)}
                                className={selectedIp === host.source_ip ? 'active' : ''}
                              >
                                <td className="num-cell" style={{ opacity: 0.5, borderRight: '1px solid var(--border-color)', width: '40px' }}>{idx + 1}</td>
                                <td className="ip-cell">
                                  {(host.severity === 'Critical' || host.severity === 'High') && (
                                    <span className="threat-pulse" />
                                  )}
                                  {host.source_ip}
                                </td>
                                <td className="num-cell">{host.total_connections.toLocaleString()}</td>
                                <td className="num-cell">{host.unique_destinations}</td>
                                <td className="num-cell">{host.unique_ports}</td>
                                <td style={{ textAlign: 'center' }}>
                                  <span className={`badge badge-${host.severity.toLowerCase()}`}>
                                    {host.severity}
                                  </span>
                                </td>
                                <td className="mono" style={{
                                  fontSize: 11.5,
                                  color: host.classification?.includes('Distributed') ? 'var(--color-critical)' :
                                    host.classification?.includes('Stealth') ? 'var(--color-warning)' :
                                      host.classification?.includes('Vertical') ? 'var(--color-blue)' :
                                        host.classification?.includes('Strobe') ? 'var(--color-purple)' :
                                          'var(--text-secondary)'
                                }}>
                                  {host.classification}
                                </td>
                                <td style={{ textAlign: 'right' }}>
                                  <button className="table-action-btn">
                                    <ArrowRight size={13} />
                                  </button>
                                </td>
                              </tr>
                            )) : (
                              <tr><td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-tertiary)', fontSize: 13 }}>
                                No hosts matching your filters.
                              </td></tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                      <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
                        <span>Showing {sortedFilteredHosts.length} of {report.hosts.length} hosts</span>
                        <span>UNSW-NB15 Verified Ground-Truth Labels</span>
                      </div>
                    </div>

                    {/* INSPECTOR PANEL */}
                    <div className="inspector">
                      {selectedHost ? (
                        <>
                          <div className="inspector-header">
                            <div className="inspector-header-icon" style={{
                              background: selectedHost.severity === 'Critical' ? 'var(--color-critical-bg)' :
                                selectedHost.severity === 'High' ? 'var(--color-warning-bg)' :
                                  selectedHost.severity === 'Medium' ? 'var(--color-warning-bg)' : 'var(--color-success-bg)',
                              color: selectedHost.severity === 'Critical' ? 'var(--color-critical)' :
                                selectedHost.severity === 'High' ? 'var(--color-warning)' :
                                  selectedHost.severity === 'Medium' ? 'var(--color-warning)' : 'var(--color-success)'
                            }}>
                              <ShieldAlert size={16} />
                            </div>
                            <div>
                              <div className="inspector-title">Threat Intelligence</div>
                              <div className="inspector-sub">Host forensics & trigger analysis</div>
                            </div>
                          </div>

                          <div className="inspector-body">
                            {/* Host ID Block */}
                            <div className="info-block" style={{ marginBottom: 16 }}>
                              <div className="info-row">
                                <span className="info-label">Target Host</span>
                                <span className="info-value">{selectedHost.source_ip}</span>
                              </div>
                              <div className="info-row">
                                <span className="info-label">Threat Level</span>
                                <span><span className={`badge badge-${selectedHost.severity.toLowerCase()}`}>{selectedHost.severity}</span></span>
                              </div>
                              <div className="info-row">
                                <span className="info-label">Duration</span>
                                <span className="info-value">{selectedHost.duration_sec}s</span>
                              </div>
                              <div className="info-row">
                                <span className="info-label">Avg Rate</span>
                                <span className="info-value">{selectedHost.conn_rate_per_sec}/s</span>
                              </div>
                              <div className="info-row" style={{ borderBottom: 'none' }}>
                                <span className="info-label">Volume</span>
                                <span className="info-value">{(selectedHost.total_bytes / 1024).toFixed(1)} KB</span>
                              </div>
                            </div>

                            {/* Rule Trigger Reasons */}
                            <div style={{ marginBottom: 14 }}>
                              <div className="section-label" style={{ marginBottom: 8 }}>Rule Trigger Explanations</div>
                              <div className="callout callout-critical" style={{ padding: '10px 12px' }}>
                                <div className="reason-list">
                                  {selectedHost.reason?.split('; ').map((r, i) => (
                                    <div key={i} className="reason-item">
                                      <div className="reason-dot" />
                                      <span>{r}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>

                            {/* Advanced Correlation */}
                            {selectedHost.advanced_classification && selectedHost.advanced_classification !== 'Normal Traffic' && (
                              <div style={{ marginBottom: 14 }}>
                                <div className="section-label" style={{ marginBottom: 8 }}>Advanced Correlation</div>
                                <div className="callout callout-purple" style={{ padding: '10px 12px' }}>
                                  <div className="callout-content">
                                    <div className="callout-title" style={{ color: 'var(--color-purple)', fontSize: 12 }}>
                                      {selectedHost.advanced_classification}
                                    </div>
                                    <div className="callout-text" style={{ fontSize: 11.5 }}>{selectedHost.advanced_reason}</div>
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Connection States */}
                            <div style={{ marginBottom: 14 }}>
                              <div className="section-label" style={{ marginBottom: 8 }}>Connection State Breakdown</div>
                              {Object.entries(selectedHost.states).slice(0, 5).map(([state, count]) => {
                                const pct = (count / selectedHost.total_connections * 100);
                                return (
                                  <div key={state} className="state-bar-item">
                                    <div className="state-bar-label">
                                      <span>{state}</span>
                                      <span>{count.toLocaleString()} ({pct.toFixed(0)}%)</span>
                                    </div>
                                    <div className="state-bar-track">
                                      <div className="state-bar-fill" style={{
                                        width: `${pct}%`,
                                        background: state === 'FIN' ? 'var(--color-success)' :
                                          state === 'CON' ? 'var(--color-blue)' :
                                            state === 'INT' || state === 'REQ' || state === 'RST' ? 'var(--color-critical)' : 'var(--color-warning)'
                                      }} />
                                    </div>
                                  </div>
                                );
                              })}
                            </div>

                            {/* Protocols */}
                            <div style={{ marginBottom: 16 }}>
                              <div className="section-label" style={{ marginBottom: 6 }}>Active Protocols</div>
                              <div className="chip-list">
                                {selectedHost.protocols.slice(0, 10).map(p => (
                                  <span key={p} className="chip">{p.toUpperCase()}</span>
                                ))}
                                {selectedHost.protocols.length > 10 && (
                                  <span className="chip">+{selectedHost.protocols.length - 10} more</span>
                                )}
                              </div>
                            </div>

                            {/* AI CO-PILOT */}
                            {aiAnalysis && (
                              <div className="ai-copilot">
                                <div className="ai-copilot-header">
                                  <div className="ai-copilot-icon">🤖</div>
                                  <span className="ai-copilot-title">AI Security</span>
                                  <span className="ai-copilot-badge">Rule-Based</span>
                                </div>
                                <div className="ai-copilot-body">
                                  <div className="ai-insight">
                                    <div className="ai-insight-icon" style={{ background: 'var(--color-blue-bg)', color: 'var(--color-blue)' }}>🔍</div>
                                    <div className="ai-insight-content">
                                      <div className="ai-insight-label">Attack Explanation</div>
                                      <div className="ai-insight-text">{aiAnalysis.attackExplanation}</div>
                                    </div>
                                  </div>
                                  <div className="ai-insight">
                                    <div className="ai-insight-icon" style={{ background: 'var(--color-warning-bg)', color: 'var(--color-warning)' }}>⚠️</div>
                                    <div className="ai-insight-content">
                                      <div className="ai-insight-label">Threat Prediction</div>
                                      <div className="ai-insight-text">{aiAnalysis.prediction}</div>
                                    </div>
                                  </div>
                                  <div className="ai-insight">
                                    <div className="ai-insight-icon" style={{ background: 'var(--color-success-bg)', color: 'var(--color-success)' }}>🛡️</div>
                                    <div className="ai-insight-content">
                                      <div className="ai-insight-label">Mitigation Rule</div>
                                      <MitigationBlock command={aiAnalysis.mitigation} />
                                    </div>
                                  </div>
                                  <div className="ai-insight">
                                    <div className="ai-insight-icon" style={{ background: 'var(--color-purple-bg)', color: 'var(--color-purple)' }}>📋</div>
                                    <div className="ai-insight-content">
                                      <div className="ai-insight-label">Incident Summary</div>
                                      <div className="ai-insight-text">{aiAnalysis.summary}</div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="inspector-empty">
                          <Eye size={36} className="inspector-empty-icon" />
                          <p className="inspector-empty-text">No host selected.<br />Click any row to inspect threat details and AI analysis.</p>
                        </div>
                      )}
                    </div>
                  </div>
                </section>

                {/* ---- EXPORT BAR ---- */}
                <div className="export-bar">
                  <div className="export-bar-left">
                    <div className="export-bar-title">Threat Report Export Center</div>
                    <div className="export-bar-desc">Download official threat reports for security compliance, firewall policies, or forensic archives.</div>
                  </div>
                  <div className="export-bar-actions">
                    <button onClick={downloadCSV} className="btn btn-default">
                      <Download size={14} /> Download CSV
                    </button>
                    <button onClick={downloadPDF} className="btn btn-primary">
                      <FileText size={14} /> Print PDF Report
                    </button>
                  </div>
                </div>

                {/* ---- INFO CARDS ---- */}
                <section className="section-gap">
                  <div className="info-cards-grid">
                    <div className="info-card">
                      <div className="info-card-header">
                        <div className="info-card-icon" style={{ background: 'var(--color-blue-bg)', color: 'var(--color-blue)' }}><Cpu size={15} /></div>
                        <div className="info-card-title">State Tracking Engine</div>
                      </div>
                      <div className="info-card-text">
                        Constructs a real-time sliding window of traffic metadata to classify threats with high explainability.
                        <br /><br />
                        <strong>Vertical Scan</strong> — ≥ 20 ports on one host. <strong>Horizontal Scan</strong> — ≥ 30 target hosts.
                        <strong> Strobe Scan</strong> — Multiple hosts × multiple ports simultaneously.
                      </div>
                    </div>
                    <div className="info-card">
                      <div className="info-card-header">
                        <div className="info-card-icon" style={{ background: 'var(--color-success-bg)', color: 'var(--color-success)' }}><Database size={15} /></div>
                        <div className="info-card-title">Dataset Validation</div>
                      </div>
                      <div className="info-card-text">
                        Analyzing the <strong>UNSW-NB15</strong> benchmark Netflow partition. The engine processes mixed data types, cleans string formatting, and parses hexadecimal ports.
                        <br /><br />
                        Ground-truth threat categories (Backdoor, Exploits, Generic) are cross-referenced directly from raw CSV labels.
                      </div>
                    </div>
                    <div className="info-card">
                      <div className="info-card-header">
                        <div className="info-card-icon" style={{ background: 'var(--color-purple-bg)', color: 'var(--color-purple)' }}><Zap size={15} /></div>
                        <div className="info-card-title">Advanced Correlation Engine</div>
                      </div>
                      <div className="info-card-text">
                        Detects stealth attack vectors that bypass simple threshold rules.
                        <br /><br />
                        <strong>Distributed Campaigns</strong> — Cross-IP coordinated probes. <strong>Slow Scans</strong> — Low-rate long-duration port sweeps. <strong>Benign Profiling</strong> — Filters high-payload services to reduce false alarms.
                      </div>
                    </div>
                  </div>
                </section>

              </div> {/* end page-content */}

              {/* ============================================================
            PRINT-ONLY REPORT
            ============================================================ */}
              <div className="print-only-report">
                <div className="print-header">
                  <div>
                    <h1>THE NETWORK BOUNCER</h1>
                    <p>NIDS Sliding-Window Threat Analysis Report</p>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <p style={{ fontWeight: 'bold', margin: 0 }}>Date: {new Date().toLocaleDateString()}</p>
                    <p style={{ margin: 0 }}>Dataset: {report.dataset_name ? report.dataset_name.split(/[/\\]/).pop() : 'N/A'}</p>
                  </div>
                </div>

                <div className="print-meta-grid">
                  <div className="print-meta-card">
                    <h3>Total Hosts</h3>
                    <p>{report.summary.total_ips}</p>
                  </div>
                  <div className="print-meta-card" style={{ borderLeft: '3px solid #EF4444' }}>
                    <h3>Suspicious Hosts</h3>
                    <p>{report.summary.suspicious_ips}</p>
                  </div>
                  <div className="print-meta-card" style={{ borderLeft: '3px solid #F59E0B' }}>
                    <h3>High / Critical</h3>
                    <p>{(report.summary.severity_distribution.Critical || 0) + (report.summary.severity_distribution.High || 0)}</p>
                  </div>
                  <div className="print-meta-card" style={{ borderLeft: '3px solid #10B981' }}>
                    <h3>Normal Hosts</h3>
                    <p>{report.summary.normal_ips}</p>
                  </div>
                </div>

                <h2 className="print-section-title">Severity Distribution</h2>
                <table className="print-table">
                  <thead><tr>
                    <th style={{ width: '30%' }}>Severity Level</th>
                    <th>Count</th>
                  </tr></thead>
                  <tbody>
                    <tr><td><span className="print-badge print-badge-critical">Critical</span></td><td>{report.summary.severity_distribution.Critical || 0} hosts</td></tr>
                    <tr><td><span className="print-badge print-badge-high">High</span></td><td>{report.summary.severity_distribution.High || 0} hosts</td></tr>
                    <tr><td><span className="print-badge print-badge-medium">Medium</span></td><td>{report.summary.severity_distribution.Medium || 0} hosts</td></tr>
                    <tr><td><span className="print-badge print-badge-normal">Normal</span></td><td>{report.summary.severity_distribution.Normal || 0} hosts</td></tr>
                  </tbody>
                </table>

                <div className="page-break" />

                <h2 className="print-section-title">Suspicious Traffic &amp; Threat Signatures</h2>
                <table className="print-table">
                  <thead><tr>
                    <th style={{ width: '18%' }}>Source IP</th>
                    <th style={{ width: '10%', textAlign: 'center' }}>Conns</th>
                    <th style={{ width: '10%', textAlign: 'center' }}>Ports</th>
                    <th style={{ width: '14%' }}>Severity</th>
                    <th style={{ width: '48%' }}>Detection Reasoning</th>
                  </tr></thead>
                  <tbody>
                    {report.hosts?.filter(h => h.is_suspicious).length > 0 ? (
                      report.hosts.filter(h => h.is_suspicious).map(host => (
                        <tr key={host.source_ip} className="no-break">
                          <td style={{ fontFamily: 'monospace', fontWeight: 'bold' }}>{host.source_ip}</td>
                          <td style={{ textAlign: 'center', fontFamily: 'monospace' }}>{host.total_connections.toLocaleString()}</td>
                          <td style={{ textAlign: 'center', fontFamily: 'monospace' }}>{host.unique_ports}</td>
                          <td><span className={`print-badge print-badge-${host.severity.toLowerCase()}`}>{host.severity}</span></td>
                          <td>{host.reason || 'Normal traffic behavior'}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan="5" style={{ textAlign: 'center' }}>No suspicious hosts detected.</td></tr>
                    )}
                  </tbody>
                </table>

                <footer style={{ marginTop: '3rem', borderTop: '1px solid #E5E7EB', paddingTop: '1rem', fontSize: '8pt', color: '#9ca3af', textAlign: 'center' }}>
                  This report was generated by The Network Bouncer NIDS. Copyright &copy; {new Date().getFullYear()}. All rights reserved.
                </footer>
              </div>

            </>
          )} {/* end currentPage === 'dashboard' */}

        </div> {/* end main-content */}
      </div> {/* end app-layout */}
    </>
  );
}
