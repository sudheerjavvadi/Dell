/**
 * NewAnalysis.jsx — Upload a CSV and run the Network Bouncer analysis
 * in the browser, then display results in the same dashboard format.
 */
import React, { useState, useRef, useCallback } from 'react';
import {
  Upload, FileText, Cpu, ShieldAlert, AlertTriangle, CheckCircle,
  Shield, Search, ArrowRight, Activity, Database, BarChart2,
  ChevronUp, ChevronDown, ChevronsUpDown, Eye, Sparkles,
  Download, Printer,
} from 'lucide-react';
import { Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement,
  Title, Tooltip, Legend, ArcElement,
} from 'chart.js';
import { analyzeCSV } from '../utils/csvAnalyzer';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement);

/* ── helpers ──────────────────────────────────────────────────────────────── */
function fmtBytes(b) {
  if (b > 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b > 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b > 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function SeverityBadge({ sev }) {
  return <span className={`badge badge-${(sev || 'normal').toLowerCase()}`}>{sev}</span>;
}

/* ── Main component ───────────────────────────────────────────────────────── */
export default function NewAnalysis({ darkMode }) {
  const [dragOver,  setDragOver]  = useState(false);
  const [file,      setFile]      = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress,  setProgress]  = useState({ text: '', pct: 0, rows: 0 });
  const [report,    setReport]    = useState(null);
  const [error,     setError]     = useState(null);

  // Table state
  const [sortCol,   setSortCol]   = useState('total_connections');
  const [sortDir,   setSortDir]   = useState('desc');
  const [search,    setSearch]    = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [selectedIp, setSelectedIp] = useState(null);

  const inputRef  = useRef(null);
  const workerRef = useRef(null);   // holds active Worker instance

  // Terminate worker on component unmount
  React.useEffect(() => {
    return () => { workerRef.current?.terminate(); };
  }, []);

  /* ── File handling ──────────────────────────────────────────────────────── */
  const handleFile = useCallback((f) => {
    if (!f || !f.name.toLowerCase().endsWith('.csv')) {
      setError('Please upload a .csv file.');
      return;
    }
    setFile(f);
    setReport(null);
    setError(null);
    setProgress('');
    setSelectedIp(null);
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, [handleFile]);

  /* ── Run analysis (Web Worker — off main thread) ───────────────────────── */
  const runAnalysis = useCallback(() => {
    if (!file) return;

    // Terminate any previous worker
    if (workerRef.current) {
      workerRef.current.terminate();
      workerRef.current = null;
    }

    setAnalyzing(true);
    setError(null);
    setReport(null);
    setSelectedIp(null);
    setProgress({ text: 'Loading file…', pct: 1, rows: 0 });

    const reader = new FileReader();
    reader.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100 * 0.02); // file read = first 2%
        setProgress({ text: `Reading file… ${Math.round((e.loaded / e.total) * 100)}%`, pct: Math.max(1, pct), rows: 0 });
      }
    };
    reader.onload = (e) => {
      // Spin up the Web Worker
      try {
        const worker = new Worker(
          new URL('../workers/analyzerWorker.js', import.meta.url),
          { type: 'module' }
        );
        workerRef.current = worker;

        worker.onmessage = (msg) => {
          const { type, text, pct, rows, report: result, message } = msg.data;
          if (type === 'progress') {
            setProgress({ text, pct, rows: rows || 0 });
          } else if (type === 'done') {
            setReport(result);
            setProgress({ text: '', pct: 100, rows: 0 });
            setAnalyzing(false);
            if (result.suspicious_hosts.length > 0) {
              setSelectedIp(result.suspicious_hosts[0].source_ip);
            }
            worker.terminate();
            workerRef.current = null;
          } else if (type === 'error') {
            setError('Analysis failed: ' + message);
            setAnalyzing(false);
            worker.terminate();
            workerRef.current = null;
          }
        };

        worker.onerror = (err) => {
          setError('Worker error: ' + (err.message || 'Unknown error'));
          setAnalyzing(false);
          workerRef.current = null;
        };

        worker.postMessage({ csvText: e.target.result, filename: file.name });

      } catch (workerErr) {
        // Fallback: run on main thread if Worker not supported
        setProgress({ text: 'Analysing (fallback mode)…', pct: 50, rows: 0 });
        setTimeout(async () => {
          try {
            const { analyzeCSV } = await import('../utils/csvAnalyzer.js').catch(() => ({ analyzeCSV: null }));
            if (!analyzeCSV) throw new Error('Analyser unavailable');
            const result = analyzeCSV(e.target.result, file.name);
            setReport(result);
            if (result.suspicious_hosts.length > 0) setSelectedIp(result.suspicious_hosts[0].source_ip);
          } catch (err2) {
            setError('Analysis failed: ' + err2.message);
          } finally {
            setAnalyzing(false);
            setProgress({ text: '', pct: 0, rows: 0 });
          }
        }, 20);
      }
    };
    reader.onerror = () => {
      setError('Failed to read file.');
      setAnalyzing(false);
    };
    reader.readAsText(file);
  }, [file]);

  /* ── Derived data from report ───────────────────────────────────────────── */
  const sortedFilteredHosts = report
    ? [...report.hosts]
        .filter(h => {
          if (!h.is_suspicious) return false;
          if (search && !h.source_ip.includes(search)) return false;
          if (sevFilter !== 'ALL' && h.severity !== sevFilter) return false;
          return true;
        })
        .sort((a, b) => {
          const av = a[sortCol], bv = b[sortCol];
          const dir = sortDir === 'asc' ? 1 : -1;
          if (typeof av === 'string') return av.localeCompare(bv) * dir;
          return ((av ?? 0) - (bv ?? 0)) * dir;
        })
    : [];

  const selectedHost = report?.hosts.find(h => h.source_ip === selectedIp) || null;

  const handleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const SortIcon = ({ col }) => {
    if (sortCol !== col) return <ChevronsUpDown size={10} style={{ opacity: 0.35 }} />;
    return sortDir === 'asc' ? <ChevronUp size={10} /> : <ChevronDown size={10} />;
  };

  /* ── Download handlers ──────────────────────────────────────────────────── */
  const downloadCSV = useCallback(() => {
    if (!report) return;

    // Safe cell serializer — handles strings, numbers, arrays, objects
    const cell = (v) => {
      if (v === null || v === undefined) return '""';
      if (Array.isArray(v)) return `"${v.join(', ').replace(/"/g, '""')}"`;
      if (typeof v === 'object') return `"${JSON.stringify(v).replace(/"/g, '""')}"`;
      return `"${String(v).replace(/"/g, '""')}"`;
    };

    const headers = [
      'Source IP', 'Total Connections', 'Unique Destinations', 'Unique Ports',
      'Total Bytes (B)', 'Total Packets', 'Duration (sec)', 'Conn Rate (/sec)',
      'Peak Window IPs', 'Peak Window Ports', 'Protocols', 'Services',
      'Severity', 'Classification', 'Detection Reason',
      'Labeled Attacks', 'Attack Category',
    ];

    const rows = report.hosts
      .filter(h => h.is_suspicious)
      .sort((a, b) => {
        const order = { Critical: 0, High: 1, Medium: 2, Normal: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      })
      .map(h => [
        cell(h.source_ip),
        cell(h.total_connections),
        cell(h.unique_destinations),
        cell(h.unique_ports),
        cell(h.total_bytes),
        cell(h.total_packets),
        cell(h.duration_sec),
        cell(h.conn_rate_per_sec),
        cell(h.peak_window_ips),
        cell(h.peak_window_ports),
        cell(h.protocols),
        cell(h.services),
        cell(h.severity),
        cell(h.classification),
        cell(h.reason || 'Normal traffic behavior'),
        cell(h.labeled_attacks_count ?? 0),
        cell(h.true_attack_cat || 'N/A'),
      ]);

    const csv = [headers.map(h => `"${h}"`).join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' }); // BOM for Excel
    const url  = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const name = (report.dataset_name || 'analysis').replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_');
    link.href     = url;
    link.download = `bouncer_report_${name}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, [report]);

  const downloadPDF = useCallback(() => {
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
  <script>window.onload = () => { window.focus(); window.print(); };<\/script>
</body>
</html>`;

    const win = window.open('', '_blank', 'width=900,height=700');
    if (!win) {
      alert('Pop-up blocked. Please allow pop-ups for this site and try again.');
      return;
    }
    win.document.write(html);
    win.document.close();
  }, [report]);



  /* ── Chart configs ──────────────────────────────────────────────────────── */
  const isDark = darkMode;
  const textColor = isDark ? '#9ca3af' : '#6b7280';

  const doughnutData = report ? {
    labels: ['Critical', 'High', 'Medium', 'Normal'],
    datasets: [{
      data: [
        report.summary.severity_distribution.Critical,
        report.summary.severity_distribution.High,
        report.summary.severity_distribution.Medium,
        report.summary.severity_distribution.Normal,
      ],
      backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981'],
      borderWidth: 0,
    }],
  } : null;

  const barData = report ? {
    labels: report.suspicious_hosts.slice(0, 8).map(h => h.source_ip),
    datasets: [
      {
        label: 'Connections',
        data: report.suspicious_hosts.slice(0, 8).map(h => h.total_connections),
        backgroundColor: '#3b82f6',
        borderRadius: 4,
      },
      {
        label: 'Unique Ports',
        data: report.suspicious_hosts.slice(0, 8).map(h => h.unique_ports),
        backgroundColor: '#8b5cf6',
        borderRadius: 4,
      },
    ],
  } : null;

  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: textColor, font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: textColor, font: { size: 10 } }, grid: { color: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)' } },
      y: { ticks: { color: textColor, font: { size: 10 } }, grid: { color: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)' } },
    },
  };

  const doughnutOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { color: textColor, font: { size: 11 }, padding: 12 } } },
  };

  /* ── Render ─────────────────────────────────────────────────────────────── */
  return (
    <div className="page-content">

      {/* ── Upload Card ── */}
      {!report && (
        <div className="na-upload-section">
          <div className="section-header" style={{ marginBottom: 20 }}>
            <div>
              <div className="section-title">
                <div className="section-title-dot" style={{ background: 'var(--color-blue)' }} />
                New Network Analysis
              </div>
              <div className="section-subtitle">
                Upload any network flow CSV — the browser runs the full NIDS detection engine locally, no data leaves your machine.
              </div>
            </div>
          </div>

          {/* Drop zone */}
          <div
            className={`na-dropzone ${dragOver ? 'na-dropzone-active' : ''} ${file ? 'na-dropzone-ready' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".csv"
              style={{ display: 'none' }}
              onChange={(e) => handleFile(e.target.files[0])}
            />
            {file ? (
              <>
                <div className="na-drop-icon na-drop-icon-ready"><FileText size={28} /></div>
                <div className="na-drop-title">{file.name}</div>
                <div className="na-drop-sub">{(file.size / 1024).toFixed(1)} KB · Click to change file</div>
              </>
            ) : (
              <>
                <div className="na-drop-icon"><Upload size={28} /></div>
                <div className="na-drop-title">Drag &amp; drop a CSV file here</div>
                <div className="na-drop-sub">or click to browse · Supports UNSW-NB15, network_log.csv, and any netflow CSV</div>
              </>
            )}
          </div>

          {/* Supported formats hint */}
          <div className="na-hint-row">
            <div className="na-hint-card">
              <Database size={13} style={{ color: 'var(--color-blue)' }} />
              <span><strong>Headered CSV</strong> — any file with column names (srcip, dstip, dsport…)</span>
            </div>
            <div className="na-hint-card">
              <Cpu size={13} style={{ color: 'var(--color-purple)' }} />
              <span><strong>UNSW-NB15</strong> — raw 49-column benchmark files (auto-detected)</span>
            </div>
            <div className="na-hint-card">
              <Activity size={13} style={{ color: 'var(--color-success)' }} />
              <span><strong>In-browser</strong> — analysis runs locally, nothing is uploaded to any server</span>
            </div>
          </div>

          {error && (
            <div className="callout callout-critical" style={{ marginTop: 16 }}>
              <div className="callout-icon">⚠️</div>
              <div className="callout-content">
                <div className="callout-title">Error</div>
                <div className="callout-text">{error}</div>
              </div>
            </div>
          )}

          {/* ── Analyze button or Progress bar ── */}
          {file && !analyzing && (
            <button
              className="btn btn-primary"
              style={{ marginTop: 20, width: '100%', justifyContent: 'center', padding: '12px 0', fontSize: 14 }}
              onClick={runAnalysis}
            >
              <Cpu size={15} /> Run NIDS Analysis
            </button>
          )}

          {analyzing && (
            <div className="na-progress-wrap">
              <div className="na-progress-header">
                <Sparkles size={14} style={{ animation: 'spin 1.2s linear infinite', color: 'var(--color-blue)' }} />
                <span className="na-progress-text">{progress.text || 'Initialising…'}</span>
                {progress.rows > 0 && (
                  <span className="na-progress-rows">{progress.rows.toLocaleString()} rows</span>
                )}
                <button
                  className="topbar-btn topbar-btn-icon"
                  style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--color-critical)' }}
                  onClick={() => {
                    workerRef.current?.terminate();
                    workerRef.current = null;
                    setAnalyzing(false);
                    setProgress({ text: '', pct: 0, rows: 0 });
                    setError('Analysis cancelled.');
                  }}
                  title="Cancel analysis"
                >
                  ✕ Cancel
                </button>
              </div>
              <div className="na-progress-bar-track">
                <div
                  className="na-progress-bar-fill"
                  style={{ width: `${Math.max(2, progress.pct || 0)}%` }}
                />
              </div>
              <div className="na-progress-pct">{progress.pct || 0}%</div>
            </div>
          )}
        </div>
      )}


      {/* ── Results ── */}
      {report && (
        <>
          {/* Back + summary banner */}
          <div className="na-result-header">
            <button className="topbar-btn" onClick={() => { setReport(null); setFile(null); }}>
              ← New Analysis
            </button>
            <div style={{ flex: 1 }}>
              <div className="section-title">
                <div className="section-title-dot" style={{ background: 'var(--color-success)' }} />
                Analysis Complete — {report.dataset_name}
              </div>
              <div className="section-subtitle">
                {report.summary.total_ips} unique hosts · {report.summary.suspicious_ips} flagged suspicious
              </div>
            </div>
          </div>

          {/* Overview cards */}
          <div className="metrics-grid" style={{ marginBottom: 20 }}>
            {[
              { label: 'Critical', val: report.summary.severity_distribution.Critical, cls: 'card-critical', icon: <ShieldAlert size={16} /> },
              { label: 'High Risk', val: report.summary.severity_distribution.High,     cls: 'card-high',     icon: <AlertTriangle size={16} /> },
              { label: 'Medium Risk', val: report.summary.severity_distribution.Medium, cls: 'card-medium',   icon: <Shield size={16} /> },
              { label: 'Normal Nodes', val: report.summary.normal_ips,                  cls: 'card-success',  icon: <CheckCircle size={16} /> },
            ].map(c => (
              <div key={c.label} className={`card ${c.cls}`}>
                <div className="card-header"><span className="card-label">{c.label}</span><div className="card-icon">{c.icon}</div></div>
                <div className="card-value">{c.val}</div>
              </div>
            ))}
          </div>

          {/* Charts */}
          {report.suspicious_hosts.length > 0 && (
            <div className="charts-grid" style={{ marginBottom: 20 }}>
              <div className="chart-card">
                <div className="chart-title">Threat Level Breakdown</div>
                <div className="chart-wrapper" style={{ height: 220 }}>
                  <Doughnut data={doughnutData} options={doughnutOpts} />
                </div>
              </div>
              <div className="chart-card">
                <div className="chart-title">Top Suspicious IPs</div>
                <div className="chart-wrapper" style={{ height: 240 }}>
                  <Bar data={barData} options={chartOpts} />
                </div>
              </div>
            </div>
          )}

          {/* Table + Inspector */}
          <div className="content-grid">
            {/* Table */}
            <div>
              {/* Search/filter bar */}
              <div className="filter-bar" style={{ marginBottom: 10 }}>
                <div className="search-box">
                  <Search size={13} className="search-box-icon" />
                  <input type="text" placeholder="Search IP…" value={search}
                    onChange={e => setSearch(e.target.value)} className="search-input" />
                </div>
                <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} className="filter-select">
                  <option value="ALL">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                </select>
              </div>

              <div className="data-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
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
                    {sortedFilteredHosts.length > 0 ? sortedFilteredHosts.map(host => (
                      <tr key={host.source_ip}
                        onClick={() => setSelectedIp(host.source_ip)}
                        className={selectedIp === host.source_ip ? 'active' : ''}>
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
                          <SeverityBadge sev={host.severity} />
                        </td>
                        <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                          {host.classification}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button className="table-action-btn"><ArrowRight size={13} /></button>
                        </td>
                      </tr>
                    )) : (
                      <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: 'var(--text-tertiary)', fontSize: 13 }}>
                        {report.suspicious_hosts.length === 0
                          ? '✅ No suspicious activity detected in this dataset.'
                          : 'No hosts matching your filters.'}
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
                Showing {sortedFilteredHosts.length} of {report.summary.suspicious_ips} flagged hosts
              </div>
            </div>

            {/* Inspector */}
            <div className="inspector">
              {selectedHost ? (
                <>
                  <div className="inspector-header">
                    <div className="inspector-header-icon" style={{
                      background: selectedHost.severity === 'Critical' ? 'var(--color-critical-bg)' : 'var(--color-warning-bg)',
                      color: selectedHost.severity === 'Critical' ? 'var(--color-critical)' : 'var(--color-warning)',
                    }}>
                      <ShieldAlert size={16} />
                    </div>
                    <div>
                      <div className="inspector-title">Threat Intelligence</div>
                      <div className="inspector-sub">Host forensics &amp; trigger analysis</div>
                    </div>
                  </div>

                  <div className="inspector-body">
                    {/* Host details */}
                    <div className="info-block" style={{ marginBottom: 14 }}>
                      {[
                        ['Source IP',    selectedHost.source_ip],
                        ['Threat Level', null],
                        ['Connections',  selectedHost.total_connections.toLocaleString()],
                        ['Unique Dsts',  selectedHost.unique_destinations],
                        ['Unique Ports', selectedHost.unique_ports],
                        ['Conn Rate',    `${selectedHost.conn_rate_per_sec}/s`],
                        ['Duration',     `${selectedHost.duration_sec}s`],
                        ['Data Volume',  fmtBytes(selectedHost.total_bytes)],
                      ].map(([label, val], i) => (
                        <div key={i} className="info-row" style={i === 7 ? { borderBottom: 'none' } : {}}>
                          <span className="info-label">{label}</span>
                          {label === 'Threat Level'
                            ? <SeverityBadge sev={selectedHost.severity} />
                            : <span className="info-value">{val}</span>
                          }
                        </div>
                      ))}
                    </div>

                    {/* Detection reason */}
                    <div style={{ marginBottom: 14 }}>
                      <div className="section-label" style={{ marginBottom: 8 }}>Detection Reason</div>
                      <div className="callout callout-critical" style={{ padding: '10px 12px' }}>
                        <div className="reason-list">
                          {(selectedHost.reason || 'No specific reason recorded.').split('; ').map((r, i) => (
                            <div key={i} className="reason-item">
                              <div className="reason-dot" />
                              <span>{r}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Connection states */}
                    {selectedHost.states && Object.keys(selectedHost.states).length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div className="section-label" style={{ marginBottom: 8 }}>Connection States</div>
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
                                    state === 'CON' ? 'var(--color-blue)' : 'var(--color-critical)',
                                }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* Protocols */}
                    {selectedHost.protocols?.length > 0 && (
                      <div>
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
                    )}
                  </div>
                </>
              ) : (
                <div className="inspector-empty">
                  <Eye size={36} className="inspector-empty-icon" />
                  <p className="inspector-empty-text">
                    No host selected.<br />Click any row to inspect threat details.
                  </p>
                </div>
              )}
            </div>
          </div> {/* end content-grid */}

          {/* ── Export / Download Bar ── */}
          <div className="export-bar">
            <div className="export-bar-info">
              <BarChart2 size={14} style={{ color: 'var(--color-blue)' }} />
              <span>
                <strong>{report.summary.suspicious_ips}</strong> suspicious hosts detected out of{' '}
                <strong>{report.summary.total_ips}</strong> total · Dataset: <em>{report.dataset_name}</em>
              </span>
            </div>
            <div className="export-bar-actions">
              <button onClick={downloadCSV} className="btn btn-default">
                <Download size={14} /> Download CSV
              </button>
              <button onClick={downloadPDF} className="btn btn-primary">
                <Printer size={14} /> Print PDF Report
              </button>
            </div>
          </div>

        </> /* end results fragment */
      )}
    </div>
  );
}
