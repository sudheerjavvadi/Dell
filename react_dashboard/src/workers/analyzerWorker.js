/**
 * analyzerWorker.js — Web Worker for off-thread CSV analysis
 *
 * Runs in a background thread so the UI stays responsive
 * even for files with millions of rows (e.g. UNSW-NB15).
 *
 * Message protocol:
 *   IN  : { csvText: string, filename: string }
 *   OUT : { type: 'progress', text: string, pct: number, rows: number }
 *       | { type: 'done',     report: object }
 *       | { type: 'error',    message: string }
 */
import { parseCSV, aggregateRows, applyRules } from '../utils/csvAnalyzer.js';

self.onmessage = function (e) {
  const { csvText, filename } = e.data;

  try {
    /* ── Step 1: Parse header + get data text ───────────────────────────── */
    self.postMessage({ type: 'progress', text: 'Parsing CSV structure…', pct: 2, rows: 0 });

    const { headers, dataText } = parseCSV(csvText);

    /* ── Step 2: Aggregate rows with live progress ──────────────────────── */
    self.postMessage({ type: 'progress', text: 'Reading flows…', pct: 5, rows: 0 });

    const ipMap = aggregateRows(dataText, headers, (processed, estimated) => {
      // Progress from 5% to 85% during aggregation
      const pct = Math.min(85, 5 + Math.round((processed / Math.max(estimated, 1)) * 80));
      self.postMessage({
        type: 'progress',
        text: `Aggregating flows: ${processed.toLocaleString()} rows processed…`,
        pct,
        rows: processed,
      });
    });

    const uniqueIPs = ipMap.size;

    /* ── Step 3: Apply NIDS detection rules ─────────────────────────────── */
    self.postMessage({
      type: 'progress',
      text: `Applying NIDS rules across ${uniqueIPs.toLocaleString()} unique IPs…`,
      pct: 88,
      rows: 0,
    });

    const report = applyRules(ipMap, filename);

    self.postMessage({ type: 'progress', text: 'Building report…', pct: 97, rows: 0 });

    /* ── Done ────────────────────────────────────────────────────────────── */
    self.postMessage({ type: 'done', report });

  } catch (err) {
    self.postMessage({ type: 'error', message: err.message || String(err) });
  }
};
