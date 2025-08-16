import React, { useMemo, useState } from "react";
import { analyzeLogs, Anomaly } from "./parsers";

type TableRow = { label: string; value: number };

export default function App() {
  const [logs, setLogs] = useState("");
  const [results, setResults] = useState<{ anomalies: Anomaly[] } | null>(null);

  const handleAnalyze = () => {
    const r = analyzeLogs(logs);
    setResults({ anomalies: r.anomalies });
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setLogs(text);
  };

  const anomalies = results?.anomalies || [];

  // Quick stats by type
  const countsByType = useMemo(() => {
    const m: Record<string, number> = {};
    for (const a of anomalies) m[a.type] = (m[a.type] || 0) + 1;
    return Object.entries(m).map(([label, value]) => ({ label, value }));
  }, [anomalies]);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
          <div>
            <h1 className="text-3xl font-bold">🕵️ Log Checker</h1>
            <p className="text-gray-400">Analyze pasted or uploaded logs for quick anomaly insights. Runs 100% in your browser.</p>
          </div>
          <a
            href="https://github.com/new"
            target="_blank"
            rel="noreferrer noopener"
            className="px-4 py-2 bg-green-500 text-black rounded font-semibold hover:bg-green-400"
          >
            Fork this on GitHub
          </a>
        </header>

        <section className="grid lg:grid-cols-2 gap-6">
          <div className="space-y-3">
            <textarea
              className="w-full h-64 p-3 rounded bg-gray-800 text-sm font-mono"
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
              placeholder="Paste server logs here (Apache/Nginx combined format or SSH auth logs)..."
            />
            <div className="flex items-center gap-3">
              <input type="file" accept=".log,.txt,.csv" onChange={handleFileUpload} className="block" />
              <button className="px-5 py-2 bg-green-500 text-black font-bold rounded hover:bg-green-400" onClick={handleAnalyze}>
                Analyze Logs
              </button>
            </div>
            <p className="text-xs text-gray-500">
              Tip: try the sample file from the repo <code>samples/nginx_access_sample.log</code> to see detections.
            </p>
          </div>

          <div className="bg-gray-800 rounded p-4">
            <h2 className="text-xl font-semibold mb-2">Summary</h2>
            {anomalies.length === 0 ? (
              <p className="text-gray-400">No anomalies yet. Paste logs and click Analyze.</p>
            ) : (
              <ul className="grid grid-cols-2 gap-2">
                {countsByType.map((r) => (
                  <li key={r.label} className="bg-gray-900 rounded p-3 flex items-center justify-between">
                    <span className="text-gray-300">{r.label}</span>
                    <span className="text-green-400 font-mono">{r.value}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section className="bg-gray-800 rounded p-4">
          <h2 className="text-xl font-semibold mb-2">Anomalies</h2>
          {anomalies.length === 0 ? (
            <p className="text-gray-400">No anomalies detected.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {anomalies.map((a, i) => (
                <li key={i} className="bg-gray-900 rounded p-3">
                  <div><span className="font-semibold">{a.type}:</span> {a.message}</div>
                  {a.line && <pre className="mt-1 text-gray-500 text-xs overflow-auto">{a.line}</pre>}
                </li>
              ))}
            </ul>
          )}
        </section>

        <footer className="text-xs text-gray-500">
          Local-only: files are read in your browser; no data is sent anywhere. Add rules easily in <code>src/parsers.ts</code>.
        </footer>
      </div>
    </div>
  );
}
