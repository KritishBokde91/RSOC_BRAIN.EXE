import { useState, useCallback, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

/* ── Tauri response types ─────────────────────────────────────────── */

interface AppContext {
  workspaceRoot: string;
  defaultContainerImage: string;
  dockerAvailable: boolean;
  dockerMessage: string;
  neo4jEnvConfigured: boolean;
  defaultOllamaHost: string;
  defaultEmbeddingModel: string;
  defaultRerankerModel: string;
  defaultLlmBaseUrl: string;
  defaultLlmModel: string;
  llmApiKeyConfigured: boolean;
}

interface SecurityVulnerability {
  id: string;
  file: string;
  line: number;
  endLine: number;
  severity: string;
  owaspCategory: string;
  vulnType: string;
  title: string;
  description: string;
  originalCode: string;
  fixedCode: string;
  confidence: number;
  aiExplanation: string | null;
  detectionLayer: string;
}

interface PipelineStep {
  stage: string;
  message: string;
  durationMs: number;
}

interface FullScanResult {
  workspaceRoot: string;
  scannedFiles: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  vulnerabilities: SecurityVulnerability[];
  pipelineLog: PipelineStep[];
  warnings: string[];
}

interface FixResult {
  success: boolean;
  message: string;
}

/* ── Streaming event payloads ─────────────────────────────────────── */

interface ScanStagePayload {
  stage: string;
  message: string;
  durationMs: number;
}

interface ScanProgressPayload {
  currentFile: string;
  scannedSoFar: number;
  vulnsFoundSoFar: number;
}

/* ── Helpers ───────────────────────────────────────────────────── */

const severityColor: Record<string, string> = {
  Critical: "#ff4757",
  High: "#ffa502",
  Medium: "#f7c35f",
  Low: "#72a0ff",
};

const severityBorder: Record<string, string> = {
  Critical: "rgba(255, 71, 87, 0.6)",
  High: "rgba(255, 165, 2, 0.5)",
  Medium: "rgba(247, 195, 95, 0.4)",
  Low: "rgba(114, 160, 255, 0.3)",
};

type ScanStage =
  | "idle"
  | "scanning"
  | "analyzing"
  | "complete"
  | "error";

type SeverityFilter = "All" | "Critical" | "High" | "Medium" | "Low";

/* ── App ──────────────────────────────────────────────────────────── */

function App() {
  // Context
  const [appContext, setAppContext] = useState<AppContext | null>(null);
  const [contextError, setContextError] = useState("");
  const [selectedWorkspace, setSelectedWorkspace] = useState<string>("");

  // Scan state
  const [scanStage, setScanStage] = useState<ScanStage>("idle");
  const [scanResult, setScanResult] = useState<FullScanResult | null>(null);
  const [scanError, setScanError] = useState("");

  // Streaming state
  const [streamingVulns, setStreamingVulns] = useState<SecurityVulnerability[]>([]);
  const [currentFile, setCurrentFile] = useState("");
  const [scannedCount, setScannedCount] = useState(0);
  const [stageMessage, setStageMessage] = useState("");

  // Fix tracking
  const [fixedIds, setFixedIds] = useState<Set<string>>(new Set());
  const [skippedIds, setSkippedIds] = useState<Set<string>>(new Set());
  const [fixingId, setFixingId] = useState<string | null>(null);

  // Expanded vulnerability
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("All");
  const [searchQuery, setSearchQuery] = useState("");

  const scrollRef = useRef<HTMLDivElement>(null);
  const unlistenRefs = useRef<UnlistenFn[]>([]);

  /* ── Load context on mount ─────────────────────────────────────── */
  useEffect(() => {
    invoke<AppContext>("load_app_context")
      .then((context) => {
        setAppContext(context);
        setSelectedWorkspace(context.workspaceRoot);
      })
      .catch((e) => setContextError(String(e)));
  }, []);

  /* ── Change workspace ──────────────────────────────────────────── */
  const handleBrowseWorkspace = useCallback(async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Workspace to Scan",
      });
      if (selected && typeof selected === "string") {
        setSelectedWorkspace(selected);
      }
    } catch (e) {
      console.error("Error opening dialog", e);
    }
  }, []);

  /* ── Setup streaming listeners ─────────────────────────────────── */
  const setupStreamListeners = useCallback(async () => {
    // Cleanup any existing listeners
    for (const unlisten of unlistenRefs.current) {
      unlisten();
    }
    unlistenRefs.current = [];

    const u1 = await listen<ScanStagePayload>("scan-stage", (event) => {
      const { stage, message } = event.payload;
      setStageMessage(message);
      if (stage === "scanning") setScanStage("scanning");
      else if (stage === "analyzing") setScanStage("analyzing");
      else if (stage === "complete") setScanStage("complete");
      else if (stage === "llm-skipped") setScanStage("complete");
    });

    const u2 = await listen<ScanProgressPayload>("scan-progress", (event) => {
      const { currentFile: file, scannedSoFar } = event.payload;
      setCurrentFile(file);
      setScannedCount(scannedSoFar);
    });

    const u3 = await listen<SecurityVulnerability>("scan-vuln-found", (event) => {
      setStreamingVulns((prev) => [...prev, event.payload]);
    });

    unlistenRefs.current = [u1, u2, u3];
  }, []);

  /* ── Full scan ─────────────────────────────────────────────────── */
  const startScan = useCallback(async () => {
    if (!appContext) return;
    setScanStage("scanning");
    setScanError("");
    setScanResult(null);
    setFixedIds(new Set());
    setSkippedIds(new Set());
    setExpandedId(null);
    setStreamingVulns([]);
    setCurrentFile("");
    setScannedCount(0);
    setStageMessage("Initializing scan…");
    setSeverityFilter("All");
    setSearchQuery("");

    await setupStreamListeners();

    try {
      const result = await invoke<FullScanResult>("full_security_scan", {
        request: { workspaceRoot: selectedWorkspace || appContext.workspaceRoot },
      });
      setScanResult(result);
      setScanStage("complete");
      if (result.vulnerabilities.length > 0) {
        // Auto-expand first critical, or first vuln
        const firstCritical = result.vulnerabilities.find((v) => v.severity === "Critical");
        setExpandedId(firstCritical?.id ?? result.vulnerabilities[0].id);
      }
    } catch (e) {
      setScanError(String(e));
      setScanStage("error");
    }

    // Cleanup listeners
    for (const unlisten of unlistenRefs.current) {
      unlisten();
    }
    unlistenRefs.current = [];
  }, [appContext, selectedWorkspace, setupStreamListeners]);

  /* ── Apply fix ─────────────────────────────────────────────────── */
  const applyFix = useCallback(
    async (vuln: SecurityVulnerability) => {
      if (!appContext || !scanResult) return;
      setFixingId(vuln.id);
      try {
        const result = await invoke<FixResult>("apply_vulnerability_fix", {
          request: {
            workspaceRoot: scanResult.workspaceRoot,
            vulnerabilityId: vuln.id,
            fixedCode: vuln.fixedCode,
            file: vuln.file,
            line: vuln.line,
            endLine: vuln.endLine,
          },
        });
        if (result.success) {
          setFixedIds((prev) => new Set(prev).add(vuln.id));
        } else {
          setScanError(`Fix failed: ${result.message}`);
        }
      } catch (e) {
        setScanError(String(e));
      } finally {
        setFixingId(null);
      }
    },
    [appContext, scanResult]
  );

  const skipVuln = useCallback((id: string) => {
    setSkippedIds((prev) => new Set(prev).add(id));
  }, []);

  /* ── Computed values ───────────────────────────────────────────── */
  const displayVulns = scanResult?.vulnerabilities ?? streamingVulns;
  const filteredVulns = displayVulns.filter((v) => {
    if (fixedIds.has(v.id) || skippedIds.has(v.id)) return true; // Still show but dimmed
    if (severityFilter !== "All" && v.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        v.file.toLowerCase().includes(q) ||
        v.vulnType.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.description.toLowerCase().includes(q) ||
        v.owaspCategory.toLowerCase().includes(q)
      );
    }
    return true;
  });
  const activeVulns = filteredVulns.filter(
    (v) => !fixedIds.has(v.id) && !skippedIds.has(v.id)
  );
  const fixedCount = fixedIds.size;
  const skippedCount = skippedIds.size;
  const isScanning = scanStage === "scanning" || scanStage === "analyzing";

  /* ── Loading ───────────────────────────────────────────────────── */
  if (!appContext && !contextError) {
    return (
      <div className="app-shell">
        <div className="loading-splash">
          <div className="loading-spinner" />
          <p>Initializing AetherVerify…</p>
        </div>
      </div>
    );
  }

  /* ── Render ─────────────────────────────────────────────────────── */
  return (
    <div className="app-shell" ref={scrollRef}>
      {/* ── Hero ─────────────────────────────────────────────────── */}
      <header className="hero-panel">
        <div>
          <p className="eyebrow">Security Scanner</p>
          <h1>AetherVerify</h1>
          <p className="hero-copy">
            Dynamic + static security analysis powered by AI.
            One-click vulnerability detection, intelligent fix generation,
            and diff-based code repair.
          </p>
        </div>
        <div className="hero-metrics">
          <div className="metric-card">
            <strong>🐳 Docker</strong>
            <p>
              {appContext?.dockerAvailable
                ? `✅ ${appContext.dockerMessage}`
                : `❌ ${appContext?.dockerMessage ?? "Not connected"}`}
            </p>
          </div>
          <div className="metric-card">
            <strong>🧠 LLM</strong>
            <p>
              {appContext?.llmApiKeyConfigured
                ? `✅ ${appContext.defaultLlmModel || "Configured"}`
                : "❌ Set GROQ_API_KEY in .env"}
            </p>
          </div>
          <div className="metric-card">
            <strong>🔬 Embeddings</strong>
            <p>{appContext?.defaultEmbeddingModel || "Not configured"}</p>
          </div>
        </div>
      </header>

      {contextError && <div className="app-error">⚠️ {contextError}</div>}

      {/* ── Workspace Selector ────────────────────────────────────── */}
      <section className="workspace-section">
        <div className="workspace-row">
          <label className="workspace-label">📁 Workspace</label>
          <div className="workspace-input-group">
            <input
              type="text"
              className="workspace-input"
              value={selectedWorkspace}
              onChange={(e) => setSelectedWorkspace(e.target.value)}
              placeholder="Enter workspace path…"
              disabled={isScanning}
            />
            <button
              className="workspace-browse-btn"
              onClick={handleBrowseWorkspace}
              disabled={isScanning}
            >
              Browse
            </button>
          </div>
        </div>
      </section>

      {/* ── Scan Controls ────────────────────────────────────────── */}
      <section className="scan-section">
        <div className="scan-header">
          <div className="scan-title-row">
            <h2>🛡️ Security Analysis</h2>
            {scanStage !== "idle" && scanStage !== "error" && (
              <div className="pipeline-stepper">
                <span className={`step ${scanStage === "scanning" || scanStage === "analyzing" || scanStage === "complete" ? "step-done" : ""}`}>
                  ① Scan
                </span>
                <span className="step-arrow">→</span>
                <span className={`step ${scanStage === "analyzing" || scanStage === "complete" ? "step-done" : ""}`}>
                  ② AI Analysis
                </span>
                <span className="step-arrow">→</span>
                <span className={`step ${scanStage === "complete" ? "step-done" : ""}`}>
                  ③ Results
                </span>
              </div>
            )}
          </div>

          <button
            className="scan-button"
            onClick={startScan}
            disabled={isScanning || !appContext || !selectedWorkspace}
          >
            {isScanning ? (
              <>
                <span className="scan-spinner" />
                {scanStage === "scanning" ? "Scanning…" : "AI Analyzing…"}
              </>
            ) : (
              "🛡️ Scan & Secure"
            )}
          </button>
        </div>

        {/* ── Live Progress ────────────────────────────────────────── */}
        {isScanning && (
          <div className="live-progress">
            <div className="live-progress-header">
              <span className="live-pulse" />
              <span className="live-stage-msg">{stageMessage}</span>
            </div>
            {scanStage === "scanning" && (
              <div className="live-details">
                <span className="live-file-count">{scannedCount} files scanned</span>
                <span className="live-vuln-count">{streamingVulns.length} vulnerabilities found</span>
              </div>
            )}
            {currentFile && scanStage === "scanning" && (
              <div className="live-current-file">
                <code>{currentFile}</code>
              </div>
            )}
            <div className="live-progress-bar">
              <div className="live-progress-fill live-progress-animated" />
            </div>
          </div>
        )}

        {scanError && <div className="app-error">⚠️ {scanError}</div>}

        {/* ── Results ──────────────────────────────────────────── */}
        {(scanResult || (streamingVulns.length > 0 && scanStage === "complete")) && (
          <>
            {/* Summary bar */}
            <div className="results-summary">
              <div className="summary-grid">
                <div className="summary-card">
                  <span>Files Scanned</span>
                  <strong>{scanResult?.scannedFiles ?? scannedCount}</strong>
                </div>
                <div className="summary-card">
                  <span>Total Found</span>
                  <strong>{scanResult?.totalVulnerabilities ?? streamingVulns.length}</strong>
                </div>
                <div className="summary-card" style={{ borderColor: "rgba(255,71,87,0.3)" }}>
                  <span>Critical</span>
                  <strong style={{ color: "#ff4757" }}>{scanResult?.criticalCount ?? streamingVulns.filter(v => v.severity === "Critical").length}</strong>
                </div>
                <div className="summary-card" style={{ borderColor: "rgba(255,165,2,0.3)" }}>
                  <span>High</span>
                  <strong style={{ color: "#ffa502" }}>{scanResult?.highCount ?? streamingVulns.filter(v => v.severity === "High").length}</strong>
                </div>
                <div className="summary-card" style={{ borderColor: "rgba(247,195,95,0.3)" }}>
                  <span>Medium</span>
                  <strong style={{ color: "#f7c35f" }}>{scanResult?.mediumCount ?? streamingVulns.filter(v => v.severity === "Medium").length}</strong>
                </div>
                <div className="summary-card" style={{ borderColor: "rgba(114,160,255,0.3)" }}>
                  <span>Low</span>
                  <strong style={{ color: "#72a0ff" }}>{scanResult?.lowCount ?? streamingVulns.filter(v => v.severity === "Low").length}</strong>
                </div>
              </div>

              {fixedCount + skippedCount > 0 && (
                <div className="fix-progress-bar">
                  <div className="fix-progress-label">
                    ✅ {fixedCount} fixed · ⏭️ {skippedCount} skipped · 📋 {activeVulns.length} remaining
                  </div>
                  <div className="fix-progress-track">
                    <div
                      className="fix-progress-fill fix-progress-fixed"
                      style={{ width: `${(fixedCount / (scanResult?.totalVulnerabilities ?? displayVulns.length)) * 100}%` }}
                    />
                    <div
                      className="fix-progress-fill fix-progress-skipped"
                      style={{ width: `${(skippedCount / (scanResult?.totalVulnerabilities ?? displayVulns.length)) * 100}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Severity filter + search */}
            {displayVulns.length > 0 && (
              <div className="filter-bar">
                <div className="severity-filters">
                  {(["All", "Critical", "High", "Medium", "Low"] as SeverityFilter[]).map((sev) => (
                    <button
                      key={sev}
                      className={`filter-pill ${severityFilter === sev ? "filter-active" : ""}`}
                      style={sev !== "All" ? { "--pill-color": severityColor[sev] } as React.CSSProperties : undefined}
                      onClick={() => setSeverityFilter(sev)}
                    >
                      {sev}
                      {sev !== "All" && (
                        <span className="filter-count">
                          {displayVulns.filter((v) => v.severity === sev).length}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  className="search-input"
                  placeholder="🔍 Search by file, type, description…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            )}

            {/* Pipeline log */}
            {scanResult && scanResult.pipelineLog.length > 0 && (
              <div className="pipeline-log">
                {scanResult.pipelineLog.map((step, i) => (
                  <div key={i} className="pipeline-step">
                    <span className="pipeline-stage">{step.stage}</span>
                    <span className="pipeline-msg">{step.message}</span>
                    <span className="pipeline-time">{step.durationMs}ms</span>
                  </div>
                ))}
              </div>
            )}

            {/* No vulns */}
            {scanResult && scanResult.totalVulnerabilities === 0 && (
              <div className="clean-result">
                <h3>✅ No Vulnerabilities Found</h3>
                <p>Your project passed all {scanResult.scannedFiles} file security checks.</p>
              </div>
            )}

            {/* Vulnerability list */}
            {filteredVulns.length > 0 && (
              <div className="vuln-list">
                {filteredVulns.map((vuln) => {
                  const isFixed = fixedIds.has(vuln.id);
                  const isSkipped = skippedIds.has(vuln.id);
                  const isExpanded = expandedId === vuln.id;
                  const isFixing = fixingId === vuln.id;

                  return (
                    <div
                      key={vuln.id}
                      className={`vuln-card ${isFixed ? "vuln-fixed" : ""} ${isSkipped ? "vuln-skipped" : ""}`}
                      style={{ borderLeftColor: severityBorder[vuln.severity] ?? "#72a0ff" }}
                    >
                      {/* Header row */}
                      <div
                        className="vuln-header"
                        onClick={() => setExpandedId(isExpanded ? null : vuln.id)}
                      >
                        <div className="vuln-header-left">
                          <span
                            className="vuln-severity"
                            style={{ color: severityColor[vuln.severity] }}
                          >
                            {vuln.severity}
                          </span>
                          <span className="vuln-type-badge">{vuln.vulnType}</span>
                          <span className="vuln-owasp">{vuln.owaspCategory}</span>
                        </div>
                        <div className="vuln-header-right">
                          {isFixed && <span className="vuln-status-badge fixed">✅ Fixed</span>}
                          {isSkipped && <span className="vuln-status-badge skipped">⏭️ Skipped</span>}
                          <span className="vuln-confidence">
                            {Math.round(vuln.confidence * 100)}% conf
                          </span>
                          <span className="vuln-expand">{isExpanded ? "▼" : "▶"}</span>
                        </div>
                      </div>

                      {/* Title + location */}
                      <div className="vuln-title">{vuln.title}</div>
                      <div className="vuln-location">
                        <code>{vuln.file}:{vuln.line}</code>
                        <span className="vuln-layer">{vuln.detectionLayer}</span>
                      </div>

                      {/* Expanded content */}
                      {isExpanded && (
                        <div className="vuln-details">
                          <p className="vuln-description">{vuln.description}</p>

                          {vuln.aiExplanation && (
                            <div className="ai-explanation">
                              <strong>🧠 AI Analysis:</strong>
                              <p>{vuln.aiExplanation}</p>
                            </div>
                          )}

                          {/* Diff viewer */}
                          <div className="diff-viewer">
                            <div className="diff-panel diff-original">
                              <div className="diff-header">❌ Vulnerable Code</div>
                              <pre>{vuln.originalCode}</pre>
                            </div>
                            <div className="diff-panel diff-fixed">
                              <div className="diff-header">✅ Fixed Code</div>
                              <pre>{vuln.fixedCode}</pre>
                            </div>
                          </div>

                          {/* Actions */}
                          {!isFixed && !isSkipped && (
                            <div className="vuln-actions">
                              <button
                                className="fix-btn fix-accept"
                                onClick={(e) => { e.stopPropagation(); applyFix(vuln); }}
                                disabled={isFixing}
                              >
                                {isFixing ? "Applying…" : "✅ Accept & Fix"}
                              </button>
                              <button
                                className="fix-btn fix-skip"
                                onClick={(e) => { e.stopPropagation(); skipVuln(vuln.id); }}
                              >
                                ⏭️ Skip
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Warnings */}
            {scanResult && scanResult.warnings.length > 0 && (
              <div className="warning-card">
                <h3>⚠️ Warnings</h3>
                <ul>
                  {scanResult.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

export default App;
