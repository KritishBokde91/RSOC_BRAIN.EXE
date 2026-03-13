import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

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

interface AuditStagePayload {
  stage: string;
  message: string;
  durationMs: number;
}

interface SandboxStatusPayload {
  runId: string;
  stage: string;
  message: string;
  exitCode: number | null;
}

interface SandboxOutputPayload {
  runId: string;
  stream: "stdout" | "stderr";
  chunk: string;
}

interface AuditCommandResult {
  label: string;
  command: string;
  exitCode: number;
  status: string;
  durationMs: number;
  outputPreview: string;
}

interface AuditFinding {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  category: string;
  confidence: number;
  file: string | null;
  line: number | null;
  source: string;
  evidence: string;
  explanation: string;
  suggestion: string;
  fixSnippet: string | null;
}

interface RepositoryAuditResult {
  workspaceRoot: string;
  sourceKind: string;
  repositoryUrl: string | null;
  detectedProjectType: string;
  primaryLanguage: string;
  recommendedContainerImage: string;
  selectedContainerImage: string;
  reasoning: string;
  installCommand: string | null;
  buildCommand: string | null;
  testCommand: string | null;
  runCommand: string | null;
  runTimeoutSeconds: number;
  executedCommands: AuditCommandResult[];
  findings: AuditFinding[];
  summary: string;
  warnings: string[];
}

type AuditState = "idle" | "running" | "complete" | "error";

interface TerminalLine {
  id: string;
  tone: "stage" | "info" | "output" | "error" | "success";
  text: string;
}

const severityOrder: Record<AuditFinding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const severityAccent: Record<AuditFinding["severity"], string> = {
  Critical: "#ff6b6b",
  High: "#ffb454",
  Medium: "#ffd166",
  Low: "#7bdff2",
};

function nowStamp() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function makeTerminalLine(
  tone: TerminalLine["tone"],
  text: string,
): TerminalLine {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    tone,
    text,
  };
}

function appendCapped(lines: TerminalLine[], next: TerminalLine[]) {
  const merged = [...lines, ...next];
  return merged.slice(-450);
}

function shortRunId(runId: string) {
  return runId.slice(0, 8);
}

function App() {
  const [appContext, setAppContext] = useState<AppContext | null>(null);
  const [contextError, setContextError] = useState("");

  const [workspaceRoot, setWorkspaceRoot] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [containerImage, setContainerImage] = useState("");
  const [issuePrompt, setIssuePrompt] = useState(
    "Focus on likely runtime failures, logical bugs, and risky implementation issues.",
  );

  const [auditState, setAuditState] = useState<AuditState>("idle");
  const [stageLabel, setStageLabel] = useState("Ready to inspect a repository.");
  const [auditError, setAuditError] = useState("");
  const [auditResult, setAuditResult] = useState<RepositoryAuditResult | null>(null);
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([
    makeTerminalLine(
      "info",
      `[${nowStamp()}] Terminal ready. Start an audit to stream clone, setup, run, and analysis output here.`,
    ),
  ]);

  const terminalBodyRef = useRef<HTMLDivElement>(null);
  const unlistenRef = useRef<UnlistenFn[]>([]);

  useEffect(() => {
    invoke<AppContext>("load_app_context")
      .then((context) => {
        setAppContext(context);
        setWorkspaceRoot(context.workspaceRoot);
        setContainerImage(context.defaultContainerImage);
      })
      .catch((error) => setContextError(String(error)));
  }, []);

  useEffect(() => {
    let active = true;

    const attachListeners = async () => {
      const unlistenStage = await listen<AuditStagePayload>("audit-stage", (event) => {
        if (!active) return;
        const line = makeTerminalLine(
          "stage",
          `[${nowStamp()}] ${event.payload.stage.toUpperCase()}: ${event.payload.message}`,
        );
        setStageLabel(event.payload.message);
        if (event.payload.stage === "complete") {
          setAuditState("complete");
        }
        setTerminalLines((current) => appendCapped(current, [line]));
      });

      const unlistenStatus = await listen<SandboxStatusPayload>(
        "sandbox-status",
        (event) => {
          if (!active) return;
          const tone =
            event.payload.stage === "failed"
              ? "error"
              : event.payload.stage === "completed"
                ? "success"
                : "info";
          const exitSuffix =
            event.payload.exitCode !== null ? ` (exit ${event.payload.exitCode})` : "";
          const line = makeTerminalLine(
            tone,
            `[${nowStamp()}] [${shortRunId(event.payload.runId)}] ${event.payload.stage.toUpperCase()}: ${event.payload.message}${exitSuffix}`,
          );
          setTerminalLines((current) => appendCapped(current, [line]));
        },
      );

      const unlistenOutput = await listen<SandboxOutputPayload>(
        "sandbox-output",
        (event) => {
          if (!active) return;
          const chunks = event.payload.chunk
            .split(/\r?\n/)
            .map((line) => line.trimEnd())
            .filter(Boolean)
            .map((line) =>
              makeTerminalLine(
                event.payload.stream === "stderr" ? "error" : "output",
                `[${nowStamp()}] [${shortRunId(event.payload.runId)}] ${line}`,
              ),
            );
          if (chunks.length > 0) {
            setTerminalLines((current) => appendCapped(current, chunks));
          }
        },
      );

      unlistenRef.current = [unlistenStage, unlistenStatus, unlistenOutput];
    };

    attachListeners().catch((error) => {
      setContextError(String(error));
    });

    return () => {
      active = false;
      for (const unlisten of unlistenRef.current) {
        unlisten();
      }
      unlistenRef.current = [];
    };
  }, []);

  useEffect(() => {
    const node = terminalBodyRef.current;
    if (!node) return;
    node.scrollTop = node.scrollHeight;
  }, [terminalLines]);

  const findings =
    auditResult?.findings
      .slice()
      .sort((left, right) => severityOrder[left.severity] - severityOrder[right.severity]) ?? [];

  const severityCounts = {
    critical: findings.filter((finding) => finding.severity === "Critical").length,
    high: findings.filter((finding) => finding.severity === "High").length,
    medium: findings.filter((finding) => finding.severity === "Medium").length,
    low: findings.filter((finding) => finding.severity === "Low").length,
  };

  async function browseWorkspace() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Repository Folder",
      });
      if (selected && typeof selected === "string") {
        setWorkspaceRoot(selected);
      }
    } catch (error) {
      setAuditError(String(error));
    }
  }

  async function startAudit() {
    if (!appContext) return;

    setAuditState("running");
    setAuditError("");
    setAuditResult(null);
    setStageLabel("Preparing repository analysis...");
    setTerminalLines([
      makeTerminalLine(
        "stage",
        `[${nowStamp()}] SESSION: Starting AI bug detector pipeline.`,
      ),
      makeTerminalLine(
        "info",
        `[${nowStamp()}] SOURCE: ${
          repositoryUrl.trim() || workspaceRoot || appContext.workspaceRoot
        }`,
      ),
    ]);

    try {
      const result = await invoke<RepositoryAuditResult>("run_ai_repository_audit", {
        request: {
          workspaceRoot,
          repositoryUrl,
          containerImage,
          issuePrompt,
        },
      });
      setAuditResult(result);
      setAuditState("complete");
      setStageLabel("Audit complete.");
    } catch (error) {
      setAuditError(String(error));
      setAuditState("error");
      setStageLabel("Audit failed.");
      setTerminalLines((current) =>
        appendCapped(current, [
          makeTerminalLine("error", `[${nowStamp()}] ERROR: ${String(error)}`),
        ]),
      );
    }
  }

  return (
    <div className="app-shell">
      <header className="hero">
        <div className="hero-copy">
          <p className="eyebrow">AI / ML Code Analysis</p>
          <h1>AI Bug Detector</h1>
          <p className="hero-text">
            Clone a repository into an isolated environment, let the LLM infer
            the stack and the safest way to run it, execute dynamic checks in
            Docker, and turn the terminal evidence into actionable bug and
            vulnerability suggestions.
          </p>
        </div>

        <div className="hero-metrics">
          <div className="metric-card">
            <span className="metric-label">Docker</span>
            <strong>{appContext?.dockerAvailable ? "Ready" : "Unavailable"}</strong>
            <p>{appContext?.dockerMessage ?? "Checking Docker..."}</p>
          </div>
          <div className="metric-card">
            <span className="metric-label">LLM</span>
            <strong>
              {appContext?.llmApiKeyConfigured
                ? appContext.defaultLlmModel || "Configured"
                : "Needs API key"}
            </strong>
            <p>{appContext?.defaultLlmBaseUrl ?? "No endpoint configured"}</p>
          </div>
          <div className="metric-card">
            <span className="metric-label">Process</span>
            <strong>{"Clone -> Detect -> Run -> Analyze"}</strong>
            <p>Terminal stays visible during the full pipeline.</p>
          </div>
        </div>
      </header>

      {(contextError || auditError) && (
        <div className="error-banner">{contextError || auditError}</div>
      )}

      <div className="surface-grid">
        <main className="main-column">
          <section className="panel controls-panel">
            <div className="panel-heading">
              <div>
                <p className="section-tag">Input</p>
                <h2>Repository Source</h2>
              </div>
              <button
                className="primary-btn"
                onClick={startAudit}
                disabled={
                  auditState === "running" ||
                  (!repositoryUrl.trim() && !workspaceRoot.trim())
                }
              >
                {auditState === "running" ? "Analyzing..." : "Clone, Run & Analyze"}
              </button>
            </div>

            <label className="field">
              <span>Local Workspace</span>
              <div className="input-row">
                <input
                  value={workspaceRoot}
                  onChange={(event) => setWorkspaceRoot(event.target.value)}
                  placeholder="/path/to/local/repository"
                  disabled={auditState === "running"}
                />
                <button
                  className="secondary-btn"
                  onClick={browseWorkspace}
                  disabled={auditState === "running"}
                >
                  Browse
                </button>
              </div>
              <small>
                Primary input. The app copies this workspace into an isolated
                Docker environment and runs the next steps there.
              </small>
            </label>

            <label className="field">
              <span>Repository URL (Optional)</span>
              <input
                value={repositoryUrl}
                onChange={(event) => setRepositoryUrl(event.target.value)}
                placeholder="https://github.com/org/project.git"
                disabled={auditState === "running"}
              />
              <small>
                Only use this when the code is not already available locally.
              </small>
            </label>

            <label className="field">
              <span>Container Image Override</span>
              <input
                value={containerImage}
                onChange={(event) => setContainerImage(event.target.value)}
                placeholder={appContext?.defaultContainerImage ?? "node:22-bookworm"}
                disabled={auditState === "running"}
              />
              <small>
                Leave this as-is to use the default, or override it when you
                already know the runtime you want.
              </small>
            </label>

            <label className="field">
              <span>Audit Focus</span>
              <textarea
                value={issuePrompt}
                onChange={(event) => setIssuePrompt(event.target.value)}
                rows={4}
                disabled={auditState === "running"}
              />
            </label>

            <div className="status-strip">
              <span className={`state-pill state-${auditState}`}>{auditState}</span>
              <span>{stageLabel}</span>
            </div>
          </section>

          {auditResult && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="section-tag">Detection</p>
                    <h2>Runtime Strategy</h2>
                  </div>
                </div>

                <div className="facts-grid">
                  <div className="fact-card">
                    <span>Project Type</span>
                    <strong>{auditResult.detectedProjectType}</strong>
                  </div>
                  <div className="fact-card">
                    <span>Primary Language</span>
                    <strong>{auditResult.primaryLanguage}</strong>
                  </div>
                  <div className="fact-card">
                    <span>Source</span>
                    <strong>{auditResult.sourceKind}</strong>
                  </div>
                  <div className="fact-card">
                    <span>Container</span>
                    <strong>{auditResult.selectedContainerImage}</strong>
                  </div>
                </div>

                <div className="explanation-card">
                  <h3>Why this plan</h3>
                  <p>{auditResult.reasoning || "No additional reasoning returned."}</p>
                </div>

                <div className="command-plan">
                  <div className="command-chip">
                    <span>Install</span>
                    <code>{auditResult.installCommand ?? "Not needed"}</code>
                  </div>
                  <div className="command-chip">
                    <span>Test</span>
                    <code>{auditResult.testCommand ?? "Not detected"}</code>
                  </div>
                  <div className="command-chip">
                    <span>Build</span>
                    <code>{auditResult.buildCommand ?? "Not detected"}</code>
                  </div>
                  <div className="command-chip">
                    <span>Run</span>
                    <code>{auditResult.runCommand ?? "Not detected"}</code>
                  </div>
                </div>
              </section>

              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="section-tag">Execution</p>
                    <h2>Dynamic Analysis Commands</h2>
                  </div>
                </div>

                <div className="command-results">
                  {auditResult.executedCommands.length > 0 ? (
                    auditResult.executedCommands.map((result) => (
                      <article key={`${result.label}-${result.command}`} className="command-card">
                        <div className="command-topline">
                          <span className={`command-status status-${result.status}`}>
                            {result.status}
                          </span>
                          <strong>{result.label}</strong>
                          <span>{result.durationMs} ms</span>
                        </div>
                        <code className="command-string">{result.command}</code>
                        <pre className="command-output">{result.outputPreview || "No terminal output captured."}</pre>
                      </article>
                    ))
                  ) : (
                    <div className="empty-state">
                      No runnable commands were inferred for this repository.
                    </div>
                  )}
                </div>
              </section>

              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="section-tag">Findings</p>
                    <h2>LLM Report</h2>
                  </div>
                </div>

                <div className="summary-ribbon">
                  <div className="summary-card">
                    <span>Total</span>
                    <strong>{findings.length}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Critical</span>
                    <strong>{severityCounts.critical}</strong>
                  </div>
                  <div className="summary-card">
                    <span>High</span>
                    <strong>{severityCounts.high}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Medium</span>
                    <strong>{severityCounts.medium}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Low</span>
                    <strong>{severityCounts.low}</strong>
                  </div>
                </div>

                <div className="report-summary">{auditResult.summary}</div>

                <div className="findings-list">
                  {findings.length > 0 ? (
                    findings.map((finding) => (
                      <article
                        key={finding.id}
                        className="finding-card"
                        style={{
                          borderColor: `${severityAccent[finding.severity]}55`,
                        }}
                      >
                        <div className="finding-topline">
                          <span
                            className="severity-pill"
                            style={{
                              color: severityAccent[finding.severity],
                              borderColor: `${severityAccent[finding.severity]}66`,
                            }}
                          >
                            {finding.severity}
                          </span>
                          <span className="category-pill">{finding.category}</span>
                          <span className="confidence-pill">
                            {Math.round(finding.confidence * 100)}% confidence
                          </span>
                        </div>

                        <h3>{finding.title}</h3>

                        <div className="finding-meta">
                          <span>
                            {finding.file
                              ? `${finding.file}${finding.line ? `:${finding.line}` : ""}`
                              : "Location not pinned"}
                          </span>
                          <span>{finding.source}</span>
                        </div>

                        <p>{finding.explanation}</p>

                        <div className="finding-block">
                          <span>Evidence</span>
                          <pre>{finding.evidence}</pre>
                        </div>

                        <div className="finding-block">
                          <span>Suggestion</span>
                          <p>{finding.suggestion}</p>
                        </div>

                        {finding.fixSnippet && (
                          <div className="finding-block">
                            <span>Suggested Fix</span>
                            <pre>{finding.fixSnippet}</pre>
                          </div>
                        )}
                      </article>
                    ))
                  ) : (
                    <div className="empty-state">
                      No findings were returned. The terminal log may still show
                      useful execution details.
                    </div>
                  )}
                </div>
              </section>

              {auditResult.warnings.length > 0 && (
                <section className="panel warning-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-tag">Warnings</p>
                      <h2>Audit Notes</h2>
                    </div>
                  </div>

                  <ul className="warning-list">
                    {auditResult.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}
        </main>

        <aside className="terminal-column">
          <section className="terminal-shell">
            <div className="terminal-head">
              <div className="terminal-lights">
                <span className="light light-red" />
                <span className="light light-amber" />
                <span className="light light-green" />
              </div>
              <div>
                <p className="section-tag">Live Terminal</p>
                <h2>Environment Activity</h2>
              </div>
            </div>

            <div className="terminal-body" ref={terminalBodyRef}>
              {terminalLines.map((line) => (
                <div key={line.id} className={`terminal-line tone-${line.tone}`}>
                  {line.text}
                </div>
              ))}
              {auditState === "running" && (
                <div className="terminal-line tone-output cursor-line">_</div>
              )}
            </div>

            <div className="terminal-foot">
              <span>Terminal is always visible so clone, install, run, and analysis output stay in one place.</span>
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

export default App;
