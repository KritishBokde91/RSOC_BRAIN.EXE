import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

/* ─────────────────────────────────────────────
   TYPES
───────────────────────────────────────────── */
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

/* ─────────────────────────────────────────────
   CONSTANTS
───────────────────────────────────────────── */
const PLATFORM = "AetherVerify";

const severityOrder: Record<AuditFinding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const focusPresets = [
  {
    label: "Logic Bugs",
    prompt:
      "Focus on likely runtime failures, logical bugs, and risky implementation issues.",
  },
  {
    label: "Security",
    prompt:
      "Prioritize exploit paths, unsafe defaults, insecure dependencies, and data exposure risks.",
  },
  {
    label: "Stability",
    prompt:
      "Focus on startup failures, dependency drift, flaky tests, configuration issues, and production reliability risks.",
  },
];

const PIPELINE_STEPS = ["Clone", "Detect", "Run", "Analyze"];

/* ─────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────── */
function nowStamp() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function makeLine(tone: TerminalLine["tone"], text: string): TerminalLine {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    tone,
    text,
  };
}

function appendCapped(lines: TerminalLine[], next: TerminalLine[]) {
  return [...lines, ...next].slice(-450);
}

function shortId(id: string) { return id.slice(0, 8); }

function prettyDuration(ms: number) {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function truncate(str: string, max = 40) {
  if (str.length <= max) return str;
  return `${str.slice(0, Math.floor(max / 2) - 1)}…${str.slice(-(Math.ceil(max / 2) - 1))}`;
}

function stateDesc(s: AuditState) {
  if (s === "running")  return "Containerized checks streaming live.";
  if (s === "complete") return "Run finished — review strategy and findings below.";
  if (s === "error")    return "Pipeline stopped early. See terminal for details.";
  return "Configure source, runtime, and focus to get started.";
}

/* ─────────────────────────────────────────────
   COMPONENT
───────────────────────────────────────────── */
export default function App() {
  /* state */
  const [ctx, setCtx]             = useState<AppContext | null>(null);
  const [ctxError, setCtxError]   = useState("");

  const [workspace, setWorkspace]   = useState("");
  const [repoUrl, setRepoUrl]       = useState("");
  const [container, setContainer]   = useState("");
  const [focusPrompt, setFocusPrompt] = useState(focusPresets[0].prompt);

  const [auditState, setAuditState] = useState<AuditState>("idle");
  const [stageMsg, setStageMsg]     = useState("Ready.");
  const [auditError, setAuditError] = useState("");
  const [result, setResult]         = useState<RepositoryAuditResult | null>(null);
  const [lines, setLines]           = useState<TerminalLine[]>([
    makeLine("info", `[${nowStamp()}] Terminal ready. Start an audit to see live output.`),
  ]);

  const termRef      = useRef<HTMLDivElement>(null);
  const unlistensRef = useRef<UnlistenFn[]>([]);

  /* load context */
  useEffect(() => {
    invoke<AppContext>("load_app_context")
      .then((c) => {
        setCtx(c);
        setWorkspace(c.workspaceRoot);
        setContainer(c.defaultContainerImage);
      })
      .catch((e) => setCtxError(String(e)));
  }, []);

  /* event listeners */
  useEffect(() => {
    let alive = true;

    (async () => {
      const unStage = await listen<AuditStagePayload>("audit-stage", (e) => {
        if (!alive) return;
        setStageMsg(e.payload.message);
        if (e.payload.stage === "complete") setAuditState("complete");
        setLines((prev) =>
          appendCapped(prev, [
            makeLine("stage", `[${nowStamp()}] ${e.payload.stage.toUpperCase()}: ${e.payload.message}`),
          ])
        );
      });

      const unStatus = await listen<SandboxStatusPayload>("sandbox-status", (e) => {
        if (!alive) return;
        const tone = e.payload.stage === "failed"
          ? "error"
          : e.payload.stage === "completed"
          ? "success"
          : "info";
        const exit = e.payload.exitCode !== null ? ` (exit ${e.payload.exitCode})` : "";
        setLines((prev) =>
          appendCapped(prev, [
            makeLine(tone, `[${nowStamp()}] [${shortId(e.payload.runId)}] ${e.payload.stage.toUpperCase()}: ${e.payload.message}${exit}`),
          ])
        );
      });

      const unOutput = await listen<SandboxOutputPayload>("sandbox-output", (e) => {
        if (!alive) return;
        const chunks = e.payload.chunk
          .split(/\r?\n/)
          .map((l) => l.trimEnd())
          .filter(Boolean)
          .map((l) =>
            makeLine(
              e.payload.stream === "stderr" ? "error" : "output",
              `[${nowStamp()}] [${shortId(e.payload.runId)}] ${l}`
            )
          );
        if (chunks.length) setLines((prev) => appendCapped(prev, chunks));
      });

      unlistensRef.current = [unStage, unStatus, unOutput];
    })().catch((e) => setCtxError(String(e)));

    return () => {
      alive = false;
      unlistensRef.current.forEach((fn) => fn());
      unlistensRef.current = [];
    };
  }, []);

  /* auto-scroll terminal */
  useEffect(() => {
    const node = termRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [lines]);

  /* derived */
  const findings = (result?.findings ?? [])
    .slice()
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const counts = {
    critical: findings.filter((f) => f.severity === "Critical").length,
    high:     findings.filter((f) => f.severity === "High").length,
    medium:   findings.filter((f) => f.severity === "Medium").length,
    low:      findings.filter((f) => f.severity === "Low").length,
  };

  const hasSource     = Boolean(repoUrl.trim() || workspace.trim());
  const dockerOk      = ctx?.dockerAvailable ?? false;
  const llmOk         = ctx?.llmApiKeyConfigured ?? false;
  const wordCount     = focusPrompt.trim() ? focusPrompt.trim().split(/\s+/).length : 0;
  const canRun        = auditState !== "running" && hasSource && dockerOk;
  const sourceMode    = repoUrl.trim() ? "Remote URL" : "Local path";
  const curWorkspace  = workspace.trim() || ctx?.workspaceRoot || "Not set";
  const curContainer  = container.trim() || ctx?.defaultContainerImage || "—";
  const topFinding    = findings[0] ?? null;
  const cmdCount      = result?.executedCommands.length ?? 0;
  const lastLine      = lines[lines.length - 1]?.text ?? "";

  const urgentCount   = counts.critical + counts.high;
  const followCount   = counts.medium + counts.low;
  const runSummary    = result
    ? findings.length > 0
      ? `${urgentCount} urgent, ${followCount} follow-up`
      : "No findings"
    : "—";

  const commandPlan = [
    { label: "Install", value: result?.installCommand ?? "—" },
    { label: "Build",   value: result?.buildCommand   ?? "—" },
    { label: "Test",    value: result?.testCommand     ?? "—" },
    { label: "Run",     value: result?.runCommand      ?? "—" },
  ];

  const readiness = [
    { label: "Source", value: hasSource ? sourceMode : "Not set",         ok: hasSource },
    { label: "Docker", value: dockerOk  ? "Connected" : "Offline",        ok: dockerOk  },
    { label: "LLM",    value: llmOk     ? "Configured" : "Needs API key", ok: llmOk     },
    { label: "Focus",  value: wordCount >= 8 ? "Targeted" : "Too brief",  ok: wordCount >= 8 },
  ] as const;

  const heroStats = [
    { label: "Runtime",  value: dockerOk ? "Ready" : "Unavailable", note: ctx?.dockerMessage ?? "Checking…" },
    { label: "Model",    value: llmOk ? (ctx?.defaultLlmModel ?? "Set") : "No key",  note: ctx?.defaultLlmBaseUrl ?? "—" },
    { label: "Commands", value: result ? `${cmdCount}` : "—",        note: result ? `${cmdCount} steps run` : "After first run" },
    { label: "Findings", value: result ? `${findings.length}` : "—", note: result ? runSummary : "After first run" },
  ];

  /* actions */
  async function browse() {
    try {
      const sel = await open({ directory: true, multiple: false, title: "Select Repository" });
      if (sel && typeof sel === "string") setWorkspace(sel);
    } catch (e) { setAuditError(String(e)); }
  }

  async function startAudit() {
    if (!ctx) return;
    setAuditState("running");
    setAuditError("");
    setResult(null);
    setStageMsg("Preparing analysis…");
    setLines([
      makeLine("stage", `[${nowStamp()}] SESSION: Starting ${PLATFORM} audit pipeline.`),
      makeLine("info",  `[${nowStamp()}] SOURCE: ${repoUrl.trim() || workspace || ctx.workspaceRoot}`),
    ]);

    try {
      const res = await invoke<RepositoryAuditResult>("run_ai_repository_audit", {
        request: { workspaceRoot: workspace, repositoryUrl: repoUrl, containerImage: container, issuePrompt: focusPrompt },
      });
      setResult(res);
      setAuditState("complete");
      setStageMsg("Audit complete.");
    } catch (e) {
      setAuditError(String(e));
      setAuditState("error");
      setStageMsg("Audit failed.");
      setLines((prev) => appendCapped(prev, [makeLine("error", `[${nowStamp()}] ERROR: ${String(e)}`)]));
    }
  }

  /* ── RENDER ── */
  return (
    <div className="av-app">

      {/* ══ TOPBAR ══ */}
      <nav className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <div className="brand-mark">AV</div>
            <span className="brand-name">
              {PLATFORM}
              <span className="brand-slash"> / </span>
              <span className="brand-sub">Audit Command Center</span>
            </span>
          </div>
          <div className="topbar-pills">
            <span className="pill">{sourceMode}</span>
            <span className="pill">{dockerOk ? "Docker linked" : "Docker offline"}</span>
            <span className={`pill state-${auditState}`}>
              <span className="pill-dot" />
              {auditState}
            </span>
          </div>
        </div>
      </nav>

      <div className="av-shell">

        {/* ══ HERO STRIP ══ */}
        <div className="hero-strip">
          <div className="hero-strip-inner">
            <div>
              <h1 className="hero-heading">
                Repository<br />
                audit <em>command</em><br />
                center.
              </h1>
              <div className="pipeline">
                {PIPELINE_STEPS.map((step, i) => (
                  <div key={step} className="pipe-step">
                    <span className="pipe-num">0{i + 1}</span>
                    {step}
                  </div>
                ))}
              </div>
            </div>
            <div className="hero-aside">
              <span className={`pill state-${auditState}`}>
                <span className="pill-dot" />
                {auditState}
              </span>
              <p className="hero-status-text">{stateDesc(auditState)}</p>
            </div>
          </div>
        </div>

        {/* ══ STATS BAR ══ */}
        <div className="stats-bar anim-up anim-up-1" style={{ marginBottom: 20 }}>
          {heroStats.map((s) => (
            <div key={s.label} className="stat-cell">
              <div className="stat-label">{s.label}</div>
              <div className="stat-value" title={s.value}>{truncate(s.value, 18)}</div>
              <div className="stat-note" title={s.note}>{s.note}</div>
            </div>
          ))}
        </div>

        {/* ══ ERROR ══ */}
        {(ctxError || auditError) && (
          <div className="error-banner">{ctxError || auditError}</div>
        )}

        {/* ══ WORKSPACE ══ */}
        <div className="workspace anim-up anim-up-2">

          {/* ── MAIN COLUMN ── */}
          <div className="main-col">

            {/* INTAKE PANEL */}
            <section className="card intake-panel">
              <div className="card-header">
                <div className="card-header-row">
                  <div>
                    <p className="section-eyebrow">Source &amp; Runtime</p>
                    <h2 className="section-title">Configure the audit target and focus.</h2>
                  </div>
                  <span className="header-badge">intake</span>
                </div>
              </div>

              <div className="intake-body">
                {/* Fields */}
                <div className="field-group">
                  <div className="field">
                    <label className="field-label">Local Workspace</label>
                    <span className="field-hint">Path to a local repository on this machine.</span>
                    <div className="input-wrap">
                      <input
                        className="av-input"
                        value={workspace}
                        onChange={(e) => setWorkspace(e.target.value)}
                        placeholder="/path/to/repo"
                        disabled={auditState === "running"}
                      />
                      <button className="btn-ghost" onClick={browse} disabled={auditState === "running"}>
                        Browse
                      </button>
                    </div>
                  </div>

                  <div className="field">
                    <label className="field-label">Repository URL</label>
                    <span className="field-hint">Clone into the Docker sandbox instead.</span>
                    <input
                      className="av-input"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/org/project.git"
                      disabled={auditState === "running"}
                    />
                  </div>

                  <div className="field">
                    <label className="field-label">Container Image</label>
                    <span className="field-hint">Override the auto-detected runtime image.</span>
                    <div className="input-wrap">
                      <input
                        className="av-input"
                        value={container}
                        onChange={(e) => setContainer(e.target.value)}
                        placeholder={ctx?.defaultContainerImage ?? "node:22-bookworm"}
                        disabled={auditState === "running"}
                      />
                      <button
                        className="btn-ghost"
                        onClick={() => setContainer(ctx?.defaultContainerImage ?? "")}
                        disabled={auditState === "running" || !ctx}
                      >
                        Default
                      </button>
                    </div>
                  </div>

                  <div className="field">
                    <label className="field-label">Audit Focus</label>
                    <span className="field-hint">Narrow the review angle before the first command starts.</span>
                    <textarea
                      className="av-textarea"
                      value={focusPrompt}
                      onChange={(e) => setFocusPrompt(e.target.value)}
                      rows={4}
                      disabled={auditState === "running"}
                    />
                    <div className="preset-row">
                      {focusPresets.map((p) => (
                        <button
                          key={p.label}
                          className={`preset-chip${focusPrompt.trim() === p.prompt ? " is-active" : ""}`}
                          onClick={() => setFocusPrompt(p.prompt)}
                          disabled={auditState === "running"}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Run Profile */}
                <div className="card-inset run-profile">
                  <p className="profile-heading">Run Profile</p>
                  {[
                    { label: "Source mode",    value: hasSource ? sourceMode : "Choose source" },
                    { label: "Focus density",  value: `${wordCount} words` },
                    { label: "LLM",            value: llmOk ? "Connected" : "Needs setup" },
                    { label: "Image",          value: truncate(curContainer, 26) },
                    { label: "Workspace",      value: truncate(curWorkspace, 26) },
                  ].map((row) => (
                    <div key={row.label} className="profile-row">
                      <div className="profile-row-label">{row.label}</div>
                      <div className="profile-row-value" title={row.value}>{row.value}</div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            {/* EMPTY / RESULTS */}
            {!result ? (
              <section className="card empty-state anim-up anim-up-3">
                <div className="empty-blocks">
                  <div className="empty-block" />
                  <div className="empty-block" />
                  <div className="empty-block" />
                  <div className="empty-block" />
                </div>
                <div>
                  <h3 className="empty-heading">Results appear after the first run.</h3>
                  <p className="empty-body">
                    Strategy, execution evidence, findings, and warnings will
                    stack here in review order once the pipeline completes.
                  </p>
                </div>
              </section>
            ) : (
              <>
                {/* SNAPSHOT */}
                <section className="card anim-up">
                  <div className="card-header">
                    <div className="card-header-row">
                      <div>
                        <p className="section-eyebrow">Audit Snapshot</p>
                        <h2 className="section-title">{runSummary}</h2>
                      </div>
                      <span className="header-badge">complete</span>
                    </div>
                  </div>
                  <div className="panel-body">
                    <div className="snapshot-bar">
                      <div className="snap-cell">
                        <div className="snap-label">Total</div>
                        <div className="snap-value">{findings.length}</div>
                      </div>
                      <div className="snap-cell sev-critical">
                        <div className="snap-label">Critical</div>
                        <div className="snap-value">{counts.critical}</div>
                      </div>
                      <div className="snap-cell sev-high">
                        <div className="snap-label">High</div>
                        <div className="snap-value">{counts.high}</div>
                      </div>
                      <div className="snap-cell sev-medium">
                        <div className="snap-label">Medium</div>
                        <div className="snap-value">{counts.medium}</div>
                      </div>
                      <div className="snap-cell sev-low">
                        <div className="snap-label">Low</div>
                        <div className="snap-value">{counts.low}</div>
                      </div>
                    </div>
                    {result.summary && (
                      <div className="snap-summary">{result.summary}</div>
                    )}
                  </div>
                </section>

                {/* RUNTIME STRATEGY */}
                <section className="card">
                  <div className="card-header">
                    <div className="card-header-row">
                      <div>
                        <p className="section-eyebrow">Runtime Strategy</p>
                        <h2 className="section-title">Project profile and command plan.</h2>
                      </div>
                    </div>
                  </div>
                  <div className="panel-body">
                    <div className="strategy-grid">
                      {[
                        { label: "Project type",    value: result.detectedProjectType },
                        { label: "Language",        value: result.primaryLanguage },
                        { label: "Source",          value: result.sourceKind },
                        { label: "Container",       value: truncate(result.selectedContainerImage, 28) },
                      ].map((f) => (
                        <div key={f.label} className="fact-tile">
                          <div className="fact-label">{f.label}</div>
                          <div className="fact-value" title={f.value}>{f.value}</div>
                        </div>
                      ))}
                    </div>

                    {result.reasoning && (
                      <div className="reasoning-box">
                        <div className="reasoning-label">Why this plan</div>
                        <p className="reasoning-text">{result.reasoning}</p>
                      </div>
                    )}

                    <div className="command-chips">
                      {commandPlan.map((c) => (
                        <div key={c.label} className="cmd-chip">
                          <div className="cmd-chip-label">{c.label}</div>
                          <div className="cmd-chip-value" title={c.value || "—"}>{c.value || "—"}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>

                {/* EXECUTION EVIDENCE */}
                <section className="card">
                  <div className="card-header">
                    <div className="card-header-row">
                      <div>
                        <p className="section-eyebrow">Execution Evidence</p>
                        <h2 className="section-title">Every dynamic command with status and output.</h2>
                      </div>
                      <span className="header-badge">{cmdCount} steps</span>
                    </div>
                  </div>
                  <div className="panel-body">
                    {result.executedCommands.length > 0 ? (
                      <div className="cmd-results">
                        {result.executedCommands.map((cmd) => (
                          <div key={`${cmd.label}-${cmd.command}`} className="cmd-card">
                            <div className="cmd-card-top">
                              <span className={`cmd-status ${cmd.status}`}>
                                {cmd.status.replace("_", " ")}
                              </span>
                              <span className="cmd-name" title={cmd.label}>{cmd.label}</span>
                              <span className="cmd-duration">{prettyDuration(cmd.durationMs)}</span>
                            </div>
                            <div className="cmd-string" title={cmd.command}>{cmd.command}</div>
                            <pre className="cmd-output">
                              {cmd.outputPreview || "No output captured."}
                            </pre>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="empty-placeholder">No runnable commands inferred for this repository.</div>
                    )}
                  </div>
                </section>

                {/* FINDINGS */}
                <section className="card">
                  <div className="card-header">
                    <div className="card-header-row">
                      <div>
                        <p className="section-eyebrow">Findings</p>
                        <h2 className="section-title">Ranked by severity, with evidence and next steps.</h2>
                      </div>
                      <span className="header-badge">{findings.length} total</span>
                    </div>
                  </div>
                  <div className="panel-body">
                    {findings.length > 0 ? (
                      <div className="findings-list">
                        {findings.map((f) => (
                          <article
                            key={f.id}
                            className={`finding-card sev-${f.severity.toLowerCase()}`}
                          >
                            <div className="finding-header">
                              <span className={`sev-badge ${f.severity.toLowerCase()}`}>
                                {f.severity}
                              </span>
                              <span className="cat-badge">{f.category}</span>
                              <span className="conf-badge">
                                {Math.round(f.confidence * 100)}% confidence
                              </span>
                            </div>

                            <h3 className="finding-title">{f.title}</h3>

                            <div className="finding-location">
                              <span>
                                {f.file
                                  ? `${truncate(f.file, 48)}${f.line ? `:${f.line}` : ""}`
                                  : "Location not pinned"}
                              </span>
                              <span>{f.source}</span>
                            </div>

                            <p className="finding-explanation">{f.explanation}</p>

                            <div className="finding-block">
                              <div className="finding-block-label">Evidence</div>
                              <pre>{f.evidence}</pre>
                            </div>

                            <div className="finding-block">
                              <div className="finding-block-label">Suggestion</div>
                              <p>{f.suggestion}</p>
                            </div>

                            {f.fixSnippet && (
                              <div className="finding-block">
                                <div className="finding-block-label">Suggested fix</div>
                                <pre>{f.fixSnippet}</pre>
                              </div>
                            )}
                          </article>
                        ))}
                      </div>
                    ) : (
                      <div className="empty-placeholder">
                        No findings returned. Check the terminal for execution evidence.
                      </div>
                    )}
                  </div>
                </section>

                {/* WARNINGS */}
                {result.warnings.length > 0 && (
                  <div className="warnings-panel">
                    <div className="warnings-title">Audit notes</div>
                    <ul className="warnings-list">
                      {result.warnings.map((w) => <li key={w}>{w}</li>)}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>

          {/* ── RAIL COLUMN ── */}
          <div className="rail-col">

            {/* LAUNCH DECK */}
            <section className="card launch-deck">
              <div style={{ marginBottom: 16 }}>
                <p className="section-eyebrow">Launch Deck</p>
                <h2 className="section-title">Confirm readiness and run.</h2>
              </div>

              <div className="readiness-grid">
                {readiness.map((r) => (
                  <div key={r.label} className={`check-tile ${r.ok ? "ok" : "warn"}`}>
                    <div className="check-label">{r.label}</div>
                    <div className="check-value">{r.value}</div>
                  </div>
                ))}
              </div>

              <button
                className="launch-btn"
                onClick={startAudit}
                disabled={!canRun}
              >
                {auditState === "running" ? `${PLATFORM} running…` : "Clone, Run & Analyze →"}
              </button>

              <div className="stage-display">
                <div className="stage-label-text">Current stage</div>
                <div className="stage-value-text">{stageMsg}</div>
              </div>

              <div className="pipe-list">
                {PIPELINE_STEPS.map((step, i) => (
                  <div key={step} className="pipe-list-item">
                    <span className="pipe-list-num">0{i + 1}</span>
                    <span className="pipe-list-text">{step}</span>
                  </div>
                ))}
              </div>
            </section>

            {/* TERMINAL */}
            <div className="terminal">
              <div className="terminal-topbar">
                <div className="terminal-title">
                  <div className="terminal-dots">
                    <div className="terminal-dot" />
                    <div className="terminal-dot" />
                    <div className="terminal-dot" />
                  </div>
                  <span className="terminal-name">{PLATFORM} — live output</span>
                </div>
                <div className="terminal-meta-row">
                  <span className="terminal-badge">{lines.length} lines</span>
                  <span className="terminal-badge">
                    {auditState === "running" ? "streaming" : auditState === "complete" ? "captured" : "ready"}
                  </span>
                </div>
              </div>

              <div className="terminal-body" ref={termRef}>
                {lines.map((line) => (
                  <div key={line.id} className={`term-line term-${line.tone}`}>
                    {line.text}
                  </div>
                ))}
                {auditState === "running" && (
                  <div className="term-line term-cursor">█</div>
                )}
              </div>

              <div className="terminal-footer">
                <div className="terminal-last-label">Latest event</div>
                <div className="terminal-last-text">{lastLine}</div>
              </div>
            </div>

            {/* SPOTLIGHT */}
            <section className="card spotlight">
              <div className="card-header-row" style={{ padding: "0 0 0 0", marginBottom: 0 }}>
                <div>
                  <p className="section-eyebrow">{topFinding ? "Top Finding" : `${PLATFORM} Brief`}</p>
                  <h2 className="section-title" style={{ fontSize: "1rem" }}>
                    {topFinding
                      ? topFinding.title
                      : "Intake, terminal, and findings in one flow."}
                  </h2>
                </div>
              </div>

              {topFinding ? (
                <div className={`spotlight-box sev-${topFinding.severity.toLowerCase()}`}>
                  <div className="spotlight-meta-row">
                    <span className={`sev-badge ${topFinding.severity.toLowerCase()}`}>
                      {topFinding.severity}
                    </span>
                    <span className="cat-badge">{topFinding.category}</span>
                  </div>
                  <p className="spotlight-body">{topFinding.explanation}</p>
                  <div className="spotlight-divider" />
                  <div className="spotlight-label">Suggested move</div>
                  <p className="spotlight-body" style={{ fontSize: "12px" }}>{topFinding.suggestion}</p>
                </div>
              ) : (
                <div className="spotlight-box">
                  {[
                    { key: "Source",    val: hasSource ? sourceMode : "Not selected" },
                    { key: "Workspace", val: truncate(curWorkspace, 28) },
                    { key: "Model",     val: ctx?.defaultLlmModel ?? "Not configured" },
                    { key: "Runtime",   val: truncate(curContainer, 28) },
                  ].map((item) => (
                    <div key={item.key} className="brief-item">
                      <span className="brief-key">{item.key}</span>
                      <span className="brief-val" title={item.val}>{item.val}</span>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}