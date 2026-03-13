import { useEffect, useEffectEvent, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import "./App.css";

type AppContext = {
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
};

type SandboxRunHandle = {
  runId: string;
};

type SandboxOutputEvent = {
  runId: string;
  stream: "stdout" | "stderr";
  chunk: string;
};

type SandboxStatusEvent = {
  runId: string;
  stage: string;
  message: string;
  exitCode?: number | null;
};

type IngestionSummary = {
  workspaceRoot: string;
  scannedFiles: number;
  symbolCount: number;
  callEdgeCount: number;
  inheritanceEdgeCount: number;
  storedToNeo4j: boolean;
  neo4jStatus: string;
  warnings: string[];
  symbolPreview: Array<{
    name: string;
    kind: string;
    language: string;
    filePath: string;
    line: number;
  }>;
};

type ContextIndexSummary = {
  workspaceRoot: string;
  indexPath: string;
  indexedFiles: number;
  chunkCount: number;
  totalSourceBytes: number;
  embeddingModel: string;
  warnings: string[];
};

type RetrievedContext = {
  filePath: string;
  language: string;
  startLine: number;
  endLine: number;
  score: number;
  vectorScore: number;
  lexicalScore: number;
  rerankScore?: number | null;
  snippet: string;
};

type IssueAnalysisResponse = {
  workspaceRoot: string;
  indexStatus: string;
  llmStatus: string;
  embeddingModel: string;
  rerankerModel: string;
  llmModel: string;
  promptPreview: string;
  answer?: string | null;
  warnings: string[];
  retrievedContext: RetrievedContext[];
};

function formatMegabytes(bytes: number) {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function App() {
  const terminalHostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const activeRunIdRef = useRef<string | null>(null);
  const hasPrintedBootstrapStatusRef = useRef(false);
  const lastPrintedSystemMessageRef = useRef("");
  const [appContext, setAppContext] = useState<AppContext | null>(null);
  const [workspaceRoot, setWorkspaceRoot] = useState("");
  const [sandboxImage, setSandboxImage] = useState("node:22-bookworm");
  const [sandboxCommand, setSandboxCommand] = useState(
    "npm --version && node --version",
  );
  const [sandboxStage, setSandboxStage] = useState("idle");
  const [sandboxMessage, setSandboxMessage] = useState(
    "Ready to execute inside Docker.",
  );
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [neo4jUri, setNeo4jUri] = useState("");
  const [neo4jUsername, setNeo4jUsername] = useState("");
  const [neo4jPassword, setNeo4jPassword] = useState("");
  const [ollamaHost, setOllamaHost] = useState("http://127.0.0.1:11434");
  const [embeddingModel, setEmbeddingModel] = useState(
    "snowflake-arctic-embed2:latest",
  );
  const [rerankerModel, setRerankerModel] = useState("");
  const [llmBaseUrl, setLlmBaseUrl] = useState("https://api.groq.com/openai/v1");
  const [llmModel, setLlmModel] = useState("qwen/qwen3-32b");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [issuePrompt, setIssuePrompt] = useState(
    "Describe the bug, failing test, or behavior you want to diagnose.",
  );
  const [ingestionSummary, setIngestionSummary] = useState<IngestionSummary | null>(null);
  const [indexSummary, setIndexSummary] = useState<ContextIndexSummary | null>(null);
  const [analysisResponse, setAnalysisResponse] = useState<IssueAnalysisResponse | null>(null);
  const [isLoadingContext, setIsLoadingContext] = useState(true);
  const [isStartingSandbox, setIsStartingSandbox] = useState(false);
  const [isIngesting, setIsIngesting] = useState(false);
  const [isBuildingIndex, setIsBuildingIndex] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isFixingAndVerifying, setIsFixingAndVerifying] = useState(false);
  const [appError, setAppError] = useState("");

  const writeTerminal = useEffectEvent((chunk: string, stream: "stdout" | "stderr") => {
    const terminal = terminalRef.current;
    if (!terminal) {
      return;
    }
    const colorizedChunk =
      stream === "stderr" ? `\u001b[38;5;210m${chunk}\u001b[0m` : chunk;
    terminal.write(colorizedChunk.replace(/\n/g, "\r\n"));
  });

  const printSystemMessage = useEffectEvent((message: string) => {
    const terminal = terminalRef.current;
    if (!terminal) {
      return;
    }
    terminal.writeln(`\u001b[38;5;81m${message}\u001b[0m`);
  });

  useEffect(() => {
    const terminal = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: `"Iosevka Term", "JetBrains Mono", monospace`,
      fontSize: 13,
      theme: {
        background: "#09111f",
        foreground: "#d7e5ff",
        cursor: "#f7c35f",
        black: "#09111f",
        red: "#ef8a85",
        green: "#9dd39b",
        yellow: "#f7c35f",
        blue: "#72a0ff",
        magenta: "#d9a6ff",
        cyan: "#6ed6d3",
        white: "#d7e5ff",
        brightBlack: "#2a3f60",
        brightRed: "#ff9f99",
        brightGreen: "#b7e8b1",
        brightYellow: "#ffd98b",
        brightBlue: "#9db9ff",
        brightMagenta: "#e2c1ff",
        brightCyan: "#8de6e2",
        brightWhite: "#f4f8ff",
      },
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    if (terminalHostRef.current) {
      terminal.open(terminalHostRef.current);
      fitAddon.fit();
      terminal.writeln("\u001b[1mAetherVerify console\u001b[0m");
      terminal.writeln("Docker-executed commands stream here.");
    }

    const handleResize = () => fitAddon.fit();
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      terminal.dispose();
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    const bootstrap = async () => {
      try {
        const context = await invoke<AppContext>("load_app_context");
        if (cancelled) {
          return;
        }
        setAppContext(context);
        setWorkspaceRoot(context.workspaceRoot);
        setSandboxImage(context.defaultContainerImage);
        setSandboxMessage(context.dockerMessage);
        setOllamaHost(context.defaultOllamaHost);
        setEmbeddingModel(context.defaultEmbeddingModel);
        setRerankerModel(context.defaultRerankerModel);
        setLlmBaseUrl(context.defaultLlmBaseUrl);
        setLlmModel(context.defaultLlmModel);
        if (!hasPrintedBootstrapStatusRef.current) {
          printSystemMessage(context.dockerMessage);
          lastPrintedSystemMessageRef.current = context.dockerMessage;
          hasPrintedBootstrapStatusRef.current = true;
        }
      } catch (error) {
        if (cancelled) {
          return;
        }
        setAppError(String(error));
      } finally {
        if (!cancelled) {
          setIsLoadingContext(false);
        }
      }
    };

    bootstrap();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let unlistenOutput: (() => void) | undefined;
    let unlistenStatus: (() => void) | undefined;

    const attachListeners = async () => {
      unlistenOutput = await listen<SandboxOutputEvent>("sandbox-output", (event) => {
        if (!activeRunIdRef.current) {
          activeRunIdRef.current = event.payload.runId;
          setActiveRunId(event.payload.runId);
        }
        if (event.payload.runId !== activeRunIdRef.current) {
          return;
        }
        writeTerminal(event.payload.chunk, event.payload.stream);
      });

      unlistenStatus = await listen<SandboxStatusEvent>("sandbox-status", (event) => {
        if (!activeRunIdRef.current) {
          activeRunIdRef.current = event.payload.runId;
          setActiveRunId(event.payload.runId);
        }
        if (event.payload.runId !== activeRunIdRef.current) {
          return;
        }
        setSandboxStage(event.payload.stage);
        setSandboxMessage(event.payload.message);
        if (event.payload.stage !== "pulling-image") {
          const terminalMessage =
            event.payload.exitCode != null
              ? `${event.payload.message} Exit code: ${event.payload.exitCode}.`
              : event.payload.message;
          if (terminalMessage !== lastPrintedSystemMessageRef.current) {
            printSystemMessage(terminalMessage);
            lastPrintedSystemMessageRef.current = terminalMessage;
          }
        }
        if (
          event.payload.stage === "completed" ||
          event.payload.stage === "failed"
        ) {
          setIsStartingSandbox(false);
          setActiveRunId(null);
          activeRunIdRef.current = null;
          lastPrintedSystemMessageRef.current = "";
        }
      });
    };

    attachListeners();

    return () => {
      unlistenOutput?.();
      unlistenStatus?.();
    };
  }, []);

  useEffect(() => {
    fitAddonRef.current?.fit();
  }, [ingestionSummary, indexSummary, analysisResponse, appContext]);

  const runSandboxCommand = async () => {
    setAppError("");
    setIsStartingSandbox(true);
    setSandboxStage("queued");
    setSandboxMessage("Submitting command to the sandbox.");
    lastPrintedSystemMessageRef.current = "";
    terminalRef.current?.clear();
    printSystemMessage(`Sandbox image: ${sandboxImage}`);
    printSystemMessage(`Workspace copy source: ${workspaceRoot}`);
    printSystemMessage(`Command: ${sandboxCommand}`);

    try {
      const handle = await invoke<SandboxRunHandle>("start_sandbox_command", {
        request: {
          workspaceRoot,
          image: sandboxImage,
          command: sandboxCommand,
        },
      });
      setActiveRunId(handle.runId);
      activeRunIdRef.current = handle.runId;
    } catch (error) {
      setIsStartingSandbox(false);
      setSandboxStage("failed");
      setSandboxMessage(String(error));
      setAppError(String(error));
      printSystemMessage(`Failed to start sandbox command: ${String(error)}`);
    }
  };

  const stopSandboxCommand = async () => {
    if (!activeRunId) {
      return;
    }

    try {
      await invoke("stop_sandbox_command", { runId: activeRunId });
      setSandboxStage("cancelled");
      setSandboxMessage("Sandbox command was stopped.");
      setIsStartingSandbox(false);
      setActiveRunId(null);
      activeRunIdRef.current = null;
      lastPrintedSystemMessageRef.current = "";
      printSystemMessage("Sandbox container stopped.");
    } catch (error) {
      setAppError(String(error));
    }
  };

  const ingestWorkspace = async () => {
    setAppError("");
    setIsIngesting(true);
    setIngestionSummary(null);

    try {
      const summary = await invoke<IngestionSummary>("ingest_workspace_graph", {
        request: {
          workspaceRoot,
          neo4jUri,
          neo4jUsername,
          neo4jPassword,
        },
      });
      setIngestionSummary(summary);
    } catch (error) {
      setAppError(String(error));
    } finally {
      setIsIngesting(false);
    }
  };

  const buildContextIndex = async () => {
    setAppError("");
    setIsBuildingIndex(true);
    setIndexSummary(null);

    try {
      const summary = await invoke<ContextIndexSummary>(
        "build_workspace_context_index",
        {
          request: {
            workspaceRoot,
            ollamaHost,
            embeddingModel,
          },
        },
      );
      setIndexSummary(summary);
    } catch (error) {
      setAppError(String(error));
    } finally {
      setIsBuildingIndex(false);
    }
  };

  const analyzeWorkspaceIssue = async () => {
    setAppError("");
    setIsAnalyzing(true);
    setAnalysisResponse(null);

    try {
      const response = await invoke<IssueAnalysisResponse>(
        "analyze_workspace_issue",
        {
          request: {
            workspaceRoot,
            issue: issuePrompt,
            ollamaHost,
            embeddingModel,
            rerankerModel,
            llmBaseUrl,
            llmApiKey,
            llmModel,
            retrievalLimit: 6,
          },
        },
      );
      setAnalysisResponse(response);
    } catch (error) {
      setAppError(String(error));
    } finally {
      setIsAnalyzing(false);
    }
  };

  const fixAndVerifyIssue = async () => {
    setAppError("");
    setIsFixingAndVerifying(true);
    setAnalysisResponse(null);
    let activePrompt = issuePrompt;

    try {
      for (let attempt = 1; attempt <= 3; attempt++) {
        printSystemMessage(`\n--- Autonomous Repair Attempt ${attempt} ---`);
        printSystemMessage("Analyzing issue and waiting for LLM patch proposal...");

        setIsAnalyzing(true);
        const response = await invoke<IssueAnalysisResponse>(
          "analyze_workspace_issue",
          {
            request: {
              workspaceRoot,
              issue: activePrompt,
              ollamaHost,
              embeddingModel,
              rerankerModel,
              llmBaseUrl,
              llmApiKey,
              llmModel,
              retrievalLimit: 6,
            },
          },
        );
        setIsAnalyzing(false);
        setAnalysisResponse(response);

        if (!response.answer) {
          printSystemMessage("LLM returned no answer. Aborting loop.");
          break;
        }

        const match = response.answer.match(/```diff\n([\s\S]*?)\n```/);
        const diff = match ? match[1] : null;

        if (!diff) {
          printSystemMessage("No unified diff block found in the LLM response. Aborting loop.");
          break;
        }

        printSystemMessage("Extracted diff. Applying to workspace...");
        const patchResult = await invoke<{ success: boolean; message: string }>("apply_patch_to_workspace", {
          request: {
            workspaceRoot,
            patchContent: diff,
          },
        });

        printSystemMessage(patchResult.message);
        if (!patchResult.success) {
          printSystemMessage("Failed to apply patch. Aborting loop.");
          break;
        }

        if (!sandboxCommand.trim()) {
          printSystemMessage("✅ No sandbox verification command configured. Assuming patch is successful!");
          break;
        }

        printSystemMessage(`Verifying via sandbox command: ${sandboxCommand}`);
        let verificationPassed = false;
        let capturedConsoleOut = "";

        await new Promise<void>((resolve, reject) => {
          let stdoutUnlisten: (() => void) | undefined;
          let statusUnlisten: (() => void) | undefined;

          const cleanup = () => {
            if (stdoutUnlisten) stdoutUnlisten();
            if (statusUnlisten) statusUnlisten();
          };

          const setupListeners = async () => {
            stdoutUnlisten = await listen<SandboxOutputEvent>("sandbox-output", (event) => {
              capturedConsoleOut += event.payload.chunk;
            });
            statusUnlisten = await listen<SandboxStatusEvent>("sandbox-status", (event) => {
              const stage = event.payload.stage;
              if (stage === "completed") {
                cleanup();
                if (event.payload.exitCode === 0) {
                  verificationPassed = true;
                  resolve();
                } else {
                  resolve(); // Resolve to let the loop continue
                }
              } else if (stage === "failed" || stage === "cancelled") {
                cleanup();
                reject(event.payload.message);
              }
            });
          };

          setupListeners().then(() => {
            invoke<SandboxRunHandle>("start_sandbox_command", {
              request: {
                workspaceRoot,
                image: sandboxImage,
                command: sandboxCommand,
              },
            }).catch((e) => {
              cleanup();
              reject(e);
            });
          });
        });

        if (verificationPassed) {
          printSystemMessage("✅ Verification successful! Issue is resolved.");
          break;
        } else {
          printSystemMessage("❌ Verification failed. Generating revised patch...");
          activePrompt = `${issuePrompt}\n\nThe previously generated patch failed the verification hook. Below is the recent console output to guide your fix:\n\n${capturedConsoleOut.substring(capturedConsoleOut.length - 2000)}`;
        }
      }
    } catch (error) {
      setAppError(String(error));
      printSystemMessage(`Verification loop error: ${String(error)}`);
    } finally {
      setIsFixingAndVerifying(false);
      setIsAnalyzing(false);
    }
  };

  const phaseTwoStatus = isAnalyzing
    ? "analyzing"
    : isBuildingIndex
      ? "indexing"
      : "ready";
  const phaseTwoWarnings = Array.from(
    new Set([
      ...(indexSummary?.warnings ?? []),
      ...(analysisResponse?.warnings ?? []),
    ]),
  );

  return (
    <main className="app-shell">
      <section className="hero-panel">
        <div>
          <p className="eyebrow">Phase 1 + Phase 2</p>
          <h1>AetherVerify</h1>
          <p className="hero-copy">
            Desktop shell for safe code execution, repository graph ingestion,
            local Ollama-based context retrieval, and issue analysis through an
            OpenAI-compatible LLM endpoint.
          </p>
        </div>
        <div className="hero-metrics">
          <div className="metric-card">
            <span className="metric-label">Docker</span>
            <strong>{appContext?.dockerAvailable ? "Connected" : "Unavailable"}</strong>
            <p>{appContext?.dockerMessage ?? "Checking runtime..."}</p>
          </div>
          <div className="metric-card">
            <span className="metric-label">Workspace</span>
            <strong>{workspaceRoot || "Detecting..."}</strong>
            <p>Use a single repository root, not a broad parent directory.</p>
          </div>
          <div className="metric-card">
            <span className="metric-label">Ollama</span>
            <strong>{embeddingModel}</strong>
            <p>{ollamaHost || "Waiting for local model host"}</p>
          </div>
          <div className="metric-card">
            <span className="metric-label">LLM</span>
            <strong>{llmModel || "Configurable"}</strong>
            <p>
              {appContext?.llmApiKeyConfigured
                ? "API key available from environment."
                : "Provide a key in the UI or environment."}
            </p>
          </div>
        </div>
      </section>

      {appError ? <p className="app-error">{appError}</p> : null}

      <section className="workspace-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="panel-label">Secure Terminal</p>
              <h2>Sandboxed command runner</h2>
            </div>
            <span className={`status-badge status-${sandboxStage}`}>
              {sandboxStage}
            </span>
          </div>

          <div className="form-grid">
            <label>
              Workspace root
              <input
                value={workspaceRoot}
                onChange={(event) => setWorkspaceRoot(event.currentTarget.value)}
                placeholder="/path/to/repository"
              />
            </label>
            <label>
              Docker image
              <input
                value={sandboxImage}
                onChange={(event) => setSandboxImage(event.currentTarget.value)}
                placeholder="node:22-bookworm"
              />
            </label>
          </div>

          <label className="command-field">
            Sandbox command
            <textarea
              value={sandboxCommand}
              onChange={(event) => setSandboxCommand(event.currentTarget.value)}
              rows={3}
            />
          </label>

          <div className="action-row">
            <button
              type="button"
              className="primary-button"
              onClick={runSandboxCommand}
              disabled={isLoadingContext || isStartingSandbox}
            >
              {isStartingSandbox ? "Running..." : "Run in Docker"}
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={stopSandboxCommand}
              disabled={!activeRunId}
            >
              Stop run
            </button>
            <p className="status-copy">{sandboxMessage}</p>
          </div>

          <div className="terminal-card">
            <div ref={terminalHostRef} className="terminal-host" />
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="panel-label">Repository Ingestion</p>
              <h2>Tree-sitter to Neo4j graph</h2>
            </div>
            <span className="status-badge status-ingestion">
              {isIngesting ? "ingesting" : "ready"}
            </span>
          </div>

          <p className="panel-copy">
            Parses JavaScript, TypeScript, TSX, Python, and Rust files. It
            extracts functions, methods, classes, call edges, and inheritance
            edges, then persists the graph to Neo4j if credentials are
            available.
          </p>
          <p className="panel-copy">
            Use a single repository root here. Avoid pointing this at a broad
            parent folder like your whole home or development directory.
          </p>

          <div className="form-grid neo4j-grid">
            <label>
              Neo4j URI
              <input
                value={neo4jUri}
                onChange={(event) => setNeo4jUri(event.currentTarget.value)}
                placeholder="bolt://127.0.0.1:7687"
              />
            </label>
            <label>
              Neo4j username
              <input
                value={neo4jUsername}
                onChange={(event) => setNeo4jUsername(event.currentTarget.value)}
                placeholder="neo4j"
              />
            </label>
            <label>
              Neo4j password
              <input
                type="password"
                value={neo4jPassword}
                onChange={(event) => setNeo4jPassword(event.currentTarget.value)}
                placeholder="Optional if set in env"
              />
            </label>
          </div>

          <div className="action-row">
            <button
              type="button"
              className="primary-button"
              onClick={ingestWorkspace}
              disabled={isLoadingContext || isIngesting}
            >
              {isIngesting ? "Ingesting..." : "Build repository graph"}
            </button>
            <p className="status-copy">
              {ingestionSummary?.neo4jStatus ??
                "Graph results will appear here after an ingest run."}
            </p>
          </div>

          <div className="summary-grid">
            <div className="summary-card">
              <span>Scanned files</span>
              <strong>{ingestionSummary?.scannedFiles ?? "0"}</strong>
            </div>
            <div className="summary-card">
              <span>Symbols</span>
              <strong>{ingestionSummary?.symbolCount ?? "0"}</strong>
            </div>
            <div className="summary-card">
              <span>Call edges</span>
              <strong>{ingestionSummary?.callEdgeCount ?? "0"}</strong>
            </div>
            <div className="summary-card">
              <span>Inheritance edges</span>
              <strong>{ingestionSummary?.inheritanceEdgeCount ?? "0"}</strong>
            </div>
          </div>

          <div className="symbol-list">
            <div className="symbol-list-header">
              <h3>Detected symbols</h3>
              <span>{ingestionSummary?.storedToNeo4j ? "Persisted" : "Preview"}</span>
            </div>
            <ul>
              {ingestionSummary?.symbolPreview.length ? (
                ingestionSummary.symbolPreview.map((symbol) => (
                  <li key={`${symbol.filePath}:${symbol.line}:${symbol.name}`}>
                    <div>
                      <strong>{symbol.name}</strong>
                      <span>
                        {symbol.kind} · {symbol.language}
                      </span>
                    </div>
                    <code>
                      {symbol.filePath}:{symbol.line}
                    </code>
                  </li>
                ))
              ) : (
                <li className="empty-state">No graph data generated yet.</li>
              )}
            </ul>
          </div>

          {ingestionSummary?.warnings.length ? (
            <div className="warning-card">
              <h3>Warnings</h3>
              <ul>
                {ingestionSummary.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>
      </section>

      <section className="phase-grid">
        <article className="panel phase-panel">
          <div className="panel-header">
            <div>
              <p className="panel-label">Phase 2</p>
              <h2>Hybrid retrieval and issue analysis</h2>
            </div>
            <span className={`status-badge status-${phaseTwoStatus}`}>
              {phaseTwoStatus}
            </span>
          </div>

          <p className="panel-copy">
            Build a cached context index with Ollama embeddings, rerank the most
            relevant chunks locally, then send the compact prompt to an
            OpenAI-compatible endpoint such as Groq.
          </p>

          <div className="form-grid model-grid">
            <label>
              Ollama host
              <input
                value={ollamaHost}
                onChange={(event) => setOllamaHost(event.currentTarget.value)}
                placeholder="http://127.0.0.1:11434"
              />
            </label>
            <label>
              Embedding model
              <input
                value={embeddingModel}
                onChange={(event) => setEmbeddingModel(event.currentTarget.value)}
                placeholder="snowflake-arctic-embed2:latest"
              />
            </label>
            <label>
              Reranker model
              <input
                value={rerankerModel}
                onChange={(event) => setRerankerModel(event.currentTarget.value)}
                placeholder="qllama/bge-reranker-v2-m3:f16"
              />
            </label>
            <label>
              LLM base URL
              <input
                value={llmBaseUrl}
                onChange={(event) => setLlmBaseUrl(event.currentTarget.value)}
                placeholder="https://api.x.ai/v1"
              />
            </label>
            <label>
              LLM model
              <input
                value={llmModel}
                onChange={(event) => setLlmModel(event.currentTarget.value)}
                placeholder="Enter your Groq model ID (e.g. qwen/qwen3-32b)"
              />
            </label>
            <label>
              LLM API key
              <input
                type="password"
                value={llmApiKey}
                onChange={(event) => setLlmApiKey(event.currentTarget.value)}
                placeholder={
                  appContext?.llmApiKeyConfigured
                    ? "Optional if set in env"
                    : "Paste key or use env"
                }
              />
            </label>
          </div>

          <label className="command-field">
            Issue prompt
            <textarea
              value={issuePrompt}
              onChange={(event) => setIssuePrompt(event.currentTarget.value)}
              rows={5}
            />
          </label>

          <div className="action-row">
            <button
              type="button"
              className="primary-button"
              onClick={buildContextIndex}
              disabled={isLoadingContext || isBuildingIndex || isAnalyzing}
            >
              {isBuildingIndex ? "Indexing..." : "Build context index"}
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={analyzeWorkspaceIssue}
              disabled={isLoadingContext || isBuildingIndex || isAnalyzing || isFixingAndVerifying}
            >
              {isAnalyzing && !isFixingAndVerifying ? "Analyzing..." : "Analyze issue"}
            </button>
            <button
              type="button"
              className="primary-button"
              onClick={fixAndVerifyIssue}
              disabled={isLoadingContext || isBuildingIndex || isAnalyzing || isFixingAndVerifying}
              style={{ background: "linear-gradient(135deg, #72a0ff 0%, #d9a6ff 100%)", color: "#09111f", border: "none" }}
            >
              {isFixingAndVerifying ? "Autonomous loop..." : "Fix & Verify (Auto)"}
            </button>
            <div className="status-stack">
              <p className="status-copy">
                {analysisResponse?.indexStatus ??
                  indexSummary?.indexPath ??
                  "Context index is cached in .aetherverify/context-index.json."}
              </p>
              <p className="status-copy">
                {analysisResponse?.llmStatus ??
                  "If the LLM is not configured, retrieval still works and the answer section stays empty."}
              </p>
            </div>
          </div>

          <div className="summary-grid phase-summary-grid">
            <div className="summary-card">
              <span>Indexed files</span>
              <strong>{indexSummary?.indexedFiles ?? "0"}</strong>
            </div>
            <div className="summary-card">
              <span>Chunks</span>
              <strong>{indexSummary?.chunkCount ?? "0"}</strong>
            </div>
            <div className="summary-card">
              <span>Indexed source</span>
              <strong>
                {indexSummary ? formatMegabytes(indexSummary.totalSourceBytes) : "0.0 MB"}
              </strong>
            </div>
            <div className="summary-card">
              <span>Retrieved context</span>
              <strong>{analysisResponse?.retrievedContext.length ?? "0"}</strong>
            </div>
          </div>

          <div className="phase-two-grid">
            <div className="symbol-list context-list">
              <div className="symbol-list-header">
                <h3>Retrieved context</h3>
                <span>{analysisResponse ? "Ranked" : "Waiting"}</span>
              </div>
              <ul>
                {analysisResponse?.retrievedContext.length ? (
                  analysisResponse.retrievedContext.map((context) => (
                    <li
                      key={`${context.filePath}:${context.startLine}:${context.endLine}`}
                    >
                      <div>
                        <strong>{context.filePath}</strong>
                        <span>
                          {context.language} · lines {context.startLine}-{context.endLine}
                        </span>
                        <p className="context-snippet">{context.snippet}</p>
                      </div>
                      <code>
                        score {context.score}
                        <br />
                        vec {context.vectorScore}
                        <br />
                        lex {context.lexicalScore}
                        {context.rerankScore != null ? (
                          <>
                            <br />
                            rr {context.rerankScore}
                          </>
                        ) : null}
                      </code>
                    </li>
                  ))
                ) : (
                  <li className="empty-state">
                    Build an index and analyze an issue to see ranked repository
                    chunks here.
                  </li>
                )}
              </ul>
            </div>

            <div className="answer-card">
              <div className="symbol-list-header">
                <h3>Model analysis</h3>
                <span>{analysisResponse?.llmModel || "Optional"}</span>
              </div>
              {analysisResponse?.answer ? (
                <pre>{analysisResponse.answer}</pre>
              ) : (
                <p className="empty-state">
                  No model answer yet. Retrieval still works even when the LLM
                  key or model is missing.
                </p>
              )}

              <div className="prompt-card">
                <h3>Prompt preview</h3>
                <pre>{analysisResponse?.promptPreview ?? "Prompt preview appears here after analysis."}</pre>
              </div>
            </div>
          </div>

          {phaseTwoWarnings.length ? (
            <div className="warning-card">
              <h3>Phase 2 warnings</h3>
              <ul>
                {phaseTwoWarnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>
      </section>
    </main>
  );
}

export default App;
