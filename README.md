# AetherVerify

AetherVerify is a Tauri-based desktop IDE for autonomous bug resolution. The project combines sandboxed execution, repository graph extraction, hybrid retrieval, and deterministic verification so an LLM can reason about bugs without directly touching the host machine.

## Current Status

Phase 1 is implemented, and the first working slice of Phase 2 is now in this repository.

Current working scope:

- Tauri v2 + React desktop shell
- xterm-based command console in the UI
- Docker-backed sandbox runner driven from Rust with `bollard`
- Tree-sitter repository ingestion for JavaScript, TypeScript, TSX, Python, and Rust
- Optional Neo4j graph persistence for files, symbols, call edges, and inheritance edges
- Local repository chunk indexing with a bounded `.aetherverify/context-index.json` cache
- Ollama embedding requests using `snowflake-arctic-embed2`
- Ollama rerank requests using `qllama/bge-reranker-v2-m3:f16`
- Issue analysis flow that retrieves ranked code context and can call an OpenAI-compatible endpoint such as Groq

Planned but not implemented yet:

- Graph-traversal-aware retrieval expansion beyond lexical + embedding ranking
- Patch application and retry loop driven directly from the analysis output
- Symbolic verification and counterexample-guided repair

## Why This Exists

Most AI coding tools are optimized for speed, not containment or proof. AetherVerify is being built around three constraints:

- AI-triggered commands must execute inside Docker, not on the host.
- Large repositories need graph-aware context reduction before any LLM call.
- Candidate fixes should be checked against edge cases instead of being accepted on model confidence alone.

## Phase 1 Architecture

| Layer | Implementation | Status |
| --- | --- | --- |
| Desktop UI | Tauri v2 + React + TypeScript | Implemented |
| Terminal surface | `@xterm/xterm` + fit addon | Implemented |
| Sandbox runtime | Docker + Rust `bollard` bridge | Implemented |
| Code ingestion | Tree-sitter parsers in Rust | Implemented |
| Graph persistence | Neo4j via `neo4rs` | Implemented when configured |
| Retrieval | Local Ollama embeddings + reranker + cached chunk index | Initial slice implemented |
| Reasoning | OpenAI-compatible LLM endpoint, including Groq-style setup | Initial slice implemented |
| Verification | CrossHair / KLEE | Planned |

## What Phase 1 Does

### 1. Secure command execution

Commands entered in the UI are sent to the Rust backend and executed inside a Docker container. The selected workspace is mounted read-only, copied into a writable container workspace, and the command runs against that copy.

### 2. Repository graph ingestion

The ingestion pipeline walks the repository, parses supported source files with Tree-sitter, and extracts:

- functions and methods
- classes
- call relationships
- inheritance relationships

If Neo4j credentials are supplied, the app persists those entities and edges into a graph database.

### 3. Phase-oriented desktop shell

The UI exposes the system state needed for the foundation stage:

- Docker runtime status
- workspace selection
- sandbox image selection
- repository graph build status
- Neo4j persistence status and symbol preview

## What Phase 2 Now Does

### 1. Cached context indexing

The app can build a bounded repository context index under `.aetherverify/context-index.json`. The index stores chunked source snippets and their Ollama embeddings so later issue-analysis requests can reuse local context instead of rescanning every time.

### 2. Local hybrid retrieval

When you submit an issue prompt, AetherVerify:

- embeds the prompt with Ollama
- scores cached chunks using embedding similarity plus lexical overlap
- optionally reranks the top candidates through the configured Ollama reranker model

### 3. OpenAI-compatible issue analysis

The retrieved context is assembled into a compact prompt and can be sent to an OpenAI-compatible chat-completions endpoint. The default configuration is aimed at Groq usage, but the base URL and model are configurable.

## Local Development

### Prerequisites

- Node.js 25+
- npm 11+
- Rust toolchain
- Docker
- Linux WebKitGTK development packages for Tauri desktop builds

For Arch/BlackArch, the missing desktop prerequisite is:

```bash
sudo pacman -S --needed webkit2gtk-4.1
```

Optional services:

- Neo4j
- Ollama with `snowflake-arctic-embed2`
- Ollama with `qllama/bge-reranker-v2-m3:f16`

Optional environment variables:

```bash
NEO4J_URI=
NEO4J_USERNAME=
NEO4J_PASSWORD=
OLLAMA_HOST=
AETHERVERIFY_EMBEDDING_MODEL=
AETHERVERIFY_RERANKER_MODEL=
AETHERVERIFY_LLM_BASE_URL=
AETHERVERIFY_LLM_MODEL=
AETHERVERIFY_LLM_API_KEY=
XAI_API_KEY=
GROQ_API_KEY=
OPENAI_API_KEY=
```

### Run the app

```bash
npm install
npm run tauri dev
```

### Frontend-only build

```bash
npm run build
```

## Repository Notes

- The frontend builds successfully with `npm run build`.
- The Tauri desktop build on this machine is currently blocked until `webkit2gtk-4.1` is installed.
- Neo4j persistence is optional; if credentials are blank, ingestion still runs and returns a local summary in the UI.

## Roadmap

### Phase 2: Intelligence and Efficiency

- Deepen retrieval from lexical + embedding ranking into graph-aware traversal and file-neighbor expansion
- Turn the issue-analysis output into a patch proposal flow with diff generation
- Add result reuse, index refresh detection, and better chunking heuristics

### Phase 3: Verification and Demo Layer

- Add symbolic verification with CrossHair and/or KLEE
- Feed counterexamples back into the repair loop
- Build the end-to-end autonomous bug resolution demo flow