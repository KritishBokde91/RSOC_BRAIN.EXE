use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use crate::workspace::{canonicalize_workspace, validate_repository_scope};

const DEFAULT_OLLAMA_HOST: &str = "http://127.0.0.1:11434";
const DEFAULT_EMBEDDING_MODEL: &str = "snowflake-arctic-embed2:latest";
const DEFAULT_LLM_BASE_URL: &str = "https://api.groq.com/openai/v1";
const MAX_WARNINGS: usize = 24;
const MAX_INDEXED_FILES: usize = 1_600;
const MAX_SOURCE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES: u64 = 48 * 1024 * 1024;
const MAX_CONTEXT_CHUNKS: usize = 1_200;
const MAX_CHUNK_LINES: usize = 48;
const CHUNK_OVERLAP_LINES: usize = 10;
const MAX_CHUNK_CHARS: usize = 1_400;
const EMBED_BATCH_SIZE: usize = 16;
const DEFAULT_RETRIEVAL_LIMIT: usize = 6;
const MAX_RETRIEVAL_LIMIT: usize = 10;
const RERANK_CANDIDATE_COUNT: usize = 12;

pub fn default_ollama_host() -> String {
    std::env::var("OLLAMA_HOST").unwrap_or_else(|_| DEFAULT_OLLAMA_HOST.to_string())
}

pub fn default_embedding_model() -> String {
    std::env::var("AETHERVERIFY_EMBEDDING_MODEL")
        .or_else(|_| std::env::var("OLLAMA_EMBEDDING_MODEL"))
        .unwrap_or_else(|_| DEFAULT_EMBEDDING_MODEL.to_string())
}

pub fn default_reranker_model() -> String {
    std::env::var("AETHERVERIFY_RERANKER_MODEL")
        .or_else(|_| std::env::var("OLLAMA_RERANKER_MODEL"))
        .unwrap_or_else(|_| "".to_string())
}

pub fn default_llm_base_url() -> String {
    std::env::var("AETHERVERIFY_LLM_BASE_URL")
        .or_else(|_| std::env::var("XAI_BASE_URL"))
        .or_else(|_| std::env::var("GROQ_BASE_URL"))
        .unwrap_or_else(|_| DEFAULT_LLM_BASE_URL.to_string())
}

pub fn default_llm_model() -> String {
    std::env::var("AETHERVERIFY_LLM_MODEL")
        .or_else(|_| std::env::var("XAI_MODEL"))
        .or_else(|_| std::env::var("GROQ_MODEL"))
        .unwrap_or_default()
}

pub fn llm_api_key_configured() -> bool {
    [
        "AETHERVERIFY_LLM_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "OPENAI_API_KEY",
    ]
    .iter()
    .any(|name| {
        std::env::var(name)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextIndexRequest {
    pub workspace_root: String,
    pub ollama_host: Option<String>,
    pub embedding_model: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextIndexSummary {
    pub workspace_root: String,
    pub index_path: String,
    pub indexed_files: usize,
    pub chunk_count: usize,
    pub total_source_bytes: u64,
    pub embedding_model: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueAnalysisRequest {
    pub workspace_root: String,
    pub issue: String,
    pub ollama_host: Option<String>,
    pub embedding_model: Option<String>,
    pub reranker_model: Option<String>,
    pub llm_base_url: Option<String>,
    pub llm_api_key: Option<String>,
    pub llm_model: Option<String>,
    pub retrieval_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievedContext {
    pub file_path: String,
    pub language: String,
    pub start_line: usize,
    pub end_line: usize,
    pub score: f32,
    pub vector_score: f32,
    pub lexical_score: f32,
    pub rerank_score: Option<f32>,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueAnalysisResponse {
    pub workspace_root: String,
    pub index_status: String,
    pub llm_status: String,
    pub embedding_model: String,
    pub reranker_model: String,
    pub llm_model: String,
    pub prompt_preview: String,
    pub answer: Option<String>,
    pub warnings: Vec<String>,
    pub retrieved_context: Vec<RetrievedContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContextIndex {
    workspace_root: String,
    built_at_unix: u64,
    embedding_model: String,
    indexed_files: usize,
    total_source_bytes: u64,
    chunks: Vec<IndexedChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexedChunk {
    id: String,
    file_path: String,
    language: String,
    start_line: usize,
    end_line: usize,
    content: String,
    lexical_tokens: Vec<String>,
    embedding: Vec<f32>,
}

#[derive(Debug)]
struct ChunkDraft {
    file_path: String,
    language: String,
    start_line: usize,
    end_line: usize,
    content: String,
    lexical_tokens: Vec<String>,
}

#[derive(Debug)]
struct IndexDraft {
    indexed_files: usize,
    total_source_bytes: u64,
    chunks: Vec<ChunkDraft>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct RetrievalCandidate<'index> {
    chunk: &'index IndexedChunk,
    vector_score: f32,
    lexical_score: f32,
    score: f32,
    rerank_score: Option<f32>,
}

#[derive(Debug, Clone)]
struct ResolvedOllamaConfig {
    host: String,
    embedding_model: String,
    reranker_model: String,
}

#[derive(Debug, Clone)]
struct ResolvedLlmConfig {
    base_url: String,
    api_key: String,
    model: String,
}

#[derive(Debug, Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

#[derive(Debug, Deserialize)]
struct OllamaRerankResponse {
    results: Vec<OllamaRerankResult>,
}

#[derive(Debug, Deserialize)]
struct OllamaRerankResult {
    index: usize,
    relevance_score: f32,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionMessage,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionMessage {
    content: Option<String>,
}

pub async fn build_context_index(
    request: ContextIndexRequest,
) -> Result<ContextIndexSummary, String> {
    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    validate_repository_scope(&workspace_root)?;

    let ollama = resolve_ollama_config(&request.ollama_host, &request.embedding_model, None)?;
    let draft = collect_index_draft(&workspace_root)?;
    let embeddings = embed_texts(
        &ollama.host,
        &ollama.embedding_model,
        draft.chunks.iter().map(|chunk| chunk.content.as_str()),
    )
    .await?;

    if embeddings.len() != draft.chunks.len() {
        return Err(format!(
            "Ollama returned {} embeddings for {} chunks.",
            embeddings.len(),
            draft.chunks.len()
        ));
    }

    let chunks = draft
        .chunks
        .into_iter()
        .zip(embeddings.into_iter())
        .enumerate()
        .map(|(index, (chunk, embedding))| IndexedChunk {
            id: format!(
                "{}:{}-{}:{index}",
                chunk.file_path, chunk.start_line, chunk.end_line
            ),
            file_path: chunk.file_path,
            language: chunk.language,
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            content: chunk.content,
            lexical_tokens: chunk.lexical_tokens,
            embedding,
        })
        .collect::<Vec<_>>();

    let index = ContextIndex {
        workspace_root: workspace_root.display().to_string(),
        built_at_unix: unix_now(),
        embedding_model: ollama.embedding_model.clone(),
        indexed_files: draft.indexed_files,
        total_source_bytes: draft.total_source_bytes,
        chunks,
    };

    let index_path = write_index_file(&workspace_root, &index)?;

    Ok(ContextIndexSummary {
        workspace_root: index.workspace_root,
        index_path: index_path.display().to_string(),
        indexed_files: index.indexed_files,
        chunk_count: index.chunks.len(),
        total_source_bytes: index.total_source_bytes,
        embedding_model: index.embedding_model,
        warnings: draft.warnings,
    })
}

pub async fn analyze_issue(request: IssueAnalysisRequest) -> Result<IssueAnalysisResponse, String> {
    if request.issue.trim().is_empty() {
        return Err("Issue prompt cannot be empty".to_string());
    }

    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    validate_repository_scope(&workspace_root)?;

    let ollama = resolve_ollama_config(
        &request.ollama_host,
        &request.embedding_model,
        request.reranker_model.as_deref(),
    )?;
    let llm = resolve_llm_config(
        request.llm_base_url.as_deref(),
        request.llm_api_key.as_deref(),
        request.llm_model.as_deref(),
    );

    let mut warnings = Vec::new();
    let (index, index_status) =
        load_or_build_index(&workspace_root, &ollama, &mut warnings).await?;
    let query_embedding = embed_texts(
        &ollama.host,
        &ollama.embedding_model,
        [request.issue.as_str()],
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| "Ollama did not return an embedding for the issue prompt.".to_string())?;

    let retrieval_limit = request
        .retrieval_limit
        .unwrap_or(DEFAULT_RETRIEVAL_LIMIT)
        .clamp(1, MAX_RETRIEVAL_LIMIT);
    let mut candidates = rank_candidates(&index, &request.issue, &query_embedding);
    candidates.truncate(RERANK_CANDIDATE_COUNT.min(candidates.len()));

    if !candidates.is_empty() && !ollama.reranker_model.is_empty() {
        match rerank_candidates(
            &ollama.host,
            &ollama.reranker_model,
            &request.issue,
            &mut candidates,
        )
        .await
        {
            Ok(()) => {}
            Err(error) => {
                push_warning(
                    &mut warnings,
                    format!("Ollama rerank skipped: {error}. Standard Ollama does not support reranking; leave the model ID empty to skip this step."),
                )
            }
        }
    }

    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
	// Context Expansion Flow: Merge snippet content with neighbor chunks
    let retrieved_context = candidates
        .into_iter()
        .take(retrieval_limit)
        .map(|candidate| {
            let mut expanded_content = candidate.chunk.content.clone();
            let mut expanded_start = candidate.chunk.start_line;
            let mut expanded_end = candidate.chunk.end_line;
            
            // Try expanding once up
            if let Some(prev_chunk) = index.chunks.iter().find(|c| {
                c.file_path == candidate.chunk.file_path && c.end_line >= expanded_start.saturating_sub(MAX_CHUNK_LINES) && c.end_line <= expanded_start
            }) {
                if prev_chunk.start_line < expanded_start {
                    expanded_content = format!("{}\n{}", prev_chunk.content, expanded_content);
                    expanded_start = prev_chunk.start_line;
                }
            }

            // Try expanding once down
            if let Some(next_chunk) = index.chunks.iter().find(|c| {
                c.file_path == candidate.chunk.file_path && c.start_line <= expanded_end + MAX_CHUNK_LINES && c.start_line >= expanded_end
            }) {
                if next_chunk.end_line > expanded_end {
                    expanded_content = format!("{}\n{}", expanded_content, next_chunk.content);
                    expanded_end = next_chunk.end_line;
                }
            }

            RetrievedContext {
                file_path: candidate.chunk.file_path.clone(),
                language: candidate.chunk.language.clone(),
                start_line: expanded_start,
                end_line: expanded_end,
                score: round_score(candidate.score),
                vector_score: round_score(candidate.vector_score),
                lexical_score: round_score(candidate.lexical_score),
                rerank_score: candidate.rerank_score.map(round_score),
                snippet: trim_snippet(&expanded_content, 1200), // increased length for expanded content
            }
        })
        .collect::<Vec<_>>();

    let prompt_preview = build_issue_prompt(&request.issue, &retrieved_context);
    let llm_model = llm
        .as_ref()
        .map(|config| config.model.clone())
        .unwrap_or_default();

    let (llm_status, answer) = match llm {
        Some(config) => match generate_issue_analysis(&config, &prompt_preview).await {
            Ok(answer) => (
                format!(
                    "Analysis generated with `{}` at {}.",
                    config.model, config.base_url
                ),
                Some(answer),
            ),
            Err(error) => {
                push_warning(&mut warnings, format!("LLM analysis skipped: {error}"));
                (
                    "LLM request failed. Retrieval results are still available below.".to_string(),
                    None,
                )
            }
        },
        None => (
            "LLM credentials or model were not configured. Retrieval results are available below."
                .to_string(),
            None,
        ),
    };

    Ok(IssueAnalysisResponse {
        workspace_root: workspace_root.display().to_string(),
        index_status,
        llm_status,
        embedding_model: ollama.embedding_model,
        reranker_model: ollama.reranker_model,
        llm_model,
        prompt_preview,
        answer,
        warnings,
        retrieved_context,
    })
}

fn resolve_ollama_config(
    host_override: &Option<String>,
    embedding_override: &Option<String>,
    reranker_override: Option<&str>,
) -> Result<ResolvedOllamaConfig, String> {
    let host = host_override
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(default_ollama_host);
    let embedding_model = embedding_override
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(default_embedding_model);
    let reranker_model = reranker_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            // Only try to read from env if the property wasn't explicitly passed as empty string
            // from the frontend. In our case, the frontend allows the user to clear it out.
            match reranker_override {
                Some("") => "".to_string(),
                _ => default_reranker_model(),
            }
        });

    if !host.starts_with("http://") && !host.starts_with("https://") {
        return Err("Ollama host must start with http:// or https://".to_string());
    }

    Ok(ResolvedOllamaConfig {
        host: host.trim_end_matches('/').to_string(),
        embedding_model,
        reranker_model,
    })
}

fn resolve_llm_config(
    base_url_override: Option<&str>,
    api_key_override: Option<&str>,
    model_override: Option<&str>,
) -> Option<ResolvedLlmConfig> {
    let base_url = base_url_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            let value = default_llm_base_url();
            if value.trim().is_empty() {
                None
            } else {
                Some(value)
            }
        })?;
    let api_key = api_key_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(resolve_llm_api_key)?;
    let model = model_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            let value = default_llm_model();
            if value.trim().is_empty() {
                None
            } else {
                Some(value)
            }
        })?;

    Some(ResolvedLlmConfig {
        base_url: base_url.trim_end_matches('/').to_string(),
        api_key,
        model,
    })
}

fn resolve_llm_api_key() -> Option<String> {
    [
        "AETHERVERIFY_LLM_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "OPENAI_API_KEY",
    ]
    .iter()
    .find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

async fn load_or_build_index(
    workspace_root: &Path,
    ollama: &ResolvedOllamaConfig,
    warnings: &mut Vec<String>,
) -> Result<(ContextIndex, String), String> {
    let index_path = context_index_path(workspace_root);
    if let Ok(contents) = fs::read_to_string(&index_path) {
        if let Ok(index) = serde_json::from_str::<ContextIndex>(&contents) {
            if index.embedding_model == ollama.embedding_model
                && index.workspace_root == workspace_root.display().to_string()
            {
                // Check if any indexed file was modified after the index was built
                let mut is_stale = false;
                let mut unique_paths = HashSet::new();
                for chunk in &index.chunks {
                    unique_paths.insert(&chunk.file_path);
                }
                for path_str in unique_paths {
                    let full_path = workspace_root.join(path_str);
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        if let Ok(modified) = metadata.modified() {
                            let modified_unix = modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                            if modified_unix > index.built_at_unix {
                                is_stale = true;
                                break;
                            }
                        }
                    } else {
                        // File was probably deleted or moved
                        is_stale = true;
                        break;
                    }
                }

                if !is_stale {
                    return Ok((
                        index,
                        format!("Using cached context index at {}", index_path.display()),
                    ));
                }
                push_warning(
                    warnings,
                    "Cached context index was rebuilt because one or more files were modified."
                        .to_string(),
                );
            } else {
                push_warning(
                    warnings,
                    "Cached context index was rebuilt because the workspace or embedding model changed."
                        .to_string(),
                );
            }
        } else {
            push_warning(
                warnings,
                "Cached context index was unreadable and has been rebuilt.".to_string(),
            );
        }
    }

    let summary = build_context_index(ContextIndexRequest {
        workspace_root: workspace_root.display().to_string(),
        ollama_host: Some(ollama.host.clone()),
        embedding_model: Some(ollama.embedding_model.clone()),
    })
    .await?;

    for warning in summary.warnings {
        push_warning(warnings, warning);
    }

    let contents = fs::read_to_string(&summary.index_path)
        .map_err(|error| format!("Failed to read cached context index: {error}"))?;
    let index = serde_json::from_str::<ContextIndex>(&contents)
        .map_err(|error| format!("Failed to parse cached context index: {error}"))?;

    Ok((
        index,
        format!("Built a fresh context index at {}", summary.index_path),
    ))
}

fn collect_index_draft(workspace_root: &Path) -> Result<IndexDraft, String> {
    let mut indexed_files = 0;
    let mut total_source_bytes: u64 = 0;
    let mut chunks = Vec::new();
    let mut warnings = Vec::new();

    for entry in WalkDir::new(workspace_root)
        .max_open(32)
        .into_iter()
        .filter_entry(should_visit_entry)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_warning(&mut warnings, format!("Skipping unreadable path: {error}"));
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let Some(language) = language_from_path(entry.path()) else {
            continue;
        };

        if indexed_files >= MAX_INDEXED_FILES {
            push_warning(
                &mut warnings,
                format!(
                    "Stopped after indexing {MAX_INDEXED_FILES} files to keep Phase 2 memory usage bounded."
                ),
            );
            break;
        }

        let file_size = match entry.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                push_warning(
                    &mut warnings,
                    format!(
                        "Skipping `{}` because metadata could not be read: {error}",
                        entry.path().display()
                    ),
                );
                continue;
            }
        };

        if file_size > MAX_SOURCE_FILE_BYTES {
            push_warning(
                &mut warnings,
                format!(
                    "Skipping `{}` because it is larger than the Phase 2 source limit of {} bytes.",
                    entry.path().display(),
                    MAX_SOURCE_FILE_BYTES
                ),
            );
            continue;
        }

        if total_source_bytes.saturating_add(file_size) > MAX_TOTAL_SOURCE_BYTES {
            push_warning(
                &mut warnings,
                format!(
                    "Stopped after reading about {} MB of source to keep embeddings bounded.",
                    MAX_TOTAL_SOURCE_BYTES / (1024 * 1024)
                ),
            );
            break;
        }

        let relative_path = entry
            .path()
            .strip_prefix(workspace_root)
            .unwrap_or(entry.path())
            .display()
            .to_string();
        let source = match fs::read_to_string(entry.path()) {
            Ok(source) => source,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    format!("Skipping `{relative_path}`: {error}"),
                );
                continue;
            }
        };

        if source.contains('\0') {
            push_warning(
                &mut warnings,
                format!("Skipping `{relative_path}` because it appears to contain binary data."),
            );
            continue;
        }

        let drafted_chunks = chunk_source(&relative_path, language, &source);
        if drafted_chunks.is_empty() {
            continue;
        }

        let remaining_slots = MAX_CONTEXT_CHUNKS.saturating_sub(chunks.len());
        if remaining_slots == 0 {
            push_warning(
                &mut warnings,
                format!(
                    "Stopped after preparing {MAX_CONTEXT_CHUNKS} chunks to keep embeddings bounded."
                ),
            );
            break;
        }

        indexed_files += 1;
        total_source_bytes += file_size;

        if drafted_chunks.len() > remaining_slots {
            chunks.extend(drafted_chunks.into_iter().take(remaining_slots));
            push_warning(
                &mut warnings,
                format!(
                    "Stopped after preparing {MAX_CONTEXT_CHUNKS} chunks to keep embeddings bounded."
                ),
            );
            break;
        }

        chunks.extend(drafted_chunks);
    }

    Ok(IndexDraft {
        indexed_files,
        total_source_bytes,
        chunks,
        warnings,
    })
}

fn chunk_source(file_path: &str, language: &str, source: &str) -> Vec<ChunkDraft> {
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;

    while start < lines.len() {
        let mut end = start;
        let mut char_count = 0usize;

        while end < lines.len() && (end - start) < MAX_CHUNK_LINES {
            let next_line_len = lines[end].len() + 1;
            if end > start && char_count + next_line_len > MAX_CHUNK_CHARS {
                break;
            }
            char_count += next_line_len;
            end += 1;
        }

        if end == start {
            end += 1;
        }

        let content = lines[start..end].join("\n").trim().to_string();
        if !content.is_empty() {
            chunks.push(ChunkDraft {
                file_path: file_path.to_string(),
                language: language.to_string(),
                start_line: start + 1,
                end_line: end,
                lexical_tokens: collect_tokens(&format!("{file_path}\n{content}")),
                content,
            });
        }

        if end >= lines.len() {
            break;
        }

        start = end.saturating_sub(CHUNK_OVERLAP_LINES);
        if start >= end {
            start = end;
        }
    }

    chunks
}

fn collect_tokens(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut seen = HashSet::new();

    for character in input.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            current.push(character.to_ascii_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 3 && seen.insert(current.clone()) {
                tokens.push(current.clone());
                if tokens.len() >= 32 {
                    break;
                }
            }
            current.clear();
        }
    }

    if !current.is_empty() && current.len() >= 3 && seen.insert(current.clone()) {
        tokens.push(current);
    }

    tokens
}

fn rank_candidates<'index>(
    index: &'index ContextIndex,
    issue: &str,
    query_embedding: &[f32],
) -> Vec<RetrievalCandidate<'index>> {
    let query_tokens = collect_tokens(issue).into_iter().collect::<HashSet<_>>();
    let mut candidates = index
        .chunks
        .iter()
        .map(|chunk| {
            let vector_score = cosine_similarity(query_embedding, &chunk.embedding);
            let lexical_score = lexical_overlap_score(&query_tokens, &chunk.lexical_tokens);
            let score = (vector_score * 0.82) + (lexical_score * 0.18);
            RetrievalCandidate {
                chunk,
                vector_score,
                lexical_score,
                score,
                rerank_score: None,
            }
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
    candidates
}

fn cosine_similarity(left: &[f32], right: &[f32]) -> f32 {
    if left.is_empty() || right.is_empty() || left.len() != right.len() {
        return 0.0;
    }

    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;

    for (left_value, right_value) in left.iter().zip(right.iter()) {
        dot += left_value * right_value;
        left_norm += left_value * left_value;
        right_norm += right_value * right_value;
    }

    if left_norm <= f32::EPSILON || right_norm <= f32::EPSILON {
        return 0.0;
    }

    (dot / (left_norm.sqrt() * right_norm.sqrt())).max(0.0)
}

fn lexical_overlap_score(query_tokens: &HashSet<String>, chunk_tokens: &[String]) -> f32 {
    if query_tokens.is_empty() || chunk_tokens.is_empty() {
        return 0.0;
    }

    let overlap = chunk_tokens
        .iter()
        .filter(|token| query_tokens.contains(*token))
        .count();

    overlap as f32 / query_tokens.len() as f32
}

async fn embed_texts<'text>(
    ollama_host: &str,
    embedding_model: &str,
    inputs: impl IntoIterator<Item = &'text str>,
) -> Result<Vec<Vec<f32>>, String> {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    let client = http_client()?;
    let mut all_embeddings = Vec::new();

    for batch in inputs.chunks(EMBED_BATCH_SIZE) {
        let response = client
            .post(format!("{}/api/embed", ollama_host.trim_end_matches('/')))
            .json(&serde_json::json!({
                "model": embedding_model,
                "input": batch,
            }))
            .send()
            .await
            .map_err(|error| format!("Failed to reach Ollama embed endpoint: {error}"))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Ollama embed request failed with status {}: {}",
                status,
                trim_snippet(&body, 200)
            ));
        }

        let body = response
            .json::<OllamaEmbedResponse>()
            .await
            .map_err(|error| format!("Failed to parse Ollama embed response: {error}"))?;
        all_embeddings.extend(body.embeddings);
    }

    Ok(all_embeddings)
}

async fn rerank_candidates(
    ollama_host: &str,
    reranker_model: &str,
    issue: &str,
    candidates: &mut [RetrievalCandidate<'_>],
) -> Result<(), String> {
    if candidates.is_empty() {
        return Ok(());
    }

    let documents = candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}:{}-{}\n{}",
                candidate.chunk.file_path,
                candidate.chunk.start_line,
                candidate.chunk.end_line,
                trim_snippet(&candidate.chunk.content, 800)
            )
        })
        .collect::<Vec<_>>();

    let client = http_client()?;
    let response = client
        .post(format!("{}/api/rerank", ollama_host.trim_end_matches('/')))
        .json(&serde_json::json!({
            "model": reranker_model,
            "query": issue,
            "documents": documents,
        }))
        .send()
        .await
        .map_err(|error| format!("Failed to reach Ollama rerank endpoint: {error}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Ollama rerank request failed with status {}: {}",
            status,
            trim_snippet(&body, 200)
        ));
    }

    let body = response
        .json::<OllamaRerankResponse>()
        .await
        .map_err(|error| format!("Failed to parse Ollama rerank response: {error}"))?;

    for result in body.results {
        if let Some(candidate) = candidates.get_mut(result.index) {
            candidate.rerank_score = Some(result.relevance_score.max(0.0));
            candidate.score = (candidate.score * 0.25) + (result.relevance_score.max(0.0) * 0.75);
        }
    }

    Ok(())
}

async fn generate_issue_analysis(llm: &ResolvedLlmConfig, prompt: &str) -> Result<String, String> {
    let client = http_client()?;
    let response = client
        .post(format!("{}/chat/completions", llm.base_url.trim_end_matches('/')))
        .bearer_auth(&llm.api_key)
        .json(&serde_json::json!({
            "model": llm.model,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": "You are AetherVerify Phase 2. Diagnose likely root causes from the supplied repository context. Be explicit when the context is insufficient. Structure the answer as Diagnosis, Likely Files, Validation Steps, and a Patch Plan. The Patch Plan MUST contain a properly formatted Unified Diff block ready to be applied (wrapped in ```diff...```)."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }))
        .send()
        .await
        .map_err(|error| format!("Failed to reach the configured LLM endpoint: {error}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "LLM request failed with status {}: {}",
            status,
            trim_snippet(&body, 220)
        ));
    }

    let body = response
        .json::<ChatCompletionResponse>()
        .await
        .map_err(|error| format!("Failed to parse LLM response: {error}"))?;

    body.choices
        .into_iter()
        .find_map(|choice| choice.message.content)
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| "LLM response did not contain any message content.".to_string())
}

fn build_issue_prompt(issue: &str, retrieved_context: &[RetrievedContext]) -> String {
    let mut prompt = String::new();
    prompt.push_str("Issue:\n");
    prompt.push_str(issue.trim());
    prompt.push_str("\n\nRetrieved repository context:\n");

    for (index, context) in retrieved_context.iter().enumerate() {
        prompt.push_str(&format!(
            "\n[Context {}] {}:{}-{} | score {:.3} | vector {:.3} | lexical {:.3}",
            index + 1,
            context.file_path,
            context.start_line,
            context.end_line,
            context.score,
            context.vector_score,
            context.lexical_score
        ));

        if let Some(rerank_score) = context.rerank_score {
            prompt.push_str(&format!(" | rerank {:.3}", rerank_score));
        }

        prompt.push('\n');
        prompt.push_str(&context.snippet);
        prompt.push('\n');
    }

    prompt.push_str(
        "\nReturn the most likely diagnosis, the files or regions to edit, what should be tested next, and a concrete patch plan containing a Unified Diff of the proposed changes.",
    );

    prompt
}

fn context_index_path(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join(".aetherverify")
        .join("context-index.json")
}

fn write_index_file(workspace_root: &Path, index: &ContextIndex) -> Result<PathBuf, String> {
    let path = context_index_path(workspace_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create cache directory: {error}"))?;
    }

    let serialized = serde_json::to_string_pretty(index)
        .map_err(|error| format!("Failed to serialize context index: {error}"))?;
    fs::write(&path, serialized)
        .map_err(|error| format!("Failed to write context index: {error}"))?;
    Ok(path)
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|error| format!("Failed to build HTTP client: {error}"))
}

fn language_from_path(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("js") | Some("jsx") => Some("javascript"),
        Some("ts") | Some("tsx") => Some("typescript"),
        Some("py") => Some("python"),
        Some("rs") => Some("rust"),
        Some("go") => Some("go"),
        Some("java") => Some("java"),
        Some("c") | Some("h") => Some("c"),
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => Some("cpp"),
        Some("json") => Some("json"),
        Some("toml") => Some("toml"),
        Some("yaml") | Some("yml") => Some("yaml"),
        Some("md") => Some("markdown"),
        _ => None,
    }
}

fn should_visit_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }

    !matches!(
        entry.file_name().to_str(),
        Some(".git")
            | Some("node_modules")
            | Some("target")
            | Some("dist")
            | Some(".next")
            | Some(".turbo")
            | Some(".idea")
            | Some(".vscode")
            | Some(".venv")
            | Some("venv")
            | Some("__pycache__")
            | Some(".pytest_cache")
            | Some(".mypy_cache")
            | Some(".cache")
            | Some(".gradle")
            | Some(".yarn")
            | Some(".pnpm-store")
            | Some(".parcel-cache")
            | Some(".svelte-kit")
            | Some(".nuxt")
            | Some("build")
            | Some("out")
            | Some("coverage")
            | Some("tmp")
            | Some("vendor")
            | Some(".aetherverify")
    )
}

fn push_warning(warnings: &mut Vec<String>, message: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(message);
        return;
    }

    if warnings.len() == MAX_WARNINGS {
        warnings.push(format!(
            "Additional warnings were omitted after {MAX_WARNINGS} entries."
        ));
    }
}

fn trim_snippet(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }

    let shortened = trimmed.chars().take(max_chars).collect::<String>();
    format!("{shortened}...")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn round_score(value: f32) -> f32 {
    (value * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::{chunk_source, collect_tokens, cosine_similarity, lexical_overlap_score};
    use std::collections::HashSet;

    #[test]
    fn chunk_source_creates_overlapping_ranges() {
        let source = (1..=80)
            .map(|line| format!("const value_{line} = {line};"))
            .collect::<Vec<_>>()
            .join("\n");

        let chunks = chunk_source("src/example.ts", "typescript", &source);

        assert!(chunks.len() >= 2);
        assert_eq!(chunks[0].start_line, 1);
        assert!(chunks[0].end_line > chunks[1].start_line);
    }

    #[test]
    fn collect_tokens_deduplicates_and_normalizes() {
        let tokens = collect_tokens("Run tests in src/App.tsx before RUN again.");
        assert!(tokens.contains(&"run".to_string()));
        assert!(tokens.contains(&"tests".to_string()));
        assert_eq!(tokens.iter().filter(|token| *token == "run").count(), 1);
    }

    #[test]
    fn lexical_overlap_score_is_zero_without_overlap() {
        let query = ["docker".to_string(), "sandbox".to_string()]
            .into_iter()
            .collect::<HashSet<_>>();
        let chunk = vec!["neo4j".to_string(), "graph".to_string()];

        assert_eq!(lexical_overlap_score(&query, &chunk), 0.0);
    }

    #[test]
    fn cosine_similarity_prefers_parallel_vectors() {
        let aligned = cosine_similarity(&[1.0, 0.0, 1.0], &[1.0, 0.0, 1.0]);
        let orthogonal = cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]);

        assert!(aligned > 0.99);
        assert!(orthogonal < 0.01);
    }
}
