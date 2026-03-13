use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use neo4rs::{query, Graph};
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};
use walkdir::{DirEntry, WalkDir};

use crate::workspace::{canonicalize_workspace, validate_repository_scope};

const MAX_SCANNED_FILES: usize = 8_000;
const MAX_SYMBOLS: usize = 120_000;
const MAX_CALLS: usize = 250_000;
const MAX_INHERITANCE_EDGES: usize = 40_000;
const MAX_RESOLVED_CALL_EDGES: usize = 250_000;
const MAX_RESOLVED_INHERITANCE_EDGES: usize = 40_000;
const MAX_NAME_MATCHES_PER_REFERENCE: usize = 32;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_WARNINGS: usize = 25;
const MAX_SYMBOL_PREVIEW: usize = 12;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestionRequest {
    pub workspace_root: String,
    pub neo4j_uri: Option<String>,
    pub neo4j_username: Option<String>,
    pub neo4j_password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestionSummary {
    pub workspace_root: String,
    pub scanned_files: usize,
    pub symbol_count: usize,
    pub call_edge_count: usize,
    pub inheritance_edge_count: usize,
    pub stored_to_neo4j: bool,
    pub neo4j_status: String,
    pub warnings: Vec<String>,
    pub symbol_preview: Vec<SymbolPreview>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolPreview {
    pub name: String,
    pub kind: String,
    pub language: String,
    pub file_path: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
struct CodeSymbol {
    id: String,
    name: String,
    kind: String,
    language: String,
    file_path: String,
    root: String,
    line: usize,
    end_line: usize,
    parent_symbol_id: Option<String>,
}

#[derive(Debug, Clone)]
struct RawCall {
    caller_symbol_id: String,
    callee_name: String,
}

#[derive(Debug, Clone)]
struct RawInheritance {
    class_symbol_id: String,
    base_name: String,
}

#[derive(Debug, Clone)]
struct ResolvedEdge {
    from_id: String,
    to_id: String,
}

#[derive(Debug)]
struct WorkspaceAnalysis {
    scanned_files: usize,
    total_source_bytes: u64,
    symbols: Vec<CodeSymbol>,
    calls: Vec<RawCall>,
    inheritances: Vec<RawInheritance>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct EdgeResolution {
    edges: Vec<ResolvedEdge>,
    ambiguous_reference_count: usize,
    truncated_at_limit: bool,
}

#[derive(Debug, Clone)]
struct Neo4jConfig {
    uri: String,
    username: String,
    password: String,
}

#[derive(Debug, Clone, Copy)]
enum LanguageKind {
    Javascript,
    Typescript,
    Tsx,
    Python,
    Rust,
}

impl LanguageKind {
    fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|value| value.to_str()) {
            Some("js") | Some("jsx") => Some(Self::Javascript),
            Some("ts") => Some(Self::Typescript),
            Some("tsx") => Some(Self::Tsx),
            Some("py") => Some(Self::Python),
            Some("rs") => Some(Self::Rust),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

pub async fn ingest_repository(request: IngestionRequest) -> Result<IngestionSummary, String> {
    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    validate_repository_scope(&workspace_root)?;
    let workspace_root_string = workspace_root.display().to_string();
    let analysis = scan_workspace(&workspace_root)?;

    let name_index = build_name_index(&analysis.symbols);
    let mut warnings = analysis.warnings;
    let call_resolution = resolve_call_edges(&analysis.calls, &name_index);
    let inheritance_resolution = resolve_inheritance_edges(&analysis.inheritances, &name_index);
    let call_edges = call_resolution.edges;
    let inheritance_edges = inheritance_resolution.edges;

    if call_resolution.ambiguous_reference_count > 0 {
        push_warning(
            &mut warnings,
            format!(
                "Capped {} ambiguous call-site resolutions at {} candidate symbols each to keep memory usage bounded.",
                call_resolution.ambiguous_reference_count,
                MAX_NAME_MATCHES_PER_REFERENCE
            ),
        );
    }

    if call_resolution.truncated_at_limit {
        push_warning(
            &mut warnings,
            format!(
                "Stopped resolving call edges after {} edges to keep memory usage bounded.",
                MAX_RESOLVED_CALL_EDGES
            ),
        );
    }

    if inheritance_resolution.ambiguous_reference_count > 0 {
        push_warning(
            &mut warnings,
            format!(
                "Capped {} ambiguous inheritance resolutions at {} candidate symbols each to keep memory usage bounded.",
                inheritance_resolution.ambiguous_reference_count,
                MAX_NAME_MATCHES_PER_REFERENCE
            ),
        );
    }

    if inheritance_resolution.truncated_at_limit {
        push_warning(
            &mut warnings,
            format!(
                "Stopped resolving inheritance edges after {} edges to keep memory usage bounded.",
                MAX_RESOLVED_INHERITANCE_EDGES
            ),
        );
    }

    let mut stored_to_neo4j = false;
    let mut neo4j_status = "Neo4j not configured. Graph parsed locally only.".to_string();

    if let Some(config) = resolve_neo4j_config(&request) {
        match persist_graph(
            &config,
            &workspace_root_string,
            &analysis.symbols,
            &call_edges,
            &inheritance_edges,
        )
        .await
        {
            Ok(()) => {
                stored_to_neo4j = true;
                neo4j_status = format!("Stored graph data in Neo4j at {}", config.uri);
            }
            Err(error) => {
                warnings.push(format!("Neo4j persistence skipped: {error}"));
                neo4j_status = format!("Neo4j configured but persistence failed: {error}");
            }
        }
    }

    let symbol_preview = analysis
        .symbols
        .iter()
        .take(MAX_SYMBOL_PREVIEW)
        .map(|symbol| SymbolPreview {
            name: symbol.name.clone(),
            kind: symbol.kind.clone(),
            language: symbol.language.clone(),
            file_path: symbol.file_path.clone(),
            line: symbol.line,
        })
        .collect();

    Ok(IngestionSummary {
        workspace_root: workspace_root_string,
        scanned_files: analysis.scanned_files,
        symbol_count: analysis.symbols.len(),
        call_edge_count: call_edges.len(),
        inheritance_edge_count: inheritance_edges.len(),
        stored_to_neo4j,
        neo4j_status,
        warnings,
        symbol_preview,
    })
}

fn scan_workspace(workspace_root: &Path) -> Result<WorkspaceAnalysis, String> {
    let mut analysis = WorkspaceAnalysis {
        scanned_files: 0,
        total_source_bytes: 0,
        symbols: Vec::new(),
        calls: Vec::new(),
        inheritances: Vec::new(),
        warnings: Vec::new(),
    };

    for entry in WalkDir::new(workspace_root)
        .max_open(32)
        .into_iter()
        .filter_entry(should_visit_entry)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_warning(
                    &mut analysis.warnings,
                    format!("Skipping unreadable path: {error}"),
                );
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let Some(language) = LanguageKind::from_path(entry.path()) else {
            continue;
        };

        if analysis.scanned_files >= MAX_SCANNED_FILES {
            push_warning(
                &mut analysis.warnings,
                format!(
                    "Stopped after scanning {MAX_SCANNED_FILES} supported files to keep memory usage bounded. Narrow the workspace root to a smaller repository to continue."
                ),
            );
            break;
        }

        let file_size = match entry.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                push_warning(
                    &mut analysis.warnings,
                    format!(
                        "Skipping `{}` because metadata could not be read: {error}",
                        entry.path().display()
                    ),
                );
                continue;
            }
        };

        if file_size > MAX_FILE_BYTES {
            push_warning(
                &mut analysis.warnings,
                format!(
                    "Skipping `{}` because it is larger than the safe ingestion limit of {} bytes.",
                    entry.path().display(),
                    MAX_FILE_BYTES
                ),
            );
            continue;
        }

        if analysis.total_source_bytes.saturating_add(file_size) > MAX_TOTAL_SOURCE_BYTES {
            push_warning(
                &mut analysis.warnings,
                format!(
                    "Stopped after reading about {} MB of source to keep memory usage bounded. Narrow the workspace root to a smaller repository to continue.",
                    MAX_TOTAL_SOURCE_BYTES / (1024 * 1024)
                ),
            );
            break;
        }

        analysis.scanned_files += 1;
        analysis.total_source_bytes += file_size;
        let relative_path = entry
            .path()
            .strip_prefix(workspace_root)
            .unwrap_or(entry.path())
            .display()
            .to_string();

        match analyze_file(workspace_root, &relative_path, entry.path(), language) {
            Ok(file_analysis) => {
                analysis.symbols.extend(file_analysis.symbols);
                analysis.calls.extend(file_analysis.calls);
                analysis.inheritances.extend(file_analysis.inheritances);
                for warning in file_analysis.warnings {
                    push_warning(&mut analysis.warnings, warning);
                }
            }
            Err(error) => {
                push_warning(
                    &mut analysis.warnings,
                    format!("Skipping `{relative_path}`: {error}"),
                );
                continue;
            }
        }

        if analysis.symbols.len() >= MAX_SYMBOLS
            || analysis.calls.len() >= MAX_CALLS
            || analysis.inheritances.len() >= MAX_INHERITANCE_EDGES
        {
            push_warning(
                &mut analysis.warnings,
                format!(
                    "Stopped early because the repository graph exceeded safe in-memory limits (symbols: {MAX_SYMBOLS}, calls: {MAX_CALLS}, inheritance edges: {MAX_INHERITANCE_EDGES}). Narrow the workspace root to a smaller repository to continue."
                ),
            );
            break;
        }
    }

    analysis.symbols.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then(left.line.cmp(&right.line))
            .then(left.name.cmp(&right.name))
    });

    Ok(analysis)
}

#[derive(Debug)]
struct FileAnalysis {
    symbols: Vec<CodeSymbol>,
    calls: Vec<RawCall>,
    inheritances: Vec<RawInheritance>,
    warnings: Vec<String>,
}

fn analyze_file(
    workspace_root: &Path,
    relative_path: &str,
    file_path: &Path,
    language: LanguageKind,
) -> Result<FileAnalysis, String> {
    let source = fs::read_to_string(file_path)
        .map_err(|error| format!("Unable to read source file: {error}"))?;

    let mut parser = Parser::new();
    let language_result = match language {
        LanguageKind::Javascript => parser.set_language(&tree_sitter_javascript::LANGUAGE.into()),
        LanguageKind::Typescript => {
            parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        LanguageKind::Tsx => parser.set_language(&tree_sitter_typescript::LANGUAGE_TSX.into()),
        LanguageKind::Python => parser.set_language(&tree_sitter_python::LANGUAGE.into()),
        LanguageKind::Rust => parser.set_language(&tree_sitter_rust::LANGUAGE.into()),
    };
    language_result.map_err(|error| format!("Unable to load tree-sitter parser: {error}"))?;

    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| "Tree-sitter failed to parse the file".to_string())?;

    let mut collector = FileCollector {
        workspace_root: workspace_root.display().to_string(),
        relative_path: relative_path.to_string(),
        language,
        source: &source,
        symbols: Vec::new(),
        calls: Vec::new(),
        inheritances: Vec::new(),
        warnings: Vec::new(),
    };

    visit_node(tree.root_node(), &mut collector, None);

    Ok(FileAnalysis {
        symbols: collector.symbols,
        calls: collector.calls,
        inheritances: collector.inheritances,
        warnings: collector.warnings,
    })
}

struct FileCollector<'source> {
    workspace_root: String,
    relative_path: String,
    language: LanguageKind,
    source: &'source str,
    symbols: Vec<CodeSymbol>,
    calls: Vec<RawCall>,
    inheritances: Vec<RawInheritance>,
    warnings: Vec<String>,
}

fn visit_node(node: Node<'_>, collector: &mut FileCollector<'_>, current_symbol: Option<String>) {
    let mut active_symbol = current_symbol;

    if let Some(symbol) = symbol_from_node(node, collector, active_symbol.clone()) {
        let symbol_id = symbol.id.clone();
        if symbol.kind == "class" {
            for base_name in inheritance_names(node, collector) {
                collector.inheritances.push(RawInheritance {
                    class_symbol_id: symbol_id.clone(),
                    base_name,
                });
            }
        }
        collector.symbols.push(symbol);
        active_symbol = Some(symbol_id);
    }

    if let Some(caller_symbol_id) = active_symbol.as_ref() {
        if let Some(callee_name) = call_name_from_node(node, collector) {
            collector.calls.push(RawCall {
                caller_symbol_id: caller_symbol_id.clone(),
                callee_name,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit_node(child, collector, active_symbol.clone());
    }
}

fn symbol_from_node(
    node: Node<'_>,
    collector: &FileCollector<'_>,
    parent_symbol_id: Option<String>,
) -> Option<CodeSymbol> {
    let (kind, name) = match collector.language {
        LanguageKind::Javascript | LanguageKind::Typescript | LanguageKind::Tsx => {
            js_like_symbol(node, collector.source)?
        }
        LanguageKind::Python => python_symbol(node, collector.source)?,
        LanguageKind::Rust => rust_symbol(node, collector.source)?,
    };

    Some(CodeSymbol {
        id: format!(
            "{}::{}::{}::{}",
            collector.relative_path,
            node.start_position().row + 1,
            kind,
            name
        ),
        name,
        kind: kind.to_string(),
        language: collector.language.as_str().to_string(),
        file_path: collector.relative_path.clone(),
        root: collector.workspace_root.clone(),
        line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
        parent_symbol_id,
    })
}

fn js_like_symbol(node: Node<'_>, source: &str) -> Option<(&'static str, String)> {
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("function", name))
        }
        "method_definition" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("method", name))
        }
        "class_declaration" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("class", name))
        }
        "variable_declarator" => {
            let value = node.child_by_field_name("value")?;
            if matches!(value.kind(), "arrow_function" | "function_expression") {
                let name = text_of(node.child_by_field_name("name")?, source)?;
                Some(("function", name))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn python_symbol(node: Node<'_>, source: &str) -> Option<(&'static str, String)> {
    match node.kind() {
        "function_definition" | "async_function_definition" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("function", name))
        }
        "class_definition" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("class", name))
        }
        _ => None,
    }
}

fn rust_symbol(node: Node<'_>, source: &str) -> Option<(&'static str, String)> {
    match node.kind() {
        "function_item" => {
            let name = text_of(node.child_by_field_name("name")?, source)?;
            Some(("function", name))
        }
        _ => None,
    }
}

fn call_name_from_node(node: Node<'_>, collector: &FileCollector<'_>) -> Option<String> {
    let is_call = match collector.language {
        LanguageKind::Javascript
        | LanguageKind::Typescript
        | LanguageKind::Tsx
        | LanguageKind::Rust => node.kind() == "call_expression",
        LanguageKind::Python => node.kind() == "call",
    };
    if !is_call {
        return None;
    }

    let function_node = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))?;
    let function_text = text_of(function_node, collector.source)?;
    extract_terminal_name(&function_text)
}

fn inheritance_names(node: Node<'_>, collector: &FileCollector<'_>) -> Vec<String> {
    if node.kind() != "class_declaration" && node.kind() != "class_definition" {
        return Vec::new();
    }

    match collector.language {
        LanguageKind::Javascript | LanguageKind::Typescript | LanguageKind::Tsx => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "class_heritage" {
                    continue;
                }

                let mut heritage_cursor = child.walk();
                let mut base_names = Vec::new();
                for heritage_child in child.named_children(&mut heritage_cursor) {
                    match heritage_child.kind() {
                        "expression" => {
                            if let Some(name) = text_of(heritage_child, collector.source)
                                .and_then(|text| extract_terminal_name(&text))
                            {
                                base_names.push(name);
                            }
                        }
                        "extends_clause" => {
                            if let Some(value_node) = heritage_child.child_by_field_name("value") {
                                if let Some(name) = text_of(value_node, collector.source)
                                    .and_then(|text| extract_terminal_name(&text))
                                {
                                    base_names.push(name);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if !base_names.is_empty() {
                    return base_names;
                }
            }

            Vec::new()
        }
        LanguageKind::Python => {
            let Some(superclasses) = node.child_by_field_name("superclasses") else {
                return Vec::new();
            };

            let mut cursor = superclasses.walk();
            superclasses
                .named_children(&mut cursor)
                .filter_map(|child| {
                    text_of(child, collector.source).and_then(|text| extract_terminal_name(&text))
                })
                .collect()
        }
        LanguageKind::Rust => Vec::new(),
    }
}

fn extract_terminal_name(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut end = None;
    let mut start = None;
    for (index, character) in trimmed.char_indices().rev() {
        if character.is_ascii_alphanumeric() || character == '_' {
            end.get_or_insert(index + character.len_utf8());
            start = Some(index);
        } else if end.is_some() {
            break;
        }
    }

    match (start, end) {
        (Some(start), Some(end)) if start < end => Some(trimmed[start..end].to_string()),
        _ => None,
    }
}

fn text_of(node: Node<'_>, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes()).ok().map(str::to_string)
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

fn build_name_index(symbols: &[CodeSymbol]) -> HashMap<String, Vec<String>> {
    let mut index = HashMap::new();
    for symbol in symbols {
        index
            .entry(symbol.name.clone())
            .or_insert_with(Vec::new)
            .push(symbol.id.clone());
    }
    index
}

fn resolve_call_edges(
    calls: &[RawCall],
    name_index: &HashMap<String, Vec<String>>,
) -> EdgeResolution {
    let mut resolved = Vec::new();
    let mut seen = HashSet::new();
    let mut ambiguous_reference_count = 0;
    let mut truncated_at_limit = false;

    for call in calls {
        if let Some(matches) = name_index.get(&call.callee_name) {
            if matches.len() > MAX_NAME_MATCHES_PER_REFERENCE {
                ambiguous_reference_count += 1;
            }

            for target in matches.iter().take(MAX_NAME_MATCHES_PER_REFERENCE) {
                let edge_key = (call.caller_symbol_id.clone(), target.clone());
                if !seen.insert(edge_key.clone()) {
                    continue;
                }

                resolved.push(ResolvedEdge {
                    from_id: edge_key.0,
                    to_id: edge_key.1,
                });

                if resolved.len() >= MAX_RESOLVED_CALL_EDGES {
                    truncated_at_limit = true;
                    return EdgeResolution {
                        edges: resolved,
                        ambiguous_reference_count,
                        truncated_at_limit,
                    };
                }
            }
        }
    }

    EdgeResolution {
        edges: resolved,
        ambiguous_reference_count,
        truncated_at_limit,
    }
}

fn resolve_inheritance_edges(
    inheritances: &[RawInheritance],
    name_index: &HashMap<String, Vec<String>>,
) -> EdgeResolution {
    let mut resolved = Vec::new();
    let mut seen = HashSet::new();
    let mut ambiguous_reference_count = 0;
    let mut truncated_at_limit = false;

    for inheritance in inheritances {
        if let Some(matches) = name_index.get(&inheritance.base_name) {
            if matches.len() > MAX_NAME_MATCHES_PER_REFERENCE {
                ambiguous_reference_count += 1;
            }

            for target in matches.iter().take(MAX_NAME_MATCHES_PER_REFERENCE) {
                let edge_key = (inheritance.class_symbol_id.clone(), target.clone());
                if !seen.insert(edge_key.clone()) {
                    continue;
                }

                resolved.push(ResolvedEdge {
                    from_id: edge_key.0,
                    to_id: edge_key.1,
                });

                if resolved.len() >= MAX_RESOLVED_INHERITANCE_EDGES {
                    truncated_at_limit = true;
                    return EdgeResolution {
                        edges: resolved,
                        ambiguous_reference_count,
                        truncated_at_limit,
                    };
                }
            }
        }
    }

    EdgeResolution {
        edges: resolved,
        ambiguous_reference_count,
        truncated_at_limit,
    }
}

fn resolve_neo4j_config(request: &IngestionRequest) -> Option<Neo4jConfig> {
    let uri = request
        .neo4j_uri
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("NEO4J_URI").ok())?;
    let username = request
        .neo4j_username
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("NEO4J_USERNAME").ok())?;
    let password = request
        .neo4j_password
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("NEO4J_PASSWORD").ok())?;

    Some(Neo4jConfig {
        uri,
        username,
        password,
    })
}

async fn persist_graph(
    config: &Neo4jConfig,
    workspace_root: &str,
    symbols: &[CodeSymbol],
    call_edges: &[ResolvedEdge],
    inheritance_edges: &[ResolvedEdge],
) -> Result<(), String> {
    let graph = Graph::new(&config.uri, &config.username, &config.password)
        .await
        .map_err(|error| error.to_string())?;

    graph
        .run(query("MATCH (n {root: $root}) DETACH DELETE n").param("root", workspace_root))
        .await
        .map_err(|error| error.to_string())?;

    graph
        .run(query("MERGE (repo:Repository {root: $root})").param("root", workspace_root))
        .await
        .map_err(|error| error.to_string())?;

    for symbol in symbols {
        graph
            .run(
                query(
                    "\
                    MERGE (repo:Repository {root: $root}) \
                    MERGE (file:File {root: $root, path: $file_path}) \
                    SET file.language = $language \
                    MERGE (repo)-[:CONTAINS]->(file) \
                    MERGE (symbol:Symbol {id: $id}) \
                    SET symbol.root = $root, \
                        symbol.name = $name, \
                        symbol.kind = $kind, \
                        symbol.language = $language, \
                        symbol.path = $file_path, \
                        symbol.line = $line, \
                        symbol.endLine = $end_line \
                    MERGE (file)-[:DECLARES]->(symbol)",
                )
                .param("root", symbol.root.clone())
                .param("file_path", symbol.file_path.clone())
                .param("language", symbol.language.clone())
                .param("id", symbol.id.clone())
                .param("name", symbol.name.clone())
                .param("kind", symbol.kind.clone())
                .param("line", symbol.line as i64)
                .param("end_line", symbol.end_line as i64),
            )
            .await
            .map_err(|error| error.to_string())?;

        if let Some(parent_symbol_id) = &symbol.parent_symbol_id {
            graph
                .run(
                    query(
                        "MATCH (parent:Symbol {id: $parent_id}), (child:Symbol {id: $child_id}) MERGE (parent)-[:CONTAINS]->(child)",
                    )
                    .param("parent_id", parent_symbol_id.clone())
                    .param("child_id", symbol.id.clone()),
                )
                .await
                .map_err(|error| error.to_string())?;
        }
    }

    for edge in call_edges {
        graph
            .run(
                query("MATCH (source:Symbol {id: $from}), (target:Symbol {id: $to}) MERGE (source)-[:CALLS]->(target)")
                    .param("from", edge.from_id.clone())
                    .param("to", edge.to_id.clone()),
            )
            .await
            .map_err(|error| error.to_string())?;
    }

    for edge in inheritance_edges {
        graph
            .run(
                query("MATCH (source:Symbol {id: $from}), (target:Symbol {id: $to}) MERGE (source)-[:EXTENDS]->(target)")
                    .param("from", edge.from_id.clone())
                    .param("to", edge.to_id.clone()),
            )
            .await
            .map_err(|error| error.to_string())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_name_index, resolve_call_edges, resolve_inheritance_edges, scan_workspace, RawCall,
        MAX_FILE_BYTES, MAX_NAME_MATCHES_PER_REFERENCE,
    };
    use crate::ingestion::{ingest_repository, IngestionRequest};
    use std::collections::HashMap;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn create_temp_workspace(test_name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("aetherverify-{test_name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("failed to create temporary test workspace");
        root
    }

    fn write_file(root: &Path, relative_path: &str, contents: &str) {
        let file_path = root.join(relative_path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).expect("failed to create parent test directory");
        }
        fs::write(file_path, contents).expect("failed to write test file");
    }

    #[test]
    fn scan_workspace_extracts_calls_and_inheritance() {
        let workspace = create_temp_workspace("js-graph");
        write_file(
            &workspace,
            "src/example.ts",
            r#"
            class Base {}

            class Child extends Base {
              run() {
                helper();
              }
            }

            function helper() {
              return 1;
            }
            "#,
        );

        let analysis = scan_workspace(&workspace).expect("workspace scan should succeed");
        let name_index = build_name_index(&analysis.symbols);
        let calls = resolve_call_edges(&analysis.calls, &name_index).edges;
        let inheritances = resolve_inheritance_edges(&analysis.inheritances, &name_index).edges;

        assert!(analysis.symbols.iter().any(|symbol| symbol.name == "Base"));
        assert!(analysis.symbols.iter().any(|symbol| symbol.name == "Child"));
        assert!(analysis.symbols.iter().any(|symbol| symbol.name == "run"));
        assert!(analysis
            .symbols
            .iter()
            .any(|symbol| symbol.name == "helper"));

        let run_symbol = analysis
            .symbols
            .iter()
            .find(|symbol| symbol.name == "run")
            .expect("run symbol should exist");
        let helper_symbol = analysis
            .symbols
            .iter()
            .find(|symbol| symbol.name == "helper")
            .expect("helper symbol should exist");
        let child_symbol = analysis
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Child")
            .expect("Child symbol should exist");
        let base_symbol = analysis
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Base")
            .expect("Base symbol should exist");

        assert!(calls
            .iter()
            .any(|edge| edge.from_id == run_symbol.id && edge.to_id == helper_symbol.id));
        assert!(inheritances
            .iter()
            .any(|edge| edge.from_id == child_symbol.id && edge.to_id == base_symbol.id));

        fs::remove_dir_all(&workspace).expect("failed to clean up temporary workspace");
    }

    #[tokio::test]
    async fn ingest_repository_returns_local_summary_without_neo4j() {
        let workspace = create_temp_workspace("summary");
        write_file(
            &workspace,
            "app.py",
            r#"
            class Service:
                def run(self):
                    helper()

            def helper():
                return "ok"
            "#,
        );

        let summary = ingest_repository(IngestionRequest {
            workspace_root: workspace.display().to_string(),
            neo4j_uri: None,
            neo4j_username: None,
            neo4j_password: None,
        })
        .await
        .expect("ingestion should succeed");

        assert_eq!(summary.scanned_files, 1);
        assert!(summary.symbol_count >= 3);
        assert!(!summary.stored_to_neo4j);
        assert_eq!(summary.call_edge_count, 1);
        assert_eq!(summary.inheritance_edge_count, 0);

        fs::remove_dir_all(&workspace).expect("failed to clean up temporary workspace");
    }

    #[tokio::test]
    async fn ingest_repository_skips_oversized_files_without_exhausting_memory() {
        let workspace = create_temp_workspace("oversized");
        let oversized_contents = "a".repeat((MAX_FILE_BYTES as usize) + 1024);
        write_file(&workspace, "big.ts", &oversized_contents);

        let summary = ingest_repository(IngestionRequest {
            workspace_root: workspace.display().to_string(),
            neo4j_uri: None,
            neo4j_username: None,
            neo4j_password: None,
        })
        .await
        .expect("ingestion should succeed");

        assert_eq!(summary.scanned_files, 0);
        assert_eq!(summary.symbol_count, 0);
        assert!(summary
            .warnings
            .iter()
            .any(|warning| warning.contains("safe ingestion limit")));

        fs::remove_dir_all(&workspace).expect("failed to clean up temporary workspace");
    }

    #[test]
    fn resolve_call_edges_caps_ambiguous_name_expansion() {
        let calls = vec![RawCall {
            caller_symbol_id: "caller".to_string(),
            callee_name: "run".to_string(),
        }];
        let name_index = HashMap::from([(
            "run".to_string(),
            (0..64)
                .map(|index| format!("target-{index}"))
                .collect::<Vec<_>>(),
        )]);

        let resolution = resolve_call_edges(&calls, &name_index);

        assert_eq!(resolution.edges.len(), MAX_NAME_MATCHES_PER_REFERENCE);
        assert_eq!(resolution.ambiguous_reference_count, 1);
        assert!(!resolution.truncated_at_limit);
    }
}
