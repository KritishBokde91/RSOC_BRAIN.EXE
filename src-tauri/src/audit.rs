use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use bollard::{
    container::LogOutput,
    models::{ContainerCreateBody, HostConfig, Mount, MountTypeEnum},
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
        RemoveContainerOptionsBuilder, StartContainerOptions, WaitContainerOptionsBuilder,
    },
    Docker,
};
use futures_util::stream::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use walkdir::{DirEntry, WalkDir};

use crate::{
    default_workspace_root,
    intelligence::{default_llm_base_url, default_llm_model},
    workspace::{canonicalize_workspace, validate_repository_scope},
};

const AUDIT_STAGE_EVENT: &str = "audit-stage";
const SANDBOX_OUTPUT_EVENT: &str = "sandbox-output";
const SANDBOX_STATUS_EVENT: &str = "sandbox-status";

const DEFAULT_CLONE_IMAGE: &str = "alpine/git:2.47.1";
const DEFAULT_NODE_IMAGE: &str = "node:22-bookworm";
const DEFAULT_PYTHON_IMAGE: &str = "python:3.12-bookworm";
const DEFAULT_RUST_IMAGE: &str = "rust:1-bookworm";
const DEFAULT_JAVA_IMAGE: &str = "maven:3.9-eclipse-temurin-21";
const DEFAULT_GO_IMAGE: &str = "golang:1.24-bookworm";
const DEFAULT_CPP_IMAGE: &str = "gcc:14-bookworm";

const DEFAULT_COMMAND_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_RUN_TIMEOUT_SECONDS: u64 = 45;
const DEFAULT_SANDBOX_MEMORY_BYTES: i64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 512;
const MAX_REPO_TREE_ENTRIES: usize = 120;
const MAX_MANIFEST_FILES: usize = 8;
const MAX_MANIFEST_CHARS: usize = 4_000;
const MAX_COMMAND_OUTPUT_CHARS: usize = 6_000;
const MAX_ANALYSIS_SNIPPETS: usize = 8;
const MAX_SNIPPET_CHARS: usize = 1_600;
const MAX_FINDINGS: usize = 8;

const PYTHON_CPU_TORCH_MARKERS: &[&str] = &[
    "sentence-transformers",
    "transformers",
    "torch",
    "torchvision",
    "torchaudio",
    "accelerate",
    "peft",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryAuditRequest {
    pub workspace_root: Option<String>,
    pub repository_url: Option<String>,
    pub container_image: Option<String>,
    pub issue_prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryAuditResult {
    pub workspace_root: String,
    pub source_kind: String,
    pub repository_url: Option<String>,
    pub detected_project_type: String,
    pub primary_language: String,
    pub recommended_container_image: String,
    pub selected_container_image: String,
    pub reasoning: String,
    pub install_command: Option<String>,
    pub build_command: Option<String>,
    pub test_command: Option<String>,
    pub run_command: Option<String>,
    pub run_timeout_seconds: u64,
    pub executed_commands: Vec<AuditCommandResult>,
    pub findings: Vec<AuditFinding>,
    pub summary: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditCommandResult {
    pub label: String,
    pub command: String,
    pub exit_code: i64,
    pub status: String,
    pub duration_ms: u64,
    pub output_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub confidence: f32,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub source: String,
    pub evidence: String,
    pub explanation: String,
    pub suggestion: String,
    pub fix_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStagePayload {
    stage: String,
    message: String,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxOutputPayload {
    run_id: String,
    stream: String,
    chunk: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxStatusPayload {
    run_id: String,
    stage: String,
    message: String,
    exit_code: Option<i64>,
}

#[derive(Debug, Clone)]
struct PreparedWorkspace {
    source_root: PathBuf,
    analysis_root: PathBuf,
    source_kind: String,
    repository_url: Option<String>,
}

#[derive(Debug, Clone)]
struct RepositorySnapshot {
    root_entries: Vec<String>,
    tree_entries: Vec<String>,
    manifest_files: Vec<SourceSnippet>,
    language_counts: Vec<(String, usize)>,
}

#[derive(Debug, Clone)]
struct SourceSnippet {
    path: String,
    content: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectPlan {
    #[serde(default)]
    project_type: String,
    #[serde(default)]
    primary_language: String,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    recommended_container_image: String,
    install_command: Option<String>,
    build_command: Option<String>,
    test_command: Option<String>,
    run_command: Option<String>,
    #[serde(default)]
    run_timeout_seconds: Option<u64>,
    #[serde(default)]
    analysis_focus: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditReport {
    summary: String,
    #[serde(default)]
    findings: Vec<AuditFinding>,
}

#[derive(Debug)]
struct ContainerExecution {
    exit_code: i64,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct CommandStep {
    label: &'static str,
    command: String,
    timeout_seconds: u64,
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

pub async fn run_repository_audit(
    app: AppHandle,
    request: RepositoryAuditRequest,
) -> Result<RepositoryAuditResult, String> {
    let overall_start = Instant::now();
    let mut warnings = Vec::new();

    emit_audit_stage(
        &app,
        "preparing-source",
        "Preparing repository source for analysis...",
        0,
    )?;

    let prepared = prepare_workspace(&app, &request).await?;

    emit_audit_stage(
        &app,
        "detecting-project",
        "Inspecting repository structure and asking the LLM how to run it...",
        0,
    )?;
    let detect_start = Instant::now();

    let snapshot = collect_repository_snapshot(&prepared.analysis_root)?;
    let detected_plan = match generate_project_plan(&prepared.analysis_root, &snapshot, &request)
        .await
    {
        Ok(plan) => plan,
        Err(error) => {
            warnings.push(format!(
                "LLM-based stack detection was unavailable, so heuristic detection was used instead: {error}"
            ));
            fallback_project_plan(&prepared.analysis_root, &snapshot)?
        }
    };
    let plan = normalize_project_plan(&prepared.analysis_root, detected_plan);

    emit_audit_stage(
        &app,
        "project-detected",
        format!(
            "Detected {} project in {}. Planned commands are ready.",
            non_empty_or(&plan.project_type, "repository"),
            non_empty_or(&plan.primary_language, "an unknown primary language")
        ),
        detect_start.elapsed().as_millis() as u64,
    )?;

    let selected_image = request
        .container_image
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| recommended_image_for_plan(&plan));

    let command_steps = build_command_steps(&plan);
    let mut executed_commands = Vec::new();

    if command_steps.is_empty() {
        warnings.push(
            "No runnable verification commands could be inferred. The report is based on repository structure only."
                .to_string(),
        );
    }

    for (index, step) in command_steps.iter().enumerate() {
        let run_id = format!("audit-run-{}-{}", unique_suffix(), index + 1);
        let stage_message = format!("Running {} inside `{}`...", step.label, selected_image);
        emit_audit_stage(&app, "running-command", stage_message, 0)?;

        let started = Instant::now();
        let execution = run_workspace_command(
            &app,
            &run_id,
            &prepared.analysis_root,
            &selected_image,
            &step.command,
            step.timeout_seconds,
        )
        .await?;
        let duration_ms = started.elapsed().as_millis() as u64;

        let status = command_status(execution.exit_code, step.timeout_seconds);
        let preview = combined_output_preview(&execution.stdout, &execution.stderr);

        executed_commands.push(AuditCommandResult {
            label: step.label.to_string(),
            command: step.command.clone(),
            exit_code: execution.exit_code,
            status: status.to_string(),
            duration_ms,
            output_preview: preview,
        });

        if step.label == "install" && execution.exit_code != 0 {
            warnings.push(
                "Dependency installation failed, so later command results may be incomplete."
                    .to_string(),
            );
            break;
        }
    }

    emit_audit_stage(
        &app,
        "analyzing-findings",
        "Synthesizing terminal output and repository context into actionable findings...",
        0,
    )?;

    let source_snippets = collect_analysis_snippets(
        &prepared.analysis_root,
        &snapshot,
        &executed_commands,
        &plan,
    )?;
    let issue_prompt = request
        .issue_prompt
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let report = match generate_audit_report(
        &prepared.analysis_root,
        &snapshot,
        &plan,
        &executed_commands,
        &source_snippets,
        issue_prompt,
    )
    .await
    {
        Ok(report) => report,
        Err(error) => {
            warnings.push(format!(
                "LLM-based finding synthesis was unavailable, so the report falls back to command failures only: {error}"
            ));
            fallback_audit_report(&executed_commands)
        }
    };

    emit_audit_stage(
        &app,
        "complete",
        format!(
            "Audit complete. {} commands executed, {} findings generated.",
            executed_commands.len(),
            report.findings.len()
        ),
        overall_start.elapsed().as_millis() as u64,
    )?;

    Ok(RepositoryAuditResult {
        workspace_root: prepared.source_root.display().to_string(),
        source_kind: prepared.source_kind,
        repository_url: prepared.repository_url,
        detected_project_type: non_empty_or(&plan.project_type, "Unknown project").to_string(),
        primary_language: non_empty_or(&plan.primary_language, "Unknown").to_string(),
        recommended_container_image: recommended_image_for_plan(&plan),
        selected_container_image: selected_image,
        reasoning: plan.reasoning,
        install_command: sanitize_optional(plan.install_command),
        build_command: sanitize_optional(plan.build_command),
        test_command: sanitize_optional(plan.test_command),
        run_command: sanitize_optional(plan.run_command),
        run_timeout_seconds: plan
            .run_timeout_seconds
            .unwrap_or(DEFAULT_RUN_TIMEOUT_SECONDS),
        executed_commands,
        findings: normalize_findings(report.findings),
        summary: report.summary,
        warnings,
    })
}

async fn prepare_workspace(
    app: &AppHandle,
    request: &RepositoryAuditRequest,
) -> Result<PreparedWorkspace, String> {
    if let Some(url) = request
        .repository_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let clone_root =
            std::env::temp_dir().join(format!("aetherverify-audit-{}", unique_suffix()));
        fs::create_dir_all(&clone_root)
            .map_err(|error| format!("Failed to create clone directory: {error}"))?;

        let clone_target = clone_root.join("repo");
        let clone_command = build_clone_command(url);
        let run_id = format!("audit-clone-{}", unique_suffix());

        run_generic_container_command(
            app,
            &run_id,
            DEFAULT_CLONE_IMAGE,
            "/analysis-output",
            clone_command,
            vec![rw_mount(&clone_root, "/analysis-output")?],
        )
        .await?;

        let analysis_root = canonicalize_workspace(&clone_target.display().to_string())?;
        validate_repository_scope(&analysis_root)?;

        return Ok(PreparedWorkspace {
            source_root: analysis_root.clone(),
            analysis_root,
            source_kind: "cloned".to_string(),
            repository_url: Some(url.to_string()),
        });
    }

    let workspace_root = request
        .workspace_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            default_workspace_root()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        });

    let source_root = canonicalize_workspace(&workspace_root)?;
    validate_repository_scope(&source_root)?;
    let analysis_root = create_analysis_copy(&source_root)?;

    Ok(PreparedWorkspace {
        source_root,
        analysis_root,
        source_kind: "local".to_string(),
        repository_url: None,
    })
}

fn create_analysis_copy(source_root: &Path) -> Result<PathBuf, String> {
    let analysis_root = std::env::temp_dir()
        .join(format!("aetherverify-audit-{}", unique_suffix()))
        .join("workspace");
    fs::create_dir_all(&analysis_root)
        .map_err(|error| format!("Failed to create analysis workspace: {error}"))?;

    for entry in WalkDir::new(source_root)
        .into_iter()
        .filter_entry(should_visit_repository_entry)
    {
        let entry = entry.map_err(|error| format!("Failed to walk workspace: {error}"))?;
        let relative = entry
            .path()
            .strip_prefix(source_root)
            .map_err(|error| format!("Failed to derive relative path: {error}"))?;

        if relative.as_os_str().is_empty() {
            continue;
        }

        let target = analysis_root.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).map_err(|error| {
                format!(
                    "Failed to create analysis directory {}: {error}",
                    target.display()
                )
            })?;
            continue;
        }

        if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "Failed to create analysis parent directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            fs::copy(entry.path(), &target).map_err(|error| {
                format!(
                    "Failed to copy {} into analysis workspace: {error}",
                    entry.path().display()
                )
            })?;
            if let Ok(metadata) = fs::metadata(entry.path()) {
                let _ = fs::set_permissions(&target, metadata.permissions());
            }
        }
    }

    Ok(analysis_root)
}

fn collect_repository_snapshot(workspace_root: &Path) -> Result<RepositorySnapshot, String> {
    let root_entries = fs::read_dir(workspace_root)
        .map_err(|error| format!("Failed to inspect repository root: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .take(MAX_REPO_TREE_ENTRIES)
        .collect::<Vec<_>>();

    let mut tree_entries = Vec::new();
    let mut language_counts = BTreeMap::new();
    for entry in WalkDir::new(workspace_root)
        .max_depth(3)
        .into_iter()
        .filter_entry(should_visit_repository_entry)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }

        let relative = match entry.path().strip_prefix(workspace_root) {
            Ok(path) => path.display().to_string(),
            Err(_) => continue,
        };

        if tree_entries.len() < MAX_REPO_TREE_ENTRIES {
            tree_entries.push(relative.clone());
        }

        if let Some(language) = language_from_path(entry.path()) {
            *language_counts.entry(language).or_insert(0usize) += 1;
        }
    }

    let manifest_candidates = [
        "README.md",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "requirements.txt",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "go.mod",
        "Makefile",
        "Dockerfile",
    ];

    let manifest_files = manifest_candidates
        .into_iter()
        .filter_map(|relative| {
            let path = workspace_root.join(relative);
            if !path.is_file() {
                return None;
            }
            read_snippet_file(workspace_root, &path, MAX_MANIFEST_CHARS).ok()
        })
        .take(MAX_MANIFEST_FILES)
        .collect::<Vec<_>>();

    let language_counts = language_counts.into_iter().collect::<Vec<_>>();

    Ok(RepositorySnapshot {
        root_entries,
        tree_entries,
        manifest_files,
        language_counts,
    })
}

async fn generate_project_plan(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
    request: &RepositoryAuditRequest,
) -> Result<ProjectPlan, String> {
    let config = resolve_llm_config()?;
    let system_prompt = "You detect repository stacks and propose the safest Docker commands for verifying them. Prefer commands that finish on their own. Use null when you are unsure. Return only JSON.";
    let user_prompt =
        build_project_plan_prompt(workspace_root, snapshot, request.issue_prompt.as_deref());

    let content = send_llm_request(&config, system_prompt, &user_prompt, 1_400).await?;
    let json_content = strip_json_fences(&content);
    let mut plan = serde_json::from_str::<ProjectPlan>(&json_content)
        .map_err(|error| format!("Failed to parse project plan JSON: {error}"))?;

    if plan.recommended_container_image.trim().is_empty() {
        plan.recommended_container_image =
            fallback_project_plan(workspace_root, snapshot)?.recommended_container_image;
    }
    if plan.run_timeout_seconds.unwrap_or(0) == 0 {
        plan.run_timeout_seconds = Some(DEFAULT_RUN_TIMEOUT_SECONDS);
    }

    Ok(plan)
}

fn fallback_project_plan(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
) -> Result<ProjectPlan, String> {
    if workspace_root.join("package.json").is_file() {
        let package_json = fs::read_to_string(workspace_root.join("package.json"))
            .map_err(|error| format!("Failed to read package.json: {error}"))?;
        let package: serde_json::Value = serde_json::from_str(&package_json)
            .map_err(|error| format!("Failed to parse package.json: {error}"))?;
        let scripts = package
            .get("scripts")
            .and_then(|value| value.as_object())
            .cloned()
            .unwrap_or_default();
        let runner = js_script_runner(workspace_root);
        let build_command = pick_script_command(&runner, &scripts, &["build"]);
        let test_command = pick_script_command(&runner, &scripts, &["test"]);
        let run_command =
            pick_script_command(&runner, &scripts, &["start", "dev", "serve", "preview"]);
        let install_command = Some(js_install_command(workspace_root));

        let package_text = package_json.to_lowercase();
        let project_type = if package_text.contains("\"vite\"") {
            "Vite / JavaScript application"
        } else if package_text.contains("\"next\"") {
            "Next.js application"
        } else if package_text.contains("\"react\"") {
            "React application"
        } else if package_text.contains("\"express\"") {
            "Node.js API"
        } else {
            "Node.js project"
        };

        return Ok(ProjectPlan {
            project_type: project_type.to_string(),
            primary_language: dominant_language(snapshot, "JavaScript / TypeScript"),
            reasoning: "Detected package.json at the repository root and inferred commands from the available npm scripts.".to_string(),
            recommended_container_image: DEFAULT_NODE_IMAGE.to_string(),
            install_command,
            build_command,
            test_command,
            run_command,
            run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
            analysis_focus: vec![
                "dependency health".to_string(),
                "runtime startup errors".to_string(),
                "test and build failures".to_string(),
            ],
        });
    }

    if workspace_root.join("pyproject.toml").is_file()
        || workspace_root.join("requirements.txt").is_file()
    {
        let requirements_text = fs::read_to_string(workspace_root.join("requirements.txt")).ok();
        let uses_cpu_torch_strategy = requirements_text
            .as_deref()
            .is_some_and(requires_cpu_torch_strategy);
        let install_command = if workspace_root.join("requirements.txt").is_file() {
            Some(python_install_command(uses_cpu_torch_strategy))
        } else {
            Some("python -m pip install --upgrade pip setuptools wheel && python -m pip install -e .".to_string())
        };
        let test_command = if has_python_tests(workspace_root) {
            Some("python -m pytest -q".to_string())
        } else {
            None
        };
        let run_command = first_existing_command(
            workspace_root,
            &[
                ("main.py", "python main.py"),
                ("app.py", "python app.py"),
                ("manage.py", "python manage.py check"),
            ],
        );

        return Ok(ProjectPlan {
            project_type: "Python project".to_string(),
            primary_language: "Python".to_string(),
            reasoning: if uses_cpu_torch_strategy {
                "Detected Python packaging files at the repository root. This repo also includes transformer-style ML dependencies, so the audit will prefer CPU-only Torch wheels to avoid pulling large CUDA packages inside the analysis container.".to_string()
            } else {
                "Detected Python packaging files at the repository root.".to_string()
            },
            recommended_container_image: DEFAULT_PYTHON_IMAGE.to_string(),
            install_command,
            build_command: None,
            test_command,
            run_command,
            run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
            analysis_focus: vec![
                "dependency installation issues".to_string(),
                "unit test failures".to_string(),
                "entrypoint crashes".to_string(),
                if uses_cpu_torch_strategy {
                    "CPU-only ML dependency setup".to_string()
                } else {
                    "runtime import stability".to_string()
                },
            ],
        });
    }

    if workspace_root.join("Cargo.toml").is_file() {
        return Ok(ProjectPlan {
            project_type: "Rust project".to_string(),
            primary_language: "Rust".to_string(),
            reasoning: "Detected Cargo.toml at the repository root.".to_string(),
            recommended_container_image: DEFAULT_RUST_IMAGE.to_string(),
            install_command: None,
            build_command: Some("cargo build".to_string()),
            test_command: Some("cargo test".to_string()),
            run_command: Some("cargo run".to_string()),
            run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
            analysis_focus: vec![
                "compile failures".to_string(),
                "test regressions".to_string(),
                "runtime panics".to_string(),
            ],
        });
    }

    if workspace_root.join("pom.xml").is_file() {
        return Ok(ProjectPlan {
            project_type: "Java / Maven project".to_string(),
            primary_language: dominant_language(snapshot, "Java"),
            reasoning: "Detected pom.xml at the repository root.".to_string(),
            recommended_container_image: DEFAULT_JAVA_IMAGE.to_string(),
            install_command: None,
            build_command: Some("mvn -q -DskipTests package".to_string()),
            test_command: Some("mvn -q test".to_string()),
            run_command: None,
            run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
            analysis_focus: vec![
                "build failures".to_string(),
                "test failures".to_string(),
                "dependency mismatches".to_string(),
            ],
        });
    }

    if workspace_root.join("go.mod").is_file() {
        return Ok(ProjectPlan {
            project_type: "Go project".to_string(),
            primary_language: "Go".to_string(),
            reasoning: "Detected go.mod at the repository root.".to_string(),
            recommended_container_image: DEFAULT_GO_IMAGE.to_string(),
            install_command: None,
            build_command: Some("go build ./...".to_string()),
            test_command: Some("go test ./...".to_string()),
            run_command: None,
            run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
            analysis_focus: vec![
                "compile failures".to_string(),
                "test regressions".to_string(),
                "panic paths".to_string(),
            ],
        });
    }

    let primary_language = snapshot
        .language_counts
        .first()
        .map(|(language, _)| language.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    Ok(ProjectPlan {
        project_type: "General code repository".to_string(),
        primary_language,
        reasoning: "The repository did not expose a standard manifest at the root, so the audit will focus on structural inspection and any available command output.".to_string(),
        recommended_container_image: DEFAULT_CPP_IMAGE.to_string(),
        install_command: None,
        build_command: None,
        test_command: None,
        run_command: None,
        run_timeout_seconds: Some(DEFAULT_RUN_TIMEOUT_SECONDS),
        analysis_focus: vec!["structural issues".to_string(), "entrypoint discovery".to_string()],
    })
}

fn build_command_steps(plan: &ProjectPlan) -> Vec<CommandStep> {
    let mut steps = Vec::new();
    let mut seen = BTreeSet::new();

    push_unique_step(
        &mut steps,
        &mut seen,
        "install",
        plan.install_command.clone(),
        DEFAULT_COMMAND_TIMEOUT_SECONDS,
    );
    push_unique_step(
        &mut steps,
        &mut seen,
        "test",
        plan.test_command.clone(),
        DEFAULT_COMMAND_TIMEOUT_SECONDS,
    );
    push_unique_step(
        &mut steps,
        &mut seen,
        "build",
        plan.build_command.clone(),
        DEFAULT_COMMAND_TIMEOUT_SECONDS,
    );
    push_unique_step(
        &mut steps,
        &mut seen,
        "run",
        plan.run_command.clone(),
        plan.run_timeout_seconds
            .unwrap_or(DEFAULT_RUN_TIMEOUT_SECONDS),
    );

    steps.truncate(4);
    steps
}

fn push_unique_step(
    steps: &mut Vec<CommandStep>,
    seen: &mut BTreeSet<String>,
    label: &'static str,
    command: Option<String>,
    timeout_seconds: u64,
) {
    let Some(command) = sanitize_optional(command) else {
        return;
    };
    if seen.insert(command.clone()) {
        steps.push(CommandStep {
            label,
            command,
            timeout_seconds,
        });
    }
}

async fn run_workspace_command(
    app: &AppHandle,
    run_id: &str,
    workspace_root: &Path,
    image: &str,
    command: &str,
    timeout_seconds: u64,
) -> Result<ContainerExecution, String> {
    let mounts = vec![rw_mount(workspace_root, "/workspace")?];
    let shell_command = build_workspace_shell_command(command, timeout_seconds);
    run_generic_container_command(app, run_id, image, "/workspace", shell_command, mounts).await
}

async fn run_generic_container_command(
    app: &AppHandle,
    run_id: &str,
    image: &str,
    working_dir: &str,
    shell_command: String,
    mounts: Vec<Mount>,
) -> Result<ContainerExecution, String> {
    let docker = connect_docker().await?;
    ensure_image_available(&docker, app, run_id, image).await?;

    emit_sandbox_status(
        app,
        run_id,
        "starting",
        format!("Starting `{image}` for audit step."),
        None,
    )?;

    let container_name = format!("aetherverify-audit-{}", unique_suffix());
    let host_config = HostConfig {
        mounts: Some(mounts),
        auto_remove: Some(false),
        cap_drop: Some(vec!["ALL".to_string()]),
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        memory: Some(DEFAULT_SANDBOX_MEMORY_BYTES),
        pids_limit: Some(DEFAULT_SANDBOX_PIDS_LIMIT),
        ..Default::default()
    };

    let container_config = ContainerCreateBody {
        image: Some(image.to_string()),
        working_dir: Some(working_dir.to_string()),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        env: Some(vec!["TERM=xterm-256color".to_string()]),
        user: current_user_spec(),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), shell_command]),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create_options = CreateContainerOptionsBuilder::new()
        .name(&container_name)
        .build();

    let created = docker
        .create_container(Some(create_options), container_config)
        .await
        .map_err(|error| format!("Failed to create audit container: {error}"))?;

    docker
        .start_container(&created.id, None::<StartContainerOptions>)
        .await
        .map_err(|error| format!("Failed to start audit container: {error}"))?;

    emit_sandbox_status(
        app,
        run_id,
        "running",
        "Command is running inside the Docker analysis environment.".to_string(),
        None,
    )?;

    let attach_options = AttachContainerOptionsBuilder::new()
        .stream(true)
        .stdout(true)
        .stderr(true)
        .logs(true)
        .build();
    let mut attached = docker
        .attach_container(&created.id, Some(attach_options))
        .await
        .map_err(|error| format!("Failed to attach to audit container logs: {error}"))?;

    let mut stdout = String::new();
    let mut stderr = String::new();

    while let Some(chunk) = attached.output.next().await {
        match chunk {
            Ok(LogOutput::StdOut { message }) => {
                let text = String::from_utf8_lossy(&message).into_owned();
                push_capped(&mut stdout, &text, MAX_COMMAND_OUTPUT_CHARS);
                emit_sandbox_output(app, run_id, "stdout", &text)?;
            }
            Ok(LogOutput::StdErr { message }) => {
                let text = String::from_utf8_lossy(&message).into_owned();
                push_capped(&mut stderr, &text, MAX_COMMAND_OUTPUT_CHARS);
                emit_sandbox_output(app, run_id, "stderr", &text)?;
            }
            Ok(_) => {}
            Err(error) => {
                emit_sandbox_status(
                    app,
                    run_id,
                    "failed",
                    format!("Audit log streaming failed: {error}"),
                    None,
                )?;
                break;
            }
        }
    }

    let wait_options = WaitContainerOptionsBuilder::new()
        .condition("not-running")
        .build();
    let mut wait_stream = docker.wait_container(&created.id, Some(wait_options));
    let exit_code = match wait_stream.next().await {
        Some(Ok(response)) => response.status_code,
        Some(Err(error)) => {
            let error_text = error.to_string();
            let explanation = if error_text.trim().is_empty() {
                "The audit container stopped unexpectedly while the command was running."
                    .to_string()
            } else {
                format!("Failed while waiting for audit command: {error_text}")
            };
            push_capped(
                &mut stderr,
                &format!("\n{explanation}\n"),
                MAX_COMMAND_OUTPUT_CHARS,
            );
            let _ = emit_sandbox_status(app, run_id, "failed", explanation, Some(1));
            1
        }
        None => 1,
    };

    let remove_options = RemoveContainerOptionsBuilder::new().force(true).build();
    docker
        .remove_container(&created.id, Some(remove_options))
        .await
        .map_err(|error| format!("Failed to remove audit container: {error}"))?;

    emit_sandbox_status(
        app,
        run_id,
        if exit_code == 0 {
            "completed"
        } else {
            "failed"
        },
        if exit_code == 0 {
            "Audit command finished successfully.".to_string()
        } else {
            format!("Audit command exited with status {exit_code}.")
        },
        Some(exit_code),
    )?;

    Ok(ContainerExecution {
        exit_code,
        stdout,
        stderr,
    })
}

async fn generate_audit_report(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
    plan: &ProjectPlan,
    executed_commands: &[AuditCommandResult],
    source_snippets: &[SourceSnippet],
    issue_prompt: Option<&str>,
) -> Result<AuditReport, String> {
    let config = resolve_llm_config()?;
    let system_prompt = "You are an expert AI bug detector. Use repository structure, terminal output, and source snippets to identify likely bugs, runtime failures, security risks, and maintainability issues. Return only JSON.";
    let user_prompt = build_audit_report_prompt(
        workspace_root,
        snapshot,
        plan,
        executed_commands,
        source_snippets,
        issue_prompt,
    );

    let content = send_llm_request(&config, system_prompt, &user_prompt, 2_600).await?;
    let json_content = strip_json_fences(&content);
    serde_json::from_str::<AuditReport>(&json_content)
        .map_err(|error| format!("Failed to parse audit report JSON: {error}"))
}

fn fallback_audit_report(executed_commands: &[AuditCommandResult]) -> AuditReport {
    let mut findings = Vec::new();
    for command in executed_commands
        .iter()
        .filter(|command| command.exit_code != 0)
    {
        let mut specialized = specialized_fallback_findings(command);
        findings.append(&mut specialized);

        if findings.len() < MAX_FINDINGS {
            findings.push(generic_fallback_finding(command));
        }

        if findings.len() >= MAX_FINDINGS {
            break;
        }
    }
    findings.truncate(MAX_FINDINGS);

    let summary = if findings.is_empty() {
        "The audit completed without obvious command failures, but deeper LLM synthesis was unavailable.".to_string()
    } else {
        "The fallback report highlights commands that failed during sandbox execution.".to_string()
    };

    AuditReport { summary, findings }
}

fn specialized_fallback_findings(command: &AuditCommandResult) -> Vec<AuditFinding> {
    let output_lower = command.output_preview.to_lowercase();
    let mut findings = Vec::new();

    if output_lower.contains("supabase_url is required") {
        let (file, line) = first_trace_location(&command.output_preview);
        findings.push(AuditFinding {
            id: String::new(),
            title: "Required Supabase configuration is missing".to_string(),
            severity: "High".to_string(),
            category: "Runtime Failure".to_string(),
            confidence: 0.93,
            file,
            line,
            source: "Sandbox execution".to_string(),
            evidence: command.output_preview.clone(),
            explanation: "The app crashes during startup because `create_client(...)` is called before `SUPABASE_URL` is populated from environment configuration.".to_string(),
            suggestion: "Define `SUPABASE_URL` and the matching service-role key in the runtime environment or `.env`, and guard client creation so startup fails with a clearer configuration check before importing request handlers.".to_string(),
            fix_snippet: Some("SUPABASE_URL=...\nSUPABASE_SERVICE_ROLE_KEY=...".to_string()),
        });
    }

    if findings.is_empty() && output_lower.contains(" is required") {
        if let Some(config_name) = extract_required_config_name(&command.output_preview) {
            let (file, line) = first_trace_location(&command.output_preview);
            findings.push(AuditFinding {
                id: String::new(),
                title: format!("Required configuration `{config_name}` is missing"),
                severity: "High".to_string(),
                category: "Runtime Failure".to_string(),
                confidence: 0.9,
                file,
                line,
                source: "Sandbox execution".to_string(),
                evidence: command.output_preview.clone(),
                explanation: format!(
                    "The application startup path expects `{config_name}` to be present, but it was missing when the audit ran."
                ),
                suggestion: format!(
                    "Provide `{config_name}` through the environment or `.env`, and avoid constructing external service clients at import time so the app can fail with a clearer startup validation step."
                ),
                fix_snippet: Some(format!("{config_name}=...")),
            });
        }
    }

    if findings.is_empty()
        && command.label == "test"
        && (output_lower.contains("assertionerror")
            || output_lower.contains("\ne assert ")
            || output_lower.contains(" failed"))
    {
        let (file, line) = first_pytest_failure_location(&command.output_preview);
        findings.push(AuditFinding {
            id: String::new(),
            title: "Dynamic tests exposed a likely logic bug".to_string(),
            severity: "Medium".to_string(),
            category: "Logic Bug".to_string(),
            confidence: 0.84,
            file,
            line,
            source: "Sandbox execution".to_string(),
            evidence: command.output_preview.clone(),
            explanation: "The test suite reached the project logic and failed an assertion, which usually means the implementation does not match the expected behavior for at least one code path.".to_string(),
            suggestion: "Inspect the failing assertion, compare the expected and actual values, and trace that mismatch back to the referenced function or branch before rerunning the audit.".to_string(),
            fix_snippet: None,
        });
    }

    findings
}

fn generic_fallback_finding(command: &AuditCommandResult) -> AuditFinding {
    AuditFinding {
        id: String::new(),
        title: format!("`{}` command did not complete successfully", command.label),
        severity: if command.label == "install" {
            "High".to_string()
        } else {
            "Medium".to_string()
        },
        category: "Dynamic Analysis".to_string(),
        confidence: 0.58,
        file: None,
        line: None,
        source: "Sandbox execution".to_string(),
        evidence: command.output_preview.clone(),
        explanation: format!(
            "The `{}` step exited with status {} while running `{}`.",
            command.label, command.exit_code, command.command
        ),
        suggestion: "Inspect the failing command output, then align dependencies, scripts, entrypoints, and environment variables before rerunning the audit.".to_string(),
        fix_snippet: None,
    }
}

fn first_trace_location(output: &str) -> (Option<String>, Option<usize>) {
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("File \"") else {
            continue;
        };
        let Some((path_part, after_path)) = rest.split_once("\", line ") else {
            continue;
        };
        let line_number = after_path
            .split(',')
            .next()
            .and_then(|value| value.trim().parse::<usize>().ok());
        let file = path_part
            .strip_prefix("/workspace/")
            .unwrap_or(path_part)
            .to_string();
        return (Some(file), line_number);
    }

    (None, None)
}

fn first_pytest_failure_location(output: &str) -> (Option<String>, Option<usize>) {
    let traced = first_trace_location(output);
    if traced.0.is_some() {
        return traced;
    }

    for line in output.lines() {
        let trimmed = line.trim();
        let mut parts = trimmed.split(':');
        let Some(path) = parts.next() else {
            continue;
        };
        let Some(line_number) = parts
            .next()
            .and_then(|value| value.trim().parse::<usize>().ok())
        else {
            continue;
        };
        let path = path.trim().trim_start_matches("./");
        if is_probable_source_path(path) {
            return (Some(path.to_string()), Some(line_number));
        }
    }

    (None, None)
}

fn extract_required_config_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(prefix) = trimmed.split(" is required").next() else {
            continue;
        };
        let candidate = prefix
            .rsplit([':', ' '])
            .next()
            .unwrap_or(prefix)
            .trim_matches(|ch: char| ch == '"' || ch == '\'');
        if candidate.is_empty() {
            continue;
        }
        if candidate
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Some(candidate.to_string());
        }
        if candidate.contains('_') || candidate.ends_with("_url") {
            return Some(candidate.to_string());
        }
    }

    None
}

fn collect_analysis_snippets(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
    executed_commands: &[AuditCommandResult],
    plan: &ProjectPlan,
) -> Result<Vec<SourceSnippet>, String> {
    let mut snippets = Vec::new();
    let mut seen = BTreeSet::new();

    for snippet in &snapshot.manifest_files {
        if seen.insert(snippet.path.clone()) {
            snippets.push(snippet.clone());
        }
    }

    for path in output_referenced_paths(workspace_root, executed_commands) {
        if snippets.len() >= MAX_ANALYSIS_SNIPPETS {
            break;
        }
        if seen.insert(path.clone()) {
            let full_path = workspace_root.join(&path);
            if let Ok(snippet) = read_snippet_file(workspace_root, &full_path, MAX_SNIPPET_CHARS) {
                snippets.push(snippet);
            }
        }
    }

    for candidate in common_entrypoints(plan) {
        if snippets.len() >= MAX_ANALYSIS_SNIPPETS {
            break;
        }
        if seen.insert(candidate.to_string()) {
            let full_path = workspace_root.join(candidate);
            if let Ok(snippet) = read_snippet_file(workspace_root, &full_path, MAX_SNIPPET_CHARS) {
                snippets.push(snippet);
            }
        }
    }

    snippets.truncate(MAX_ANALYSIS_SNIPPETS);
    Ok(snippets)
}

fn build_project_plan_prompt(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
    issue_prompt: Option<&str>,
) -> String {
    let mut prompt = String::new();
    prompt.push_str("Infer the project type and the safest Docker commands to validate it.\n");
    prompt.push_str("Return JSON with these exact keys:\n");
    prompt.push_str(
        "{\"projectType\":\"...\",\"primaryLanguage\":\"...\",\"reasoning\":\"...\",\"recommendedContainerImage\":\"...\",\"installCommand\":\"string or null\",\"buildCommand\":\"string or null\",\"testCommand\":\"string or null\",\"runCommand\":\"string or null\",\"runTimeoutSeconds\":45,\"analysisFocus\":[\"...\"]}\n",
    );
    prompt.push_str("Rules:\n");
    prompt.push_str("- Prefer short-lived commands that finish on their own.\n");
    prompt.push_str("- Do not suggest editors, shells, or interactive commands.\n");
    prompt.push_str("- If the repository looks like a frontend app, prefer build or test commands over long-running dev servers.\n");
    prompt.push_str("- Keep the reasoning concise and factual.\n");
    if let Some(issue_prompt) = issue_prompt
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        prompt.push_str(&format!("- User focus: {issue_prompt}\n"));
    }
    prompt.push_str(&format!(
        "\nRepository root: {}\nTop-level entries:\n{}\n\nRepresentative tree:\n{}\n\nLanguage counts:\n{}\n\nManifest excerpts:\n{}\n",
        workspace_root.display(),
        join_lines(&snapshot.root_entries),
        join_lines(&snapshot.tree_entries),
        snapshot
            .language_counts
            .iter()
            .map(|(language, count)| format!("{language}: {count}"))
            .collect::<Vec<_>>()
            .join("\n"),
        snapshot
            .manifest_files
            .iter()
            .map(|snippet| format!("FILE: {}\n{}\n", snippet.path, snippet.content))
            .collect::<Vec<_>>()
            .join("\n")
    ));
    prompt
}

fn build_audit_report_prompt(
    workspace_root: &Path,
    snapshot: &RepositorySnapshot,
    plan: &ProjectPlan,
    executed_commands: &[AuditCommandResult],
    source_snippets: &[SourceSnippet],
    issue_prompt: Option<&str>,
) -> String {
    let mut prompt = String::new();
    prompt.push_str("Produce a concise bug and vulnerability report for this repository.\n");
    prompt.push_str("Return JSON with this exact schema:\n");
    prompt.push_str(
        "{\"summary\":\"...\",\"findings\":[{\"id\":\"F-001\",\"title\":\"...\",\"severity\":\"Critical|High|Medium|Low\",\"category\":\"Runtime Failure|Build|Test|Logic|Performance|Security|Maintainability|Dynamic Analysis\",\"confidence\":0.82,\"file\":\"relative/path/or null\",\"line\":12,\"source\":\"terminal|code|both\",\"evidence\":\"...\",\"explanation\":\"...\",\"suggestion\":\"...\",\"fixSnippet\":\"string or null\"}]}\n",
    );
    prompt.push_str("Rules:\n");
    prompt.push_str("- Do not invent files or line numbers.\n");
    prompt.push_str(
        "- Prioritize findings backed by terminal output or by the supplied code snippets.\n",
    );
    prompt.push_str("- Suggest a concrete next step or code change for every finding.\n");
    prompt.push_str("- Keep summary to 2-4 sentences and findings to the most actionable items.\n");
    prompt.push_str(&format!("- Limit findings to at most {}.\n", MAX_FINDINGS));
    if let Some(issue_prompt) = issue_prompt
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        prompt.push_str(&format!("- User focus: {issue_prompt}\n"));
    }

    prompt.push_str(&format!(
        "\nRepository root: {}\nDetected project type: {}\nPrimary language: {}\nLLM run strategy reasoning: {}\nAnalysis focus: {}\n\nRepresentative tree:\n{}\n\nCommand results:\n{}\n\nSource snippets:\n{}\n",
        workspace_root.display(),
        non_empty_or(&plan.project_type, "Unknown"),
        non_empty_or(&plan.primary_language, "Unknown"),
        non_empty_or(&plan.reasoning, "No reasoning was available."),
        if plan.analysis_focus.is_empty() {
            "None specified".to_string()
        } else {
            plan.analysis_focus.join(", ")
        },
        join_lines(&snapshot.tree_entries),
        executed_commands
            .iter()
            .map(|result| {
                format!(
                    "STEP: {}\nCOMMAND: {}\nSTATUS: {} (exit {})\nOUTPUT:\n{}\n",
                    result.label,
                    result.command,
                    result.status,
                    result.exit_code,
                    result.output_preview
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        source_snippets
            .iter()
            .map(|snippet| format!("FILE: {}\n{}\n", snippet.path, snippet.content))
            .collect::<Vec<_>>()
            .join("\n")
    ));

    prompt
}

fn normalize_findings(findings: Vec<AuditFinding>) -> Vec<AuditFinding> {
    findings
        .into_iter()
        .take(MAX_FINDINGS)
        .enumerate()
        .map(|(index, mut finding)| {
            finding.id = if finding.id.trim().is_empty() {
                format!("F-{:03}", index + 1)
            } else {
                finding.id
            };
            finding.severity = normalize_severity(&finding.severity);
            finding.confidence = finding.confidence.clamp(0.0, 1.0);
            finding
        })
        .collect()
}

fn normalize_severity(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "critical" => "Critical".to_string(),
        "high" => "High".to_string(),
        "medium" => "Medium".to_string(),
        "low" => "Low".to_string(),
        _ => "Medium".to_string(),
    }
}

fn recommended_image_for_plan(plan: &ProjectPlan) -> String {
    sanitize_optional(Some(plan.recommended_container_image.clone()))
        .unwrap_or_else(|| DEFAULT_NODE_IMAGE.to_string())
}

async fn send_llm_request(
    config: &ResolvedLlmConfig,
    system_prompt: &str,
    user_prompt: &str,
    max_tokens: usize,
) -> Result<String, String> {
    let client = Client::new();
    let request_body = serde_json::json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ],
        "temperature": 0.15,
        "max_tokens": max_tokens
    });

    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|error| format!("LLM request failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("LLM returned {status}: {body}"));
    }

    let completion = response
        .json::<ChatCompletionResponse>()
        .await
        .map_err(|error| format!("Failed to parse LLM response: {error}"))?;

    completion
        .choices
        .first()
        .and_then(|choice| choice.message.content.clone())
        .ok_or_else(|| "LLM response was empty".to_string())
}

#[derive(Debug, Clone)]
struct ResolvedLlmConfig {
    base_url: String,
    api_key: String,
    model: String,
}

fn resolve_llm_config() -> Result<ResolvedLlmConfig, String> {
    let base_url = default_llm_base_url();
    let model = default_llm_model();
    let api_key = resolve_llm_api_key()
        .ok_or_else(|| "No LLM API key is configured. Set GROQ_API_KEY, OPENAI_API_KEY, XAI_API_KEY, or AETHERVERIFY_LLM_API_KEY.".to_string())?;

    if model.trim().is_empty() {
        return Err(
            "No LLM model is configured. Set GROQ_MODEL, XAI_MODEL, or AETHERVERIFY_LLM_MODEL."
                .to_string(),
        );
    }

    Ok(ResolvedLlmConfig {
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

async fn connect_docker() -> Result<Docker, String> {
    let docker = Docker::connect_with_local_defaults()
        .map_err(|error| format!("Failed to create Docker client: {error}"))?;
    docker
        .version()
        .await
        .map_err(|error| format!("Failed to reach Docker: {error}"))?;
    Ok(docker)
}

async fn ensure_image_available(
    docker: &Docker,
    app: &AppHandle,
    run_id: &str,
    image: &str,
) -> Result<(), String> {
    if docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }

    emit_sandbox_status(
        app,
        run_id,
        "pulling-image",
        format!("Pulling Docker image `{image}`..."),
        None,
    )?;

    let options = CreateImageOptionsBuilder::new().from_image(image).build();
    let mut pull_stream = docker.create_image(Some(options), None, None);
    while let Some(progress) = pull_stream.next().await {
        match progress {
            Ok(details) => {
                if let Some(status) = details.status {
                    emit_sandbox_status(app, run_id, "pulling-image", status, None)?;
                }
            }
            Err(error) => return Err(format!("Failed to pull Docker image `{image}`: {error}")),
        }
    }

    Ok(())
}

fn emit_audit_stage(
    app: &AppHandle,
    stage: &str,
    message: impl Into<String>,
    duration_ms: u64,
) -> Result<(), String> {
    app.emit(
        AUDIT_STAGE_EVENT,
        AuditStagePayload {
            stage: stage.to_string(),
            message: message.into(),
            duration_ms,
        },
    )
    .map_err(|error| error.to_string())
}

fn emit_sandbox_output(
    app: &AppHandle,
    run_id: &str,
    stream: &str,
    chunk: &str,
) -> Result<(), String> {
    app.emit(
        SANDBOX_OUTPUT_EVENT,
        SandboxOutputPayload {
            run_id: run_id.to_string(),
            stream: stream.to_string(),
            chunk: chunk.to_string(),
        },
    )
    .map_err(|error| error.to_string())
}

fn emit_sandbox_status(
    app: &AppHandle,
    run_id: &str,
    stage: &str,
    message: String,
    exit_code: Option<i64>,
) -> Result<(), String> {
    app.emit(
        SANDBOX_STATUS_EVENT,
        SandboxStatusPayload {
            run_id: run_id.to_string(),
            stage: stage.to_string(),
            message,
            exit_code,
        },
    )
    .map_err(|error| error.to_string())
}

fn build_clone_command(repository_url: &str) -> String {
    let escaped_url = repository_url.replace('\'', r"'\''");
    format!(
        "set -eu; rm -rf /analysis-output/repo; git clone --depth 1 '{}' /analysis-output/repo",
        escaped_url
    )
}

fn build_workspace_shell_command(command: &str, timeout_seconds: u64) -> String {
    let escaped_command = command.replace('\'', r"'\''");
    format!(
        "set -eu; cd /workspace; export HOME=\"/workspace/.aetherverify-home\"; export XDG_CACHE_HOME=\"/workspace/.aetherverify-cache\"; export PATH=\"$HOME/.local/bin:$PATH\"; mkdir -p \"$HOME\" \"$XDG_CACHE_HOME\"; if command -v timeout >/dev/null 2>&1; then timeout --signal=TERM {}s sh -c '{}'; else sh -c '{}'; fi",
        timeout_seconds, escaped_command, escaped_command
    )
}

fn rw_mount(source: &Path, target: &str) -> Result<Mount, String> {
    Ok(Mount {
        target: Some(target.to_string()),
        source: Some(source.display().to_string()),
        typ: Some(MountTypeEnum::BIND),
        read_only: Some(false),
        ..Default::default()
    })
}

fn current_user_spec() -> Option<String> {
    let uid = command_output_trimmed("id", &["-u"])?;
    let gid = command_output_trimmed("id", &["-g"])?;
    Some(format!("{uid}:{gid}"))
}

fn command_output_trimmed(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_snippet_file(
    workspace_root: &Path,
    file_path: &Path,
    max_chars: usize,
) -> Result<SourceSnippet, String> {
    let content = fs::read_to_string(file_path)
        .map_err(|error| format!("Failed to read {}: {error}", file_path.display()))?;
    let relative = file_path
        .strip_prefix(workspace_root)
        .unwrap_or(file_path)
        .display()
        .to_string();

    Ok(SourceSnippet {
        path: relative,
        content: trim_text(&content, max_chars),
    })
}

fn output_referenced_paths(
    workspace_root: &Path,
    executed_commands: &[AuditCommandResult],
) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();

    for command in executed_commands {
        for token in command.output_preview.split_whitespace() {
            let candidate = token
                .trim_matches(|ch: char| {
                    matches!(ch, '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';')
                })
                .replace("\\", "/");
            let candidate = candidate
                .strip_prefix("/workspace/")
                .unwrap_or(&candidate)
                .trim_end_matches(':');
            let path_part = candidate.split(':').next().unwrap_or(candidate).trim();
            if path_part.is_empty() || path_part.len() > 180 {
                continue;
            }
            if !is_probable_source_path(path_part) {
                continue;
            }
            let full_path = workspace_root.join(path_part);
            if full_path.is_file() && seen.insert(path_part.to_string()) {
                paths.push(path_part.to_string());
            }
        }
    }

    paths
}

fn common_entrypoints(plan: &ProjectPlan) -> Vec<&'static str> {
    let language = plan.primary_language.to_lowercase();
    if language.contains("python") {
        return vec!["main.py", "app.py", "src/main.py"];
    }
    if language.contains("rust") {
        return vec!["src/main.rs", "src/lib.rs"];
    }
    if language.contains("java") {
        return vec!["src/main/java/App.java", "src/main/java/Application.java"];
    }
    if language.contains("go") {
        return vec!["main.go", "cmd/main.go"];
    }
    vec![
        "src/main.ts",
        "src/main.tsx",
        "src/index.ts",
        "src/index.tsx",
        "src/App.tsx",
        "src/index.js",
        "src/App.jsx",
    ]
}

fn should_visit_repository_entry(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    if entry.file_type().is_dir() {
        return !matches!(
            name.as_ref(),
            ".git"
                | "node_modules"
                | "dist"
                | "build"
                | "target"
                | ".next"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".idea"
                | ".vscode"
                | "coverage"
                | ".aetherverify-home"
                | ".aetherverify-cache"
                | ".local"
        );
    }
    true
}

fn language_from_path(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    let language = match ext.as_str() {
        "js" | "jsx" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "py" => "Python",
        "rs" => "Rust",
        "java" => "Java",
        "go" => "Go",
        "c" => "C",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => "C++",
        "cs" => "C#",
        "php" => "PHP",
        "rb" => "Ruby",
        _ => return None,
    };
    Some(language.to_string())
}

fn has_path(workspace_root: &Path, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| workspace_root.join(candidate).exists())
}

fn has_python_tests(workspace_root: &Path) -> bool {
    if has_path(workspace_root, &["tests", "test"]) {
        return true;
    }

    fs::read_dir(workspace_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .any(|name| {
            (name.starts_with("test_") && name.ends_with(".py")) || name.ends_with("_test.py")
        })
}

fn first_existing_command(workspace_root: &Path, candidates: &[(&str, &str)]) -> Option<String> {
    candidates.iter().find_map(|(relative, command)| {
        workspace_root
            .join(relative)
            .is_file()
            .then(|| (*command).to_string())
    })
}

fn normalize_project_plan(workspace_root: &Path, mut plan: ProjectPlan) -> ProjectPlan {
    let is_python_project = workspace_root.join("requirements.txt").is_file()
        || workspace_root.join("pyproject.toml").is_file()
        || plan.primary_language.to_lowercase().contains("python")
        || plan.project_type.to_lowercase().contains("python");

    if !is_python_project {
        return plan;
    }

    let requirements_text = fs::read_to_string(workspace_root.join("requirements.txt")).ok();
    let uses_cpu_torch = requirements_text
        .as_deref()
        .is_some_and(requires_cpu_torch_strategy);

    if workspace_root.join("requirements.txt").is_file() {
        plan.install_command = Some(python_install_command(uses_cpu_torch));
    } else if workspace_root.join("pyproject.toml").is_file() {
        plan.install_command = Some(
            "python -m pip install --user --no-cache-dir --disable-pip-version-check --no-warn-script-location -e ."
                .to_string(),
        );
    }

    plan.test_command = normalize_python_test_command(plan.test_command);

    if plan.test_command.is_none() && has_python_tests(workspace_root) {
        plan.test_command = Some("python -m pytest -q".to_string());
    }

    plan.primary_language = "Python".to_string();
    if plan.recommended_container_image.trim().is_empty() {
        plan.recommended_container_image = DEFAULT_PYTHON_IMAGE.to_string();
    }
    if uses_cpu_torch && !plan.reasoning.to_lowercase().contains("cpu-only torch") {
        if !plan.reasoning.trim().is_empty() {
            plan.reasoning.push(' ');
        }
        plan.reasoning.push_str(
            "The audit normalizes Python installs to a persistent writable workspace and prefers CPU-only Torch wheels when transformer dependencies are present.",
        );
    }

    if uses_cpu_torch
        && !plan
            .analysis_focus
            .iter()
            .any(|item| item.contains("CPU-only ML dependency setup"))
    {
        plan.analysis_focus
            .push("CPU-only ML dependency setup".to_string());
    }

    plan
}

fn normalize_python_test_command(command: Option<String>) -> Option<String> {
    let command = sanitize_optional(command)?;
    let trimmed = command.trim();

    if trimmed.starts_with("python -m pytest") || trimmed.starts_with("python3 -m pytest") {
        return Some(trimmed.to_string());
    }

    if let Some(args) = trimmed.strip_prefix("pytest") {
        let args = args.trim();
        return Some(if args.is_empty() {
            "python -m pytest -q".to_string()
        } else {
            format!("python -m pytest {args}")
        });
    }

    if let Some(args) = trimmed.strip_prefix("py.test") {
        let args = args.trim();
        return Some(if args.is_empty() {
            "python -m pytest -q".to_string()
        } else {
            format!("python -m pytest {args}")
        });
    }

    Some(trimmed.to_string())
}

fn requires_cpu_torch_strategy(requirements_text: &str) -> bool {
    let normalized = requirements_text.to_lowercase();
    PYTHON_CPU_TORCH_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn python_install_command(uses_cpu_torch_strategy: bool) -> String {
    let base =
        "python -m pip install --user --no-cache-dir --disable-pip-version-check --no-warn-script-location";
    if uses_cpu_torch_strategy {
        format!(
            "{base} --index-url https://download.pytorch.org/whl/cpu --extra-index-url https://pypi.org/simple 'torch<3' && {base} -r requirements.txt"
        )
    } else {
        format!("{base} -r requirements.txt")
    }
}

fn dominant_language(snapshot: &RepositorySnapshot, fallback: &str) -> String {
    snapshot
        .language_counts
        .first()
        .map(|(language, _)| language.clone())
        .unwrap_or_else(|| fallback.to_string())
}

fn js_script_runner(workspace_root: &Path) -> String {
    if workspace_root.join("pnpm-lock.yaml").is_file() {
        "pnpm".to_string()
    } else if workspace_root.join("yarn.lock").is_file() {
        "yarn".to_string()
    } else {
        "npm".to_string()
    }
}

fn js_install_command(workspace_root: &Path) -> String {
    if workspace_root.join("pnpm-lock.yaml").is_file() {
        "corepack enable && pnpm install".to_string()
    } else if workspace_root.join("yarn.lock").is_file() {
        "corepack enable && yarn install --frozen-lockfile".to_string()
    } else {
        "npm install".to_string()
    }
}

fn pick_script_command(
    runner: &str,
    scripts: &serde_json::Map<String, serde_json::Value>,
    candidate_names: &[&str],
) -> Option<String> {
    let candidate = candidate_names.iter().find_map(|name| {
        scripts
            .get(*name)
            .and_then(|value| value.as_str())
            .filter(|script| !script.contains("no test specified"))
            .map(|_| (*name).to_string())
    })?;

    Some(match runner {
        "pnpm" => format!("corepack enable && pnpm {candidate}"),
        "yarn" => format!("corepack enable && yarn {candidate}"),
        _ => format!("npm run {candidate}"),
    })
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn sanitize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn strip_json_fences(input: &str) -> String {
    let without_think = strip_think_blocks(input);
    let trimmed = without_think.trim();
    let unfenced = trimmed
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    if serde_json::from_str::<serde_json::Value>(unfenced).is_ok() {
        return unfenced.to_string();
    }

    extract_first_json_value(unfenced).unwrap_or_else(|| unfenced.to_string())
}

fn strip_think_blocks(input: &str) -> String {
    let mut cleaned = String::with_capacity(input.len());
    let mut remainder = input;

    while let Some(start) = remainder.find("<think>") {
        let (before, after_start) = remainder.split_at(start);
        cleaned.push_str(before);

        let after_tag = &after_start["<think>".len()..];
        let Some(end) = after_tag.find("</think>") else {
            return cleaned;
        };
        remainder = &after_tag[end + "</think>".len()..];
    }

    cleaned.push_str(remainder);
    cleaned
}

fn extract_first_json_value(input: &str) -> Option<String> {
    let (start, opener) = input
        .char_indices()
        .find(|(_, ch)| *ch == '{' || *ch == '[')?;
    let closer = if opener == '{' { '}' } else { ']' };
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in input[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            value if value == opener => depth += 1,
            value if value == closer => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return Some(input[start..end].trim().to_string());
                }
            }
            _ => {}
        }
    }

    None
}

fn trim_text(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }

    let head = max_chars / 2;
    let tail = max_chars.saturating_sub(head + 20);
    let start = input.chars().take(head).collect::<String>();
    let end = input
        .chars()
        .rev()
        .take(tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{start}\n... trimmed ...\n{end}")
}

fn combined_output_preview(stdout: &str, stderr: &str) -> String {
    let merged = if stderr.trim().is_empty() {
        stdout.to_string()
    } else if stdout.trim().is_empty() {
        stderr.to_string()
    } else {
        format!("STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
    };
    trim_text(&merged, MAX_COMMAND_OUTPUT_CHARS)
}

fn command_status(exit_code: i64, timeout_seconds: u64) -> &'static str {
    if exit_code == 0 {
        "passed"
    } else if exit_code == 124 && timeout_seconds > 0 {
        "timed_out"
    } else {
        "failed"
    }
}

fn push_capped(buffer: &mut String, addition: &str, max_chars: usize) {
    buffer.push_str(addition);
    if buffer.chars().count() > max_chars {
        *buffer = trim_text(buffer, max_chars);
    }
}

fn join_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        "(none)".to_string()
    } else {
        lines.join("\n")
    }
}

fn is_probable_source_path(value: &str) -> bool {
    [
        ".js", ".jsx", ".ts", ".tsx", ".py", ".rs", ".java", ".go", ".c", ".cc", ".cpp", ".cxx",
        ".hpp", ".h", ".json", ".toml", ".yaml", ".yml",
    ]
    .iter()
    .any(|suffix| value.ends_with(suffix))
}

fn unique_suffix() -> String {
    uuid::Uuid::new_v4().to_string().chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        build_workspace_shell_command, extract_required_config_name, fallback_project_plan,
        has_python_tests, is_probable_source_path, js_install_command,
        normalize_python_test_command, python_install_command, requires_cpu_torch_strategy,
        strip_json_fences, RepositorySnapshot, SourceSnippet,
    };
    use std::{fs, path::PathBuf};

    fn temp_dir(test_name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "aetherverify-audit-{test_name}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("failed to create temp directory");
        root
    }

    #[test]
    fn workspace_command_wraps_timeout_and_copy() {
        let shell = build_workspace_shell_command("npm test", 45);
        assert!(shell.contains("cd /workspace"));
        assert!(shell.contains("HOME=\"/workspace/.aetherverify-home\""));
        assert!(shell.contains("XDG_CACHE_HOME=\"/workspace/.aetherverify-cache\""));
        assert!(shell.contains("timeout --signal=TERM 45s"));
        assert!(shell.contains("sh -c"));
        assert!(shell.contains("npm test"));
    }

    #[test]
    fn js_install_command_prefers_detected_package_manager() {
        let root = temp_dir("pnpm");
        fs::write(root.join("pnpm-lock.yaml"), "").expect("failed to write lock file");
        assert_eq!(js_install_command(&root), "corepack enable && pnpm install");
        fs::remove_dir_all(&root).expect("failed to clean temp directory");
    }

    #[test]
    fn fallback_project_plan_detects_rust_workspace() {
        let root = temp_dir("rust");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'",
        )
        .expect("failed to write cargo file");
        let snapshot = RepositorySnapshot {
            root_entries: vec![],
            tree_entries: vec![],
            manifest_files: vec![SourceSnippet {
                path: "Cargo.toml".to_string(),
                content: "[package]".to_string(),
            }],
            language_counts: vec![("Rust".to_string(), 4)],
        };

        let plan = fallback_project_plan(&root, &snapshot).expect("fallback should succeed");
        assert_eq!(plan.primary_language, "Rust");
        assert_eq!(plan.test_command.as_deref(), Some("cargo test"));

        fs::remove_dir_all(&root).expect("failed to clean temp directory");
    }

    #[test]
    fn probable_source_path_filters_expected_extensions() {
        assert!(is_probable_source_path("src/main.tsx"));
        assert!(is_probable_source_path("Cargo.toml"));
        assert!(!is_probable_source_path("README.md"));
    }

    #[test]
    fn cpu_torch_strategy_detects_sentence_transformers() {
        assert!(requires_cpu_torch_strategy(
            "fastapi\nsentence-transformers\nchromadb\n"
        ));
        assert!(!requires_cpu_torch_strategy("fastapi\nuvicorn[standard]\n"));
    }

    #[test]
    fn python_install_command_prefers_cpu_torch_when_needed() {
        let command = python_install_command(true);
        assert!(command.contains("download.pytorch.org/whl/cpu"));
        assert!(command.contains("'torch<3'"));

        let standard = python_install_command(false);
        assert!(!standard.contains("download.pytorch.org/whl/cpu"));
        assert!(standard.contains("-r requirements.txt"));
    }

    #[test]
    fn has_python_tests_detects_root_test_files() {
        let root = temp_dir("root-tests");
        fs::write(
            root.join("test_app.py"),
            "def test_ok():\n    assert True\n",
        )
        .expect("failed to write test file");
        assert!(has_python_tests(&root));
        fs::remove_dir_all(&root).expect("failed to clean temp directory");
    }

    #[test]
    fn normalize_python_test_command_prefers_module_execution() {
        assert_eq!(
            normalize_python_test_command(Some("pytest -q".to_string())).as_deref(),
            Some("python -m pytest -q")
        );
        assert_eq!(
            normalize_python_test_command(Some("py.test tests/test_demo.py".to_string()))
                .as_deref(),
            Some("python -m pytest tests/test_demo.py")
        );
        assert_eq!(
            normalize_python_test_command(Some("python -m pytest -q".to_string())).as_deref(),
            Some("python -m pytest -q")
        );
    }

    #[test]
    fn strip_json_fences_extracts_json_from_thinking_output() {
        let raw = "<think>checking repo</think>\n```json\n{\"projectType\":\"Python project\",\"testCommand\":\"pytest -q\"}\n```\nextra note";
        assert_eq!(
            strip_json_fences(raw),
            "{\"projectType\":\"Python project\",\"testCommand\":\"pytest -q\"}"
        );
    }

    #[test]
    fn extract_required_config_name_reads_uppercase_name() {
        let output = "ValueError: PAYMENT_API_KEY is required";
        assert_eq!(
            extract_required_config_name(output).as_deref(),
            Some("PAYMENT_API_KEY")
        );
    }
}
