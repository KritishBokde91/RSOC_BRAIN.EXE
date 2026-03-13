mod docker;
mod ingestion;
mod intelligence;
mod patch;
mod workspace;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use docker::{
    cancel_sandbox_run, run_sandbox_command, AppContext, SandboxRequest, SandboxRunHandle,
};
use ingestion::{ingest_repository, IngestionRequest, IngestionSummary};
use intelligence::{
    analyze_issue, build_context_index, ContextIndexRequest, ContextIndexSummary,
    IssueAnalysisRequest, IssueAnalysisResponse,
};
use patch::{apply_unified_diff, ApplyPatchRequest, ApplyPatchResponse};
use tauri::State;

#[derive(Clone, Default)]
struct AppState {
    active_runs: Arc<Mutex<HashMap<String, String>>>,
}

#[tauri::command]
async fn load_app_context() -> Result<AppContext, String> {
    docker::load_app_context().await
}

#[tauri::command]
async fn start_sandbox_command(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    request: SandboxRequest,
) -> Result<SandboxRunHandle, String> {
    run_sandbox_command(app, state.inner().clone(), request).await
}

#[tauri::command]
async fn stop_sandbox_command(state: State<'_, AppState>, run_id: String) -> Result<(), String> {
    cancel_sandbox_run(state.inner().clone(), run_id).await
}

#[tauri::command]
async fn ingest_workspace_graph(request: IngestionRequest) -> Result<IngestionSummary, String> {
    ingest_repository(request).await
}

#[tauri::command]
async fn build_workspace_context_index(
    request: ContextIndexRequest,
) -> Result<ContextIndexSummary, String> {
    build_context_index(request).await
}

#[tauri::command]
async fn analyze_workspace_issue(
    request: IssueAnalysisRequest,
) -> Result<IssueAnalysisResponse, String> {
    analyze_issue(request).await
}

#[tauri::command]
async fn apply_patch_to_workspace(
    request: ApplyPatchRequest,
) -> Result<ApplyPatchResponse, String> {
    let workspace_path = std::path::PathBuf::from(&request.workspace_root);
    match apply_unified_diff(&workspace_path, &request.patch_content) {
        Ok(msg) => Ok(ApplyPatchResponse {
            success: true,
            message: msg,
        }),
        Err(e) => Ok(ApplyPatchResponse {
            success: false,
            message: e,
        }),
    }
}

fn default_workspace_root() -> Result<PathBuf, String> {
    let current_dir = std::env::current_dir().map_err(|error| error.to_string())?;
    if current_dir
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == "src-tauri")
    {
        current_dir
            .parent()
            .map(|path| path.to_path_buf())
            .ok_or_else(|| "Unable to resolve workspace root from src-tauri directory".to_string())
    } else {
        Ok(current_dir)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            load_app_context,
            start_sandbox_command,
            stop_sandbox_command,
            ingest_workspace_graph,
            build_workspace_context_index,
            analyze_workspace_issue,
            apply_patch_to_workspace
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
