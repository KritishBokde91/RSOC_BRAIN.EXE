use std::{
    path::{Path, PathBuf},
    process::Command,
};

use bollard::{
    container::LogOutput,
    models::{ContainerCreateBody, ContainerWaitResponse, HostConfig, Mount, MountTypeEnum},
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
        KillContainerOptionsBuilder, RemoveContainerOptionsBuilder, StartContainerOptions,
        WaitContainerOptionsBuilder,
    },
    Docker,
};
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::intelligence::{
    default_embedding_model, default_llm_base_url, default_llm_model, default_ollama_host,
    default_reranker_model, llm_api_key_configured,
};
use crate::workspace::{canonicalize_workspace, validate_repository_scope};
use crate::{default_workspace_root, AppState};

const SANDBOX_OUTPUT_EVENT: &str = "sandbox-output";
const SANDBOX_STATUS_EVENT: &str = "sandbox-status";
const DEFAULT_CONTAINER_IMAGE: &str = "node:22-bookworm";
const DEFAULT_SANDBOX_MEMORY_BYTES: i64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 512;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppContext {
    pub workspace_root: String,
    pub default_container_image: String,
    pub docker_available: bool,
    pub docker_message: String,
    pub neo4j_env_configured: bool,
    pub default_ollama_host: String,
    pub default_embedding_model: String,
    pub default_reranker_model: String,
    pub default_llm_base_url: String,
    pub default_llm_model: String,
    pub llm_api_key_configured: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRequest {
    pub workspace_root: String,
    pub image: String,
    pub command: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRunHandle {
    pub run_id: String,
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

pub async fn load_app_context() -> Result<AppContext, String> {
    let workspace_root = default_workspace_root()?;
    let neo4j_env_configured = std::env::var("NEO4J_URI").is_ok()
        && std::env::var("NEO4J_USERNAME").is_ok()
        && std::env::var("NEO4J_PASSWORD").is_ok();

    let container_image = std::env::var("AETHERVERIFY_CONTAINER_IMAGE")
        .unwrap_or_else(|_| DEFAULT_CONTAINER_IMAGE.to_string());

    let (docker_available, docker_message) = match connect_docker().await {
        Ok((_, message)) => (true, message),
        Err(message) => (false, message),
    };

    Ok(AppContext {
        workspace_root: workspace_root.display().to_string(),
        default_container_image: container_image,
        docker_available,
        docker_message,
        neo4j_env_configured,
        default_ollama_host: default_ollama_host(),
        default_embedding_model: default_embedding_model(),
        default_reranker_model: default_reranker_model(),
        default_llm_base_url: default_llm_base_url(),
        default_llm_model: default_llm_model(),
        llm_api_key_configured: llm_api_key_configured(),
    })
}

pub async fn run_sandbox_command(
    app: AppHandle,
    state: AppState,
    request: SandboxRequest,
) -> Result<SandboxRunHandle, String> {
    validate_request(&request)?;

    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    validate_repository_scope(&workspace_root)?;
    let image = request.image.trim().to_string();
    let command = request.command.trim().to_string();
    let run_id = uuid::Uuid::new_v4().to_string();
    let run_id_for_task = run_id.clone();
    let state_for_task = state.clone();
    let app_for_task = app.clone();

    tauri::async_runtime::spawn(async move {
        if let Err(error) = execute_sandbox_run(
            app_for_task,
            state_for_task,
            &run_id_for_task,
            workspace_root,
            image,
            command,
        )
        .await
        {
            let _ = emit_status(&app, &run_id_for_task, "failed", error, None);
        }
    });

    Ok(SandboxRunHandle { run_id })
}

pub async fn cancel_sandbox_run(state: AppState, run_id: String) -> Result<(), String> {
    let container_id = {
        let active_runs = state
            .active_runs
            .lock()
            .map_err(|_| "Failed to lock sandbox run registry".to_string())?;
        active_runs
            .get(&run_id)
            .cloned()
            .ok_or_else(|| "No active sandbox run found for that run id".to_string())?
    };

    let (docker, _) = connect_docker().await?;
    let kill_options = KillContainerOptionsBuilder::new().signal("SIGKILL").build();

    docker
        .kill_container(&container_id, Some(kill_options))
        .await
        .map_err(|error| format!("Failed to stop sandbox container: {error}"))?;

    let remove_options = RemoveContainerOptionsBuilder::new().force(true).build();

    docker
        .remove_container(&container_id, Some(remove_options))
        .await
        .map_err(|error| format!("Failed to remove sandbox container: {error}"))?;

    let mut active_runs = state
        .active_runs
        .lock()
        .map_err(|_| "Failed to lock sandbox run registry".to_string())?;
    active_runs.remove(&run_id);

    Ok(())
}

async fn execute_sandbox_run(
    app: AppHandle,
    state: AppState,
    run_id: &str,
    workspace_root: PathBuf,
    image: String,
    command: String,
) -> Result<(), String> {
    let (docker, _) = connect_docker().await?;

    emit_status(
        &app,
        run_id,
        "preparing-image",
        format!("Ensuring Docker image `{image}` is available."),
        None,
    )?;
    ensure_image_available(&docker, &app, run_id, &image).await?;

    let container_name = format!("aetherverify-{}", &run_id[..8]);
    let workspace_mount = Mount {
        target: Some("/workspace-ro".to_string()),
        source: Some(workspace_root.display().to_string()),
        typ: Some(MountTypeEnum::BIND),
        read_only: Some(true),
        ..Default::default()
    };
    let host_config = HostConfig {
        mounts: Some(vec![workspace_mount]),
        auto_remove: Some(false),
        cap_drop: Some(vec!["ALL".to_string()]),
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        memory: Some(DEFAULT_SANDBOX_MEMORY_BYTES),
        pids_limit: Some(DEFAULT_SANDBOX_PIDS_LIMIT),
        ..Default::default()
    };

    let container_config = ContainerCreateBody {
        image: Some(image.clone()),
        working_dir: Some("/workspace".to_string()),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        env: Some(vec!["TERM=xterm-256color".to_string()]),
        cmd: Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            build_sandbox_shell_command(&command),
        ]),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create_options = CreateContainerOptionsBuilder::new()
        .name(&container_name)
        .build();

    let created_container = docker
        .create_container(Some(create_options), container_config)
        .await
        .map_err(|error| format!("Failed to create sandbox container: {error}"))?;

    {
        let mut active_runs = state
            .active_runs
            .lock()
            .map_err(|_| "Failed to lock sandbox run registry".to_string())?;
        active_runs.insert(run_id.to_string(), created_container.id.clone());
    }

    emit_status(
        &app,
        run_id,
        "starting",
        "Starting sandbox container.".to_string(),
        None,
    )?;

    docker
        .start_container(&created_container.id, None::<StartContainerOptions>)
        .await
        .map_err(|error| format!("Failed to start sandbox container: {error}"))?;

    emit_status(
        &app,
        run_id,
        "running",
        "Command is executing inside the Docker sandbox.".to_string(),
        None,
    )?;

    let attach_options = AttachContainerOptionsBuilder::new()
        .stream(true)
        .stdout(true)
        .stderr(true)
        .logs(true)
        .build();
    let mut attached = docker
        .attach_container(&created_container.id, Some(attach_options))
        .await
        .map_err(|error| format!("Failed to attach to sandbox logs: {error}"))?;

    while let Some(chunk) = attached.output.next().await {
        let payload = match chunk {
            Ok(LogOutput::StdOut { message }) => SandboxOutputPayload {
                run_id: run_id.to_string(),
                stream: "stdout".to_string(),
                chunk: String::from_utf8_lossy(&message).into_owned(),
            },
            Ok(LogOutput::StdErr { message }) => SandboxOutputPayload {
                run_id: run_id.to_string(),
                stream: "stderr".to_string(),
                chunk: String::from_utf8_lossy(&message).into_owned(),
            },
            Ok(_) => continue,
            Err(error) => {
                let _ = emit_status(
                    &app,
                    run_id,
                    "failed",
                    format!("Failed while streaming sandbox output: {error}"),
                    None,
                );
                break;
            }
        };
        let _ = app.emit(SANDBOX_OUTPUT_EVENT, payload);
    }

    let wait_options = WaitContainerOptionsBuilder::new()
        .condition("not-running")
        .build();
    let mut wait_stream = docker.wait_container(&created_container.id, Some(wait_options));
    let exit_status = match wait_stream.next().await {
        Some(Ok(ContainerWaitResponse { status_code, .. })) => status_code,
        Some(Err(error)) => {
            return Err(format!(
                "Failed while waiting for sandbox completion: {error}"
            ))
        }
        None => 1,
    };

    let remove_options = RemoveContainerOptionsBuilder::new().force(true).build();

    docker
        .remove_container(&created_container.id, Some(remove_options))
        .await
        .map_err(|error| format!("Failed to remove sandbox container: {error}"))?;

    {
        let mut active_runs = state
            .active_runs
            .lock()
            .map_err(|_| "Failed to lock sandbox run registry".to_string())?;
        active_runs.remove(run_id);
    }

    let stage = if exit_status == 0 {
        "completed"
    } else {
        "failed"
    };
    let message = if exit_status == 0 {
        "Sandbox command finished successfully."
    } else {
        "Sandbox command exited with a non-zero status."
    };
    emit_status(&app, run_id, stage, message.to_string(), Some(exit_status))
        .map_err(|error| error.to_string())?;

    Ok(())
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

    let options = CreateImageOptionsBuilder::new().from_image(image).build();
    let mut pull_stream = docker.create_image(Some(options), None, None);
    while let Some(progress) = pull_stream.next().await {
        match progress {
            Ok(details) => {
                if let Some(status) = details.status {
                    let message = if let Some(progress) = details.progress_detail {
                        match (progress.current, progress.total) {
                            (Some(current), Some(total)) => format!("{status} {current}/{total}"),
                            (Some(current), None) => format!("{status} {current}"),
                            _ => status,
                        }
                    } else {
                        status
                    };
                    let _ = emit_status(app, run_id, "pulling-image", message, None);
                }
            }
            Err(error) => return Err(format!("Failed to pull Docker image `{image}`: {error}")),
        }
    }
    Ok(())
}

fn build_sandbox_shell_command(command: &str) -> String {
    let escaped_command = command.replace('\'', r"'\''");
    format!(
        "set -eu; rm -rf /workspace; mkdir -p /workspace; cp -a /workspace-ro/. /workspace/ 2>/dev/null || true; cd /workspace; sh -lc '{}'",
        escaped_command
    )
}

fn emit_status(
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

fn validate_request(request: &SandboxRequest) -> Result<(), String> {
    if request.command.trim().is_empty() {
        return Err("Sandbox command cannot be empty".to_string());
    }
    if request.image.trim().is_empty() {
        return Err("Sandbox image cannot be empty".to_string());
    }
    if request.workspace_root.trim().is_empty() {
        return Err("Workspace root cannot be empty".to_string());
    }
    Ok(())
}

async fn connect_docker() -> Result<(Docker, String), String> {
    let docker = Docker::connect_with_local_defaults()
        .map_err(|error| enrich_docker_error(format!("Failed to create Docker client: {error}")))?;
    let version = docker
        .version()
        .await
        .map_err(|error| enrich_docker_error(error.to_string()))?;

    let message = format!(
        "Connected to Docker {}",
        version.version.unwrap_or_else(|| "unknown".to_string())
    );
    Ok((docker, message))
}

fn enrich_docker_error(raw_error: String) -> String {
    if let Some(socket_path) = existing_docker_socket() {
        let socket_display = socket_path.display().to_string();
        if let Some(group_names) = current_group_names() {
            if !group_names.iter().any(|group| group == "docker") {
                return format!(
                    "Docker socket exists at {socket_display}, but this user cannot access it. Add the current user to the `docker` group with `sudo usermod -aG docker $USER`, then log out and back in. Original error: {raw_error}"
                );
            }
        }

        return format!(
            "Docker socket exists at {socket_display}, but the app could not connect. Ensure the Docker daemon is running and this user can access the socket. Original error: {raw_error}"
        );
    }

    format!(
        "Docker socket was not found. Start Docker or configure a reachable Docker host. Original error: {raw_error}"
    )
}

fn existing_docker_socket() -> Option<&'static Path> {
    [
        Path::new("/var/run/docker.sock"),
        Path::new("/run/docker.sock"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn current_group_names() -> Option<Vec<String>> {
    let output = Command::new("id").arg("-Gn").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let groups = String::from_utf8(output.stdout).ok()?;
    let parsed = groups
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::build_sandbox_shell_command;

    #[test]
    fn sandbox_shell_command_copies_workspace_and_escapes_quotes() {
        let command = "printf 'hi'";
        let shell = build_sandbox_shell_command(command);

        assert!(shell.contains("cp -a /workspace-ro/. /workspace/"));
        assert!(shell.contains("cd /workspace; sh -lc"));
        assert!(shell.contains("printf '\\''hi'\\''"));
    }
}
