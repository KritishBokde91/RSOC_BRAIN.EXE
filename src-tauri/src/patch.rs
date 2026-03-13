use std::{
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyPatchRequest {
    pub workspace_root: String,
    pub patch_content: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyPatchResponse {
    pub success: bool,
    pub message: String,
}

pub fn apply_unified_diff(
    workspace_root: &Path,
    patch_content: &str,
) -> Result<String, String> {
    // A very primitive unified diff parser and applier.
    // In a production application, you would use a robust patching library.
    // This implementation simply looks for file boundaries and replaces the whole file if a match is found based on a "--- a/file" / "+++ b/file" header.
    // For the AetherVerify Phase 3 demo, we'll try to extract full replacement blocks if the LLM generated them, or attempt a naive line-by-line replacement if it's a true patch.
    // Since building a full diff applier from scratch is complex, we will implement a simplified approach:
    // We expect the LLM to provide the FULL file content or we use the `patch` system command as a backend if available.
    
    // For cross-platform reliability in this prototype, let's invoke the system's `patch` utility.
    // This requires `patch` to be installed on the host system.
    
    let mut temp_patch_file = std::env::temp_dir();
    temp_patch_file.push(format!("aetherverify_patch_{}.diff", std::process::id()));
    
    fs::write(&temp_patch_file, patch_content)
        .map_err(|e| format!("Failed to write temporary patch file: {}", e))?;
        
    let output = std::process::Command::new("patch")
        .arg("-p1") // Strip first directory level (a/ and b/)
        .arg("--forward")
        .arg("--batch")
        .arg("-i")
        .arg(&temp_patch_file)
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("Failed to execute 'patch' command. Is it installed? Error: {}", e))?;
        
    let _ = fs::remove_file(temp_patch_file);
    
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    
    if output.status.success() {
        Ok(format!("Patch applied successfully.\n{}", stdout))
    } else {
        Err(format!("Failed to apply patch.\nStdout: {}\nStderr: {}", stdout, stderr))
    }
}
