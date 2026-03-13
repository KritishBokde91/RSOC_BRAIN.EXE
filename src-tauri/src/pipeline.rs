use std::fs;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::intelligence::{default_llm_base_url, default_llm_model};
use crate::security_scanner::{run_security_scan_streaming, SecurityVulnerability};
use crate::workspace::canonicalize_workspace;

// ── Event names ──────────────────────────────────────────────────

pub const SCAN_STAGE_EVENT: &str = "scan-stage";

// ── Event payloads ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStagePayload {
    pub stage: String,
    pub message: String,
    pub duration_ms: u64,
}

// ── Public types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullScanRequest {
    pub workspace_root: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullScanResult {
    pub workspace_root: String,
    pub scanned_files: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerabilities: Vec<SecurityVulnerability>,
    pub pipeline_log: Vec<PipelineStep>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineStep {
    pub stage: String,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixRequest {
    pub workspace_root: String,
    #[allow(dead_code)]
    pub vulnerability_id: String,
    pub fixed_code: String,
    pub file: String,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixResult {
    pub success: bool,
    pub message: String,
}

// ── LLM response parsing ─────────────────────────────────────────

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

// ── Full scan pipeline (with streaming) ──────────────────────────

pub async fn run_full_scan(
    app: AppHandle,
    request: FullScanRequest,
) -> Result<FullScanResult, String> {
    let mut pipeline_log = Vec::new();
    let mut warnings = Vec::new();

    // ── Stage 1: Emit scanning stage ─────────────────────────────
    let _ = app.emit(
        SCAN_STAGE_EVENT,
        ScanStagePayload {
            stage: "scanning".to_string(),
            message: "Scanning files for security vulnerabilities…".to_string(),
            duration_ms: 0,
        },
    );

    let scan_start = std::time::Instant::now();

    // Use streaming scanner that emits per-file progress and per-vuln events
    let scan_result = run_security_scan_streaming(&app, &request.workspace_root)?;

    let scan_duration = scan_start.elapsed().as_millis() as u64;
    let scan_msg = format!(
        "Scanned {} files, found {} vulnerabilities",
        scan_result.scanned_files, scan_result.total_vulnerabilities
    );

    pipeline_log.push(PipelineStep {
        stage: "security-scan".to_string(),
        message: scan_msg.clone(),
        duration_ms: scan_duration,
    });

    let _ = app.emit(
        SCAN_STAGE_EVENT,
        ScanStagePayload {
            stage: "scan-complete".to_string(),
            message: scan_msg,
            duration_ms: scan_duration,
        },
    );

    if scan_result.total_vulnerabilities == 0 {
        let _ = app.emit(
            SCAN_STAGE_EVENT,
            ScanStagePayload {
                stage: "complete".to_string(),
                message: "No vulnerabilities found — project looks clean!".to_string(),
                duration_ms: scan_duration,
            },
        );
        return Ok(FullScanResult {
            workspace_root: scan_result.workspace_root,
            scanned_files: scan_result.scanned_files,
            total_vulnerabilities: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            vulnerabilities: Vec::new(),
            pipeline_log,
            warnings: scan_result.warnings,
        });
    }

    // ── Stage 2: LLM enrichment ─────────────────────────────────
    let _ = app.emit(
        SCAN_STAGE_EVENT,
        ScanStagePayload {
            stage: "analyzing".to_string(),
            message: format!(
                "Running AI analysis on {} vulnerabilities…",
                scan_result.total_vulnerabilities
            ),
            duration_ms: 0,
        },
    );

    let llm_start = std::time::Instant::now();
    let mut enriched_vulns = scan_result.vulnerabilities;

    match enrich_with_llm(&request.workspace_root, &mut enriched_vulns).await {
        Ok(()) => {
            let llm_duration = llm_start.elapsed().as_millis() as u64;
            let llm_msg = format!(
                "LLM enriched {} vulnerabilities with fixes and explanations",
                enriched_vulns.len()
            );
            pipeline_log.push(PipelineStep {
                stage: "llm-analysis".to_string(),
                message: llm_msg.clone(),
                duration_ms: llm_duration,
            });
            let _ = app.emit(
                SCAN_STAGE_EVENT,
                ScanStagePayload {
                    stage: "llm-complete".to_string(),
                    message: llm_msg,
                    duration_ms: llm_duration,
                },
            );
        }
        Err(e) => {
            let llm_duration = llm_start.elapsed().as_millis() as u64;
            warnings.push(format!("LLM enrichment skipped: {e}"));
            pipeline_log.push(PipelineStep {
                stage: "llm-analysis".to_string(),
                message: format!("Skipped — {e}"),
                duration_ms: llm_duration,
            });
            let _ = app.emit(
                SCAN_STAGE_EVENT,
                ScanStagePayload {
                    stage: "llm-skipped".to_string(),
                    message: format!("LLM skipped: {e}"),
                    duration_ms: llm_duration,
                },
            );
        }
    }

    // Merge warnings
    warnings.extend(scan_result.warnings);

    let critical_count = enriched_vulns
        .iter()
        .filter(|v| v.severity == "Critical")
        .count();
    let high_count = enriched_vulns
        .iter()
        .filter(|v| v.severity == "High")
        .count();
    let medium_count = enriched_vulns
        .iter()
        .filter(|v| v.severity == "Medium")
        .count();
    let low_count = enriched_vulns
        .iter()
        .filter(|v| v.severity == "Low")
        .count();

    // ── Stage 3: Complete ────────────────────────────────────────
    let total_duration = scan_start.elapsed().as_millis() as u64;
    let _ = app.emit(
        SCAN_STAGE_EVENT,
        ScanStagePayload {
            stage: "complete".to_string(),
            message: format!(
                "Analysis complete: {} vulnerabilities ({} critical, {} high)",
                enriched_vulns.len(),
                critical_count,
                high_count
            ),
            duration_ms: total_duration,
        },
    );

    Ok(FullScanResult {
        workspace_root: scan_result.workspace_root,
        scanned_files: scan_result.scanned_files,
        total_vulnerabilities: enriched_vulns.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        vulnerabilities: enriched_vulns,
        pipeline_log,
        warnings,
    })
}

// ── Apply single fix ─────────────────────────────────────────────

pub async fn apply_fix(request: FixRequest) -> Result<FixResult, String> {
    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    let file_path = workspace_root.join(&request.file);

    if !file_path.exists() {
        return Ok(FixResult {
            success: false,
            message: format!("File not found: {}", request.file),
        });
    }

    let source = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read {}: {e}", request.file))?;

    let lines: Vec<&str> = source.lines().collect();

    // Replace the vulnerable lines with the fixed code
    let start_idx = request.line.saturating_sub(1);
    let end_idx = request.end_line.min(lines.len());

    let mut new_lines: Vec<String> = Vec::new();
    // Lines before the fix
    for line in &lines[..start_idx] {
        new_lines.push(line.to_string());
    }
    // Insert fixed code
    for fix_line in request.fixed_code.lines() {
        new_lines.push(fix_line.to_string());
    }
    // Lines after the fix
    if end_idx < lines.len() {
        for line in &lines[end_idx..] {
            new_lines.push(line.to_string());
        }
    }

    let new_content = new_lines.join("\n");
    // Preserve trailing newline if original had one
    let new_content = if source.ends_with('\n') && !new_content.ends_with('\n') {
        format!("{new_content}\n")
    } else {
        new_content
    };

    fs::write(&file_path, &new_content)
        .map_err(|e| format!("Failed to write {}: {e}", request.file))?;

    Ok(FixResult {
        success: true,
        message: format!(
            "Fixed {} (lines {}-{})",
            request.file, request.line, request.end_line
        ),
    })
}

// ── LLM enrichment via Groq ──────────────────────────────────────

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

async fn enrich_with_llm(
    workspace_root: &str,
    vulns: &mut Vec<SecurityVulnerability>,
) -> Result<(), String> {
    let api_key = resolve_llm_api_key()
        .ok_or_else(|| "No LLM API key configured (set GROQ_API_KEY in .env)".to_string())?;
    let base_url = default_llm_base_url();
    let model = default_llm_model();
    if model.is_empty() {
        return Err("No LLM model configured (set GROQ_MODEL in .env)".to_string());
    }

    let client = Client::new();

    // Process vulnerabilities in batches for efficiency
    let batch_size = 8;
    for batch_start in (0..vulns.len()).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(vulns.len());
        let batch: Vec<&SecurityVulnerability> = vulns[batch_start..batch_end].iter().collect();

        let prompt = build_security_prompt(workspace_root, &batch);

        let request_body = serde_json::json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are AetherVerify, an expert security code analyst with deep knowledge of OWASP Top 10, CWE, and real-world exploit patterns.\n\nFor each vulnerability candidate, you MUST:\n1. Determine if it is a TRUE POSITIVE (real, exploitable vulnerability) or FALSE POSITIVE (safe code incorrectly flagged). Set is_false_positive accordingly.\n2. If true positive: provide a confidence score (0.4-1.0), write the ACTUAL corrected code as a drop-in replacement (not comments or descriptions), and explain the attack vector.\n3. If false positive: set is_false_positive to true, confidence to 0.0, and explain why it is safe.\n\nCommon false positives to watch for:\n- ChromaDB/vector DB operations flagged as SQL injection (ChromaDB uses no SQL)\n- ORM method calls like .objects.get(), .query.filter() flagged as SQL injection\n- Method calls like store.delete_conversation() flagged as raw SQL\n- pickle.load() on internal metadata files (lower severity, not user-input driven)\n- hashlib.md5/sha1 used for checksums (not password hashing)\n\nRespond as a JSON array: [{\"id\": \"VULN-XXXX\", \"is_false_positive\": false, \"confidence\": 0.85, \"fixed_code\": \"actual_replacement_code_here\", \"explanation\": \"...\"}]\nOnly output valid JSON, no markdown fences."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.15,
            "max_tokens": 4096
        });

        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("LLM request failed: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("LLM returned {status}: {body}"));
        }

        let completion: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse LLM response: {e}"))?;

        if let Some(content) = completion
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
        {
            // Strip markdown code fences if present
            let json_content = content
                .trim()
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim();

            // Try to parse the LLM output
            if let Ok(enrichments) = serde_json::from_str::<Vec<LlmEnrichment>>(json_content) {
                for enrichment in enrichments {
                    if let Some(vuln) = vulns.iter_mut().find(|v| v.id == enrichment.id) {
                        // If LLM says false positive, mark for removal
                        if enrichment.is_false_positive.unwrap_or(false)
                            || enrichment.confidence < 0.1
                        {
                            vuln.confidence = 0.0; // Will be filtered out below
                            vuln.ai_explanation =
                                Some(format!("FALSE POSITIVE: {}", enrichment.explanation));
                        } else {
                            if enrichment.confidence > 0.0 {
                                vuln.confidence = enrichment.confidence;
                            }
                            if !enrichment.fixed_code.is_empty()
                                && !enrichment.fixed_code.starts_with("#")
                                && !enrichment.fixed_code.starts_with("//")
                            {
                                vuln.fixed_code = enrichment.fixed_code;
                            }
                            if !enrichment.explanation.is_empty() {
                                vuln.ai_explanation = Some(enrichment.explanation);
                            }
                        }
                        vuln.detection_layer = format!("{} + L4-LLM", vuln.detection_layer);
                    }
                }
            }
        }
    }

    // ── Filter out false positives identified by LLM ──
    vulns.retain(|v| v.confidence >= 0.25);

    Ok(())
}

#[derive(Debug, Deserialize)]
struct LlmEnrichment {
    id: String,
    #[serde(default)]
    is_false_positive: Option<bool>,
    confidence: f32,
    fixed_code: String,
    explanation: String,
}

fn build_security_prompt(workspace_root: &str, vulns: &[&SecurityVulnerability]) -> String {
    let mut prompt = format!(
        "Analyze these security vulnerability CANDIDATES found in the project at `{}`.\n\nCRITICAL: Many of these may be FALSE POSITIVES from regex-based pattern matching. You MUST carefully analyze each one and determine if it is a real vulnerability or a false alarm. For true positives, provide the actual fixed code as a drop-in replacement.\n\n",
        workspace_root
    );

    for vuln in vulns {
        prompt.push_str(&format!(
            "--- Candidate {} ---\nType: {} ({})\nFile: {}:{}\nSeverity: {}\nDescription: {}\nCode Context (surrounding lines):\n```\n{}\n```\nInitial fix suggestion:\n```\n{}\n```\n\n",
            vuln.id,
            vuln.vuln_type,
            vuln.owasp_category,
            vuln.file,
            vuln.line,
            vuln.severity,
            vuln.description,
            vuln.original_code,
            vuln.fixed_code,
        ));
    }

    prompt.push_str("Respond with a JSON array: [{\"id\": \"VULN-XXXX\", \"is_false_positive\": true/false, \"confidence\": 0.85, \"fixed_code\": \"actual_code\", \"explanation\": \"why\"}]\nOnly valid JSON.");
    prompt
}
