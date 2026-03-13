use std::{fs, path::Path};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use walkdir::{DirEntry, WalkDir};

use crate::workspace::{canonicalize_workspace, validate_repository_scope};

pub const SCAN_PROGRESS_EVENT: &str = "scan-progress";
pub const SCAN_VULN_FOUND_EVENT: &str = "scan-vuln-found";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressPayload {
    pub current_file: String,
    pub scanned_so_far: usize,
    pub vulns_found_so_far: usize,
}

const MAX_SCAN_FILES: usize = 2_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_VULNS: usize = 500;

// ── Public types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityVulnerability {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub end_line: usize,
    pub severity: String,
    pub owasp_category: String,
    pub vuln_type: String,
    pub title: String,
    pub description: String,
    pub original_code: String,
    pub fixed_code: String,
    pub confidence: f32,
    pub ai_explanation: Option<String>,
    pub detection_layer: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityScanResult {
    pub workspace_root: String,
    pub scanned_files: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerabilities: Vec<SecurityVulnerability>,
    pub warnings: Vec<String>,
}

// ── Scan entry point (streaming) ─────────────────────────────────

pub fn run_security_scan_streaming(
    app: &AppHandle,
    workspace_root_str: &str,
) -> Result<SecurityScanResult, String> {
    let workspace_root = canonicalize_workspace(workspace_root_str)?;
    validate_repository_scope(&workspace_root)?;

    let mut vulns: Vec<SecurityVulnerability> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;
    let mut vuln_counter = 0u64;

    for entry in WalkDir::new(&workspace_root)
        .max_open(32)
        .into_iter()
        .filter_entry(should_visit_entry)
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(lang) = language_from_path(entry.path()) else {
            continue;
        };
        if scanned_files >= MAX_SCAN_FILES {
            warnings.push("Stopped after scanning 2000 files.".to_string());
            break;
        }
        let file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > MAX_FILE_BYTES || file_size == 0 {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&workspace_root)
            .unwrap_or(entry.path())
            .display()
            .to_string();
        let source = match fs::read_to_string(entry.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if source.contains('\0') {
            continue;
        }
        scanned_files += 1;

        // Emit per-file progress event
        let _ = app.emit(
            SCAN_PROGRESS_EVENT,
            ScanProgressPayload {
                current_file: relative.clone(),
                scanned_so_far: scanned_files,
                vulns_found_so_far: vulns.len(),
            },
        );

        let mut file_vulns =
            run_all_security_detectors(&relative, lang, &source, &mut vuln_counter);
        let remaining = MAX_VULNS.saturating_sub(vulns.len());
        file_vulns.truncate(remaining);

        // Emit each new vulnerability as it's found
        for v in &file_vulns {
            let _ = app.emit(SCAN_VULN_FOUND_EVENT, v.clone());
        }

        vulns.extend(file_vulns);

        if vulns.len() >= MAX_VULNS {
            warnings.push(format!(
                "Stopped after collecting {} vulnerability reports.",
                MAX_VULNS
            ));
            break;
        }
    }

    vulns.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));

    let critical_count = vulns.iter().filter(|v| v.severity == "Critical").count();
    let high_count = vulns.iter().filter(|v| v.severity == "High").count();
    let medium_count = vulns.iter().filter(|v| v.severity == "Medium").count();
    let low_count = vulns.iter().filter(|v| v.severity == "Low").count();

    Ok(SecurityScanResult {
        workspace_root: workspace_root.display().to_string(),
        scanned_files,
        total_vulnerabilities: vulns.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        vulnerabilities: vulns,
        warnings,
    })
}

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

// ── Detector orchestrator ─────────────────────────────────────────

fn run_all_security_detectors(
    file: &str,
    lang: &str,
    source: &str,
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // ── Context-aware analysis: determine what this file actually does ──
    let caps = analyze_file_capabilities(lang, source);

    // Injection attacks — only if relevant imports exist
    if caps.has_sql {
        vulns.extend(detect_sql_injection(file, lang, &lines, counter));
    }
    if caps.has_web_framework {
        vulns.extend(detect_xss(file, lang, &lines, counter));
        vulns.extend(detect_header_injection(file, lang, &lines, counter));
        vulns.extend(detect_csrf_missing(file, lang, &lines, counter));
        vulns.extend(detect_open_redirect(file, lang, &lines, counter));
    }
    // Command injection — always check for eval/exec, but os.system only with imports
    vulns.extend(detect_command_injection(file, lang, &lines, counter, &caps));

    // Broken access — only with web frameworks
    if caps.has_web_framework {
        vulns.extend(detect_auth_weaknesses(file, lang, &lines, counter));
    }

    // Data exposure — always check but with context
    vulns.extend(detect_hardcoded_secrets(file, lang, &lines, counter));
    vulns.extend(detect_info_leakage(file, lang, &lines, counter));
    if caps.has_crypto {
        vulns.extend(detect_weak_crypto(file, lang, &lines, counter));
    }

    // Insecure design — gate behind relevant imports
    if caps.has_file_io || caps.has_web_framework {
        vulns.extend(detect_path_traversal(file, lang, &lines, counter));
    }
    if caps.has_http_client {
        vulns.extend(detect_ssrf(file, lang, &lines, counter));
    }
    if caps.has_deserialization {
        vulns.extend(detect_insecure_deserialization(file, lang, &lines, counter));
    }
    if caps.has_file_io {
        vulns.extend(detect_unsafe_file_ops(file, lang, &lines, counter));
    }
    vulns.extend(detect_error_handling(file, lang, &lines, counter));
    vulns.extend(detect_insecure_randomness(file, lang, &lines, counter));

    vulns
}

fn next_id(counter: &mut u64) -> String {
    *counter += 1;
    format!("VULN-{:04}", counter)
}

fn get_line_context(lines: &[&str], line_idx: usize, window: usize) -> (String, usize, usize) {
    let start = line_idx.saturating_sub(window);
    let end = (line_idx + window + 1).min(lines.len());
    let snippet = lines[start..end].join("\n");
    (snippet, start + 1, end)
}

// ════════════════════════════════════════════════════════════════════
// CONTEXT-AWARE IMPORT ANALYSIS
// ════════════════════════════════════════════════════════════════════

/// Capabilities detected from file imports — determines which detectors apply.
#[derive(Debug, Default)]
struct FileCapabilities {
    has_sql: bool,
    has_web_framework: bool,
    has_deserialization: bool,
    has_crypto: bool,
    has_http_client: bool,
    has_shell_exec: bool,
    has_file_io: bool,
}

/// Analyze imports/use statements to determine what this file actually does.
fn analyze_file_capabilities(lang: &str, source: &str) -> FileCapabilities {
    let mut caps = FileCapabilities::default();
    let lower = source.to_lowercase();

    match lang {
        "python" => {
            // SQL-related imports
            caps.has_sql = lower.contains("import sqlite3")
                || lower.contains("import psycopg")
                || lower.contains("import mysql")
                || lower.contains("import pymysql")
                || lower.contains("from sqlalchemy")
                || lower.contains("import sqlalchemy")
                || lower.contains("from django.db")
                || lower.contains("import peewee")
                || lower.contains(".execute(")
                    && (lower.contains("cursor") || lower.contains("connection"))
                || lower.contains("raw(")
                    && (lower.contains("select ")
                        || lower.contains("insert ")
                        || lower.contains("update ")
                        || lower.contains("delete "));

            // Web framework imports
            caps.has_web_framework = lower.contains("from flask")
                || lower.contains("import flask")
                || lower.contains("from django")
                || lower.contains("import django")
                || lower.contains("from fastapi")
                || lower.contains("import fastapi")
                || lower.contains("from starlette")
                || lower.contains("from sanic")
                || lower.contains("from tornado")
                || lower.contains("from bottle");

            // Deserialization
            caps.has_deserialization = lower.contains("import pickle")
                || lower.contains("import yaml")
                || lower.contains("import marshal")
                || lower.contains("import shelve")
                || lower.contains("from pickle")
                || lower.contains("from yaml");

            // Crypto
            caps.has_crypto = lower.contains("import hashlib")
                || lower.contains("from cryptography")
                || lower.contains("import hmac")
                || lower.contains("import random");

            // HTTP client
            caps.has_http_client = lower.contains("import requests")
                || lower.contains("import urllib")
                || lower.contains("import httpx")
                || lower.contains("import aiohttp");

            // Shell execution
            caps.has_shell_exec = lower.contains("import subprocess")
                || lower.contains("import os")
                || lower.contains("from os")
                || lower.contains("import shlex");

            // File I/O
            caps.has_file_io = lower.contains("import os")
                || lower.contains("from os")
                || lower.contains("import pathlib")
                || lower.contains("import tempfile")
                || lower.contains("import shutil");
        }
        "javascript" | "typescript" => {
            caps.has_sql = lower.contains("require('mysql")
                || lower.contains("require('pg")
                || lower.contains("require('sqlite")
                || lower.contains("require('better-sqlite")
                || lower.contains("from 'mysql")
                || lower.contains("from 'pg")
                || lower.contains("from 'sqlite")
                || lower.contains("from 'sequelize")
                || lower.contains("from 'knex")
                || lower.contains("from 'typeorm")
                || lower.contains("from 'prisma");

            caps.has_web_framework = lower.contains("require('express")
                || lower.contains("from 'express")
                || lower.contains("require('koa")
                || lower.contains("from 'koa")
                || lower.contains("require('fastify")
                || lower.contains("from 'fastify")
                || lower.contains("from 'next");

            caps.has_deserialization = lower.contains("serialize") || lower.contains("unserialize");

            caps.has_http_client = lower.contains("require('axios")
                || lower.contains("from 'axios")
                || lower.contains("require('got")
                || lower.contains("require('node-fetch")
                || lower.contains("from 'node-fetch");

            caps.has_shell_exec =
                lower.contains("child_process") || lower.contains("require('shelljs");

            caps.has_crypto = lower.contains("require('crypto")
                || lower.contains("from 'crypto")
                || lower.contains("math.random");

            caps.has_file_io = lower.contains("require('fs")
                || lower.contains("from 'fs")
                || lower.contains("require('path")
                || lower.contains("from 'path");
        }
        "rust" => {
            caps.has_sql =
                lower.contains("sqlx") || lower.contains("diesel") || lower.contains("rusqlite");
            caps.has_shell_exec =
                lower.contains("std::process::command") || lower.contains("command::new");
            caps.has_crypto = lower.contains("md5") || lower.contains("sha1");
            caps.has_http_client = lower.contains("reqwest") || lower.contains("hyper");
            caps.has_web_framework = lower.contains("actix")
                || lower.contains("rocket")
                || lower.contains("axum")
                || lower.contains("warp");
            caps.has_deserialization = lower.contains("serde") || lower.contains("bincode");
            caps.has_file_io = lower.contains("std::fs");
        }
        _ => {
            // For unknown languages, assume everything is possible
            caps.has_sql = true;
            caps.has_web_framework = true;
            caps.has_deserialization = true;
            caps.has_crypto = true;
            caps.has_http_client = true;
            caps.has_shell_exec = true;
            caps.has_file_io = true;
        }
    }

    caps
}

/// Check if a line is part of a known safe API (false positive suppression).
fn is_safe_api_call(line: &str, lang: &str) -> bool {
    let lower = line.to_lowercase();
    match lang {
        "python" => {
            // ChromaDB, vector DB, ORM safe operations
            lower.contains(".collection.get(")
                || lower.contains(".collection.query(")
                || lower.contains(".collection.add(")
                || lower.contains(".collection.update(")
                || lower.contains(".collection.delete(")
                || lower.contains(".collection.peek(")
                || lower.contains(".collection.count(")
                // Store/pipeline method calls (not raw SQL)
                || (lower.contains(".store.") && !lower.contains("execute"))
                || (lower.contains(".delete_conversation(") && !lower.contains("execute"))
                || (lower.contains(".get_conversation(") && !lower.contains("execute"))
                // ORM safe query methods
                || lower.contains(".objects.filter(")
                || lower.contains(".objects.get(")
                || lower.contains(".objects.create(")
                || lower.contains(".objects.all(")
                || lower.contains(".query.filter(")
                || lower.contains(".query.get(")
                // Redis, MongoDB, etc.
                || lower.contains(".find_one(")
                || lower.contains(".find(")
                || lower.contains(".insert_one(")
                || lower.contains(".insert_many(")
                || lower.contains(".update_one(")
                || lower.contains(".aggregate(")
                || lower.contains(".hget(")
                || lower.contains(".hset(")
        }
        "javascript" | "typescript" => {
            lower.contains(".findone(")
                || lower.contains(".findmany(")
                || lower.contains(".findunique(")
                || lower.contains(".create(")
                || lower.contains(".upsert(")
                || lower.contains("prisma.")
                || lower.contains("mongoose.")
        }
        _ => false,
    }
}

/// Check if a line contains actual SQL keywords in string literals.
fn contains_sql_in_string(line: &str) -> bool {
    let re = Regex::new(r#"(?i)["'`].*\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE)\b.*["'`]"#).unwrap();
    re.is_match(line)
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 1: SQL Injection (Context-Aware)
// ════════════════════════════════════════════════════════════════════

fn detect_sql_injection(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r#"(?i)(execute|cursor\.execute)\s*\(\s*[f"'].*%s"#,
                "SQL query uses string formatting instead of parameterized queries",
            ),
            (
                r#"(?i)(execute|cursor\.execute)\s*\(\s*f["']"#,
                "SQL query uses f-string interpolation — vulnerable to injection",
            ),
            (
                r#"(?i)(execute|cursor\.execute)\s*\(\s*["'].*\+\s*"#,
                "SQL query uses string concatenation — vulnerable to injection",
            ),
            (
                r#"(?i)(execute|cursor\.execute)\s*\(\s*.*\.format\("#,
                "SQL query uses .format() — vulnerable to injection",
            ),
            (
                r#"(?i)raw\s*\(\s*[f"'].*SELECT|INSERT|UPDATE|DELETE"#,
                "Raw SQL with string interpolation",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                r#"(?i)(query|execute)\s*\(\s*[`"'].*\$\{"#,
                "SQL query uses template literal interpolation — vulnerable to injection",
            ),
            (
                r#"(?i)(query|execute)\s*\(\s*.*\+\s*"#,
                "SQL query uses string concatenation — vulnerable to injection",
            ),
            (
                r#"(?i)\.raw\s*\(\s*[`"'].*\$\{"#,
                "Raw SQL query with interpolation",
            ),
        ],
        "rust" => vec![(
            r#"(?i)format!\s*\(\s*["'].*SELECT|INSERT|UPDATE|DELETE"#,
            "SQL query built with format! macro — use parameterized queries",
        )],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }
        // Skip known safe API calls (ChromaDB, ORMs, NoSQL, etc.)
        if is_safe_api_call(trimmed, lang) {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    // For Python raw() pattern, verify actual SQL keywords are present
                    if pattern.contains("raw") && !contains_sql_in_string(trimmed) {
                        continue;
                    }
                    let (ctx, _start, end) = get_line_context(lines, i, 2);
                    let fixed = generate_sql_fix(trimmed, lang);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Critical".to_string(),
                        owasp_category: "A03:2021 Injection".to_string(),
                        vuln_type: "SQLInjection".to_string(),
                        title: "SQL Injection Vulnerability".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fixed,
                        confidence: 0.85,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

fn generate_sql_fix(line: &str, lang: &str) -> String {
    match lang {
        "python" => {
            if line.contains("f\"") || line.contains("f'") {
                "# Use parameterized queries:\n# cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))".to_string()
            } else {
                "# Use parameterized queries with placeholders:\n# cursor.execute(\"SELECT * FROM table WHERE col = %s\", (value,))".to_string()
            }
        }
        "javascript" | "typescript" => {
            "// Use parameterized queries:\n// db.query(\"SELECT * FROM users WHERE id = $1\", [userId])".to_string()
        }
        _ => "Use parameterized/prepared statements instead of string interpolation.".to_string(),
    }
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 2: XSS (Cross-Site Scripting)
// ════════════════════════════════════════════════════════════════════

fn detect_xss(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    let patterns: Vec<(&str, &str, &str)> = match lang {
        "javascript" | "typescript" => vec![
            (r"\.innerHTML\s*=", "Direct innerHTML assignment — vulnerable to stored/reflected XSS",
             "// Use textContent for safe text insertion:\n// element.textContent = userInput;\n// Or sanitize: DOMPurify.sanitize(userInput)"),
            (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML bypasses XSS protection",
             "// Sanitize before rendering:\n// dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}"),
            (r"document\.write\s*\(", "document.write() with dynamic content enables XSS",
             "// Replace with safe DOM manipulation:\n// const el = document.createElement('div');\n// el.textContent = content;\n// document.body.appendChild(el);"),
            (r"\.outerHTML\s*=", "outerHTML assignment with user input enables XSS",
             "// Use textContent or create elements safely"),
            (r"eval\s*\(", "eval() executes arbitrary code — severe XSS/RCE risk",
             "// Use JSON.parse() for JSON data, or a safe parser for expressions"),
        ],
        "python" => vec![
            (r"(?i)mark_safe\s*\(", "Django mark_safe() bypasses HTML escaping — XSS risk if user input",
             "# Only use mark_safe on already-sanitized content:\n# from django.utils.html import escape\n# mark_safe(escape(user_input))"),
            (r"\|\s*safe\b", "Django |safe template filter bypasses auto-escaping",
             "# Remove |safe filter or sanitize input before marking safe"),
            (r"(?i)render_template_string\s*\(", "Flask render_template_string with user input enables SSTI/XSS",
             "# Use render_template() with .html files instead of template strings"),
            (r"Markup\s*\(", "Jinja2 Markup() bypasses auto-escaping",
             "# Use Markup.escape() to sanitize user input first"),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc, fix) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _start, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "High".to_string(),
                        owasp_category: "A03:2021 Injection".to_string(),
                        vuln_type: "XSS".to_string(),
                        title: "Cross-Site Scripting (XSS)".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fix.to_string(),
                        confidence: 0.80,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 3: Command Injection
// ════════════════════════════════════════════════════════════════════

fn detect_command_injection(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
    caps: &FileCapabilities,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    let patterns: Vec<(&str, &str, &str)> = match lang {
        "python" if caps.has_shell_exec => vec![
            (r"os\.system\s*\(", "os.system() executes shell commands — command injection risk",
             "# Use subprocess with argument list (no shell):\n# import subprocess\n# subprocess.run(['command', 'arg1'], check=True)"),
            (r"subprocess\.\w+\(.*shell\s*=\s*True", "subprocess with shell=True allows injection via shell metacharacters",
             "# Remove shell=True and pass args as list:\n# subprocess.run(['cmd', arg], check=True)"),
            (r"os\.popen\s*\(", "os.popen() is vulnerable to command injection",
             "# Use subprocess.run() with argument list instead"),
            (r"eval\s*\(", "eval() executes arbitrary Python code — critical injection risk",
             "# Use ast.literal_eval() for safe evaluation of literals:\n# import ast\n# result = ast.literal_eval(user_input)"),
            (r"exec\s*\(", "exec() executes arbitrary Python code — critical injection risk",
             "# Remove exec() and implement the logic directly, or use a safe sandbox"),
            (r"__import__\s*\(", "__import__() with user input allows arbitrary module loading",
             "# Use explicit imports instead of dynamic __import__()"),
        ],
        "python" => vec![
            // Only eval/exec — always dangerous regardless of imports
            (r"eval\s*\(", "eval() executes arbitrary Python code — critical injection risk",
             "# Use ast.literal_eval() for safe evaluation of literals:\n# import ast\n# result = ast.literal_eval(user_input)"),
            (r"exec\s*\(", "exec() executes arbitrary Python code — critical injection risk",
             "# Remove exec() and implement the logic directly, or use a safe sandbox"),
        ],
        "javascript" | "typescript" if caps.has_shell_exec => vec![
            (r"child_process\.\w*exec\b", "child_process.exec() runs shell commands — injection risk",
             "// Use execFile() with argument array:\n// const { execFile } = require('child_process');\n// execFile('cmd', [arg1, arg2], callback);"),
            (r"eval\s*\(", "eval() executes arbitrary code — critical injection/XSS risk",
             "// Use JSON.parse() for JSON, or a safe expression parser"),
            (r"new\s+Function\s*\(", "new Function() creates functions from strings — code injection risk",
             "// Define functions directly instead of from string templates"),
        ],
        "javascript" | "typescript" => vec![
            // Only eval — always dangerous regardless of imports
            (r"eval\s*\(", "eval() executes arbitrary code — critical injection/XSS risk",
             "// Use JSON.parse() for JSON, or a safe expression parser"),
            (r"new\s+Function\s*\(", "new Function() creates functions from strings — code injection risk",
             "// Define functions directly instead of from string templates"),
        ],
        "rust" => vec![
            (r"Command::new\s*\(.*\.arg\(.*format!", "Shell command with formatted arguments — injection risk if user-controlled",
             "// Validate and sanitize user input before passing as command arguments\n// Use allowlists for permissible commands"),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }
        for (pattern, desc, fix) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let is_eval_exec = pattern.contains("eval") || pattern.contains("exec");
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: if is_eval_exec { "Critical" } else { "High" }.to_string(),
                        owasp_category: "A03:2021 Injection".to_string(),
                        vuln_type: "CommandInjection".to_string(),
                        title: "Command/Code Injection".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fix.to_string(),
                        confidence: 0.82,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 4: Header Injection
// ════════════════════════════════════════════════════════════════════

fn detect_header_injection(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r"(?i)response\[.*\]\s*=\s*.*request\.",
                "HTTP response header set from request data — header injection risk",
            ),
            (
                r"(?i)set_cookie\s*\(.*request\.",
                "Cookie value derived from user request — injection risk",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                r"(?i)res\.set(?:Header)?\s*\(.*req\.",
                "Response header set from request parameter — header injection",
            ),
            (
                r"(?i)res\.header\s*\(.*req\.",
                "Response header derived from request — CRLF injection risk",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "High".to_string(),
                        owasp_category: "A03:2021 Injection".to_string(),
                        vuln_type: "HeaderInjection".to_string(),
                        title: "HTTP Header Injection".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Sanitize user input by stripping \\r\\n characters before setting headers.".to_string(),
                        confidence: 0.70,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 5: Auth Weaknesses
// ════════════════════════════════════════════════════════════════════

fn detect_auth_weaknesses(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    let patterns: Vec<(&str, &str, &str)> = match lang {
        "python" => vec![
            (r#"(?i)password\s*==\s*["']"#, "Hardcoded password comparison — credentials should be hashed",
             "# Use bcrypt or argon2 to hash and compare passwords:\n# import bcrypt\n# bcrypt.checkpw(password.encode(), hashed)"),
            (r#"(?i)verify\s*=\s*False"#, "SSL verification disabled — allows MITM attacks",
             "# Remove verify=False or set verify=True:\n# requests.get(url, verify=True)"),
            (r"(?i)@app\.route.*methods.*POST(?!.*@login_required)", "POST endpoint may lack authentication decorator",
             "# Add @login_required decorator:\n# @login_required\n# @app.route('/endpoint', methods=['POST'])"),
        ],
        "javascript" | "typescript" => vec![
            (r#"(?i)password\s*===?\s*["']"#, "Hardcoded password comparison — use bcrypt.compare()",
             "// Use bcrypt for password verification:\n// const match = await bcrypt.compare(password, hashedPassword);"),
            (r"(?i)rejectUnauthorized\s*:\s*false", "TLS certificate validation disabled — MITM vulnerability",
             "// Remove rejectUnauthorized: false in production"),
            (r#"(?i)jwt\.sign\(.*algorithm.*["']none["']"#, "JWT signed with 'none' algorithm — trivially forgeable",
             "// Use a strong algorithm:\n// jwt.sign(payload, secret, { algorithm: 'HS256' })"),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc, fix) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "High".to_string(),
                        owasp_category: "A07:2021 Auth Failures".to_string(),
                        vuln_type: "AuthWeakness".to_string(),
                        title: "Authentication/Authorization Weakness".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fix.to_string(),
                        confidence: 0.72,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 6: CSRF Missing
// ════════════════════════════════════════════════════════════════════

fn detect_csrf_missing(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r"(?i)@csrf_exempt",
                "CSRF protection explicitly disabled on this endpoint",
            ),
            (
                r"(?i)WTF_CSRF_ENABLED\s*=\s*False",
                "CSRF protection globally disabled for Flask-WTF",
            ),
        ],
        "javascript" | "typescript" => vec![(
            r"(?i)csrf\s*:\s*false",
            "CSRF protection explicitly disabled",
        )],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Medium".to_string(),
                        owasp_category: "A01:2021 Broken Access".to_string(),
                        vuln_type: "CSRFMissing".to_string(),
                        title: "CSRF Protection Disabled".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Enable CSRF protection for state-changing endpoints."
                            .to_string(),
                        confidence: 0.90,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 7: Open Redirect
// ════════════════════════════════════════════════════════════════════

fn detect_open_redirect(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![(
            r"(?i)redirect\s*\(\s*request\.(args|GET|POST|form)",
            "Redirect URL taken directly from user request — open redirect",
        )],
        "javascript" | "typescript" => vec![
            (
                r"(?i)res\.redirect\s*\(\s*req\.(query|params|body)",
                "Redirect URL from request parameters — open redirect",
            ),
            (
                r"(?i)window\.location\s*=\s*.*(?:search|hash|href)",
                "Client-side redirect from URL parameters — open redirect risk",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Medium".to_string(),
                        owasp_category: "A01:2021 Broken Access".to_string(),
                        vuln_type: "OpenRedirect".to_string(),
                        title: "Open Redirect".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code:
                            "Validate redirect URLs against an allowlist of trusted domains."
                                .to_string(),
                        confidence: 0.68,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 8: Hardcoded Secrets
// ════════════════════════════════════════════════════════════════════

fn detect_hardcoded_secrets(
    file: &str,
    _lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let secret_re = Regex::new(
        r#"(?i)(password|secret|api_?key|token|auth_?token|private_?key|access_?key|client_?secret)\s*[=:]\s*["'][^"']{8,}["']"#
    ).unwrap();
    // Common API key patterns
    let api_key_re = Regex::new(
        r#"(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gsk_[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[a-zA-Z0-9_-]{35})"#
    ).unwrap();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }
        if trimmed.contains("your_")
            || trimmed.contains("_here")
            || trimmed.contains("placeholder")
            || trimmed.contains("example")
            || trimmed.contains("CHANGEME")
        {
            continue;
        }

        let matched = if secret_re.is_match(trimmed) {
            Some("Hardcoded credential detected — must be stored in environment variables")
        } else if api_key_re.is_match(trimmed) {
            Some("API key pattern detected in source code — highly sensitive exposure")
        } else {
            None
        };

        if let Some(desc) = matched {
            let (ctx, _, end) = get_line_context(lines, i, 0);
            let redacted = redact_secret(&ctx);
            vulns.push(SecurityVulnerability {
                id: next_id(counter),
                file: file.to_string(),
                line: i + 1,
                end_line: end,
                severity: "Critical".to_string(),
                owasp_category: "A02:2021 Crypto Failures".to_string(),
                vuln_type: "HardcodedSecret".to_string(),
                title: "Hardcoded Secret/Credential".to_string(),
                description: desc.to_string(),
                original_code: redacted,
                fixed_code:
                    "# Use environment variables:\n# import os\n# secret = os.environ['SECRET_KEY']"
                        .to_string(),
                confidence: 0.92,
                ai_explanation: None,
                detection_layer: "L1-Pattern".to_string(),
            });
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 9: Info Leakage
// ════════════════════════════════════════════════════════════════════

fn detect_info_leakage(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r"(?i)DEBUG\s*=\s*True",
                "Django DEBUG=True exposes stack traces and config to attackers",
            ),
            (
                r"(?i)traceback\.print_exc\s*\(",
                "Stack trace printed — may leak internal details to users",
            ),
            (
                r"(?i)(app\.run|\.run)\s*\(.*debug\s*=\s*True",
                "Flask debug mode enabled — exposes debugger and source in production",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                r"(?i)console\.log\s*\(.*(?:password|token|secret|key)",
                "Logging sensitive data to console",
            ),
            (
                r"(?i)\.stack\b.*res\.(send|json|write)",
                "Sending error stack trace to client response",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Medium".to_string(),
                        owasp_category: "A04:2021 Insecure Design".to_string(),
                        vuln_type: "InfoLeakage".to_string(),
                        title: "Information Leakage".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Disable debug mode in production. Use generic error messages for users.".to_string(),
                        confidence: 0.78,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 10: Weak Crypto
// ════════════════════════════════════════════════════════════════════

fn detect_weak_crypto(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str, &str)> = match lang {
        "python" => vec![
            (r"(?i)hashlib\.(md5|sha1)\s*\(", "Weak hash algorithm (MD5/SHA1) — not collision-resistant",
             "# Use SHA-256 or stronger:\n# import hashlib\n# hashlib.sha256(data).hexdigest()"),
            (r"(?i)random\.(random|randint|choice)\s*\(", "Using `random` module for security-sensitive values — not cryptographically secure",
             "# Use secrets module:\n# import secrets\n# token = secrets.token_hex(32)"),
            (r"(?i)DES\b|Blowfish|RC4", "Weak/deprecated encryption algorithm",
             "# Use AES-256-GCM:\n# from cryptography.fernet import Fernet"),
        ],
        "javascript" | "typescript" => vec![
            (r#"(?i)createHash\s*\(\s*['"](?:md5|sha1)['"]"#, "Weak hash algorithm — use SHA-256+",
             "// Use SHA-256:\n// crypto.createHash('sha256').update(data).digest('hex')"),
            (r"Math\.random\s*\(", "Math.random() is not cryptographically secure — do not use for tokens/keys",
             "// Use crypto:\n// const { randomBytes } = require('crypto');\n// const token = randomBytes(32).toString('hex');"),
        ],
        "rust" => vec![
            (r"(?i)md5::|Md5::", "MD5 is cryptographically broken — use SHA-256+",
             "// Use sha2 crate:\n// use sha2::{Sha256, Digest};\n// let hash = Sha256::digest(data);"),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc, fix) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 0);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Medium".to_string(),
                        owasp_category: "A02:2021 Crypto Failures".to_string(),
                        vuln_type: "WeakCrypto".to_string(),
                        title: "Weak Cryptography".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fix.to_string(),
                        confidence: 0.85,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 11: Path Traversal
// ════════════════════════════════════════════════════════════════════

fn detect_path_traversal(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r#"(?i)open\s*\(\s*(?:request\.|.*\+|f['"])"#,
                "File opened with user-controlled path — path traversal risk",
            ),
            (
                r"(?i)os\.path\.join\s*\(.*request\.",
                "os.path.join with user input — traversal via absolute path injection",
            ),
            (
                r"(?i)send_file\s*\(.*request\.",
                "Flask send_file with user-controlled path — file disclosure",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                r"(?i)(?:readFile|readFileSync|createReadStream)\s*\(.*req\.",
                "File read with user-controlled path — path traversal",
            ),
            (
                r"(?i)path\.join\s*\(.*req\.",
                "path.join with user input — directory traversal risk",
            ),
            (
                r"(?i)res\.sendFile\s*\(.*req\.",
                "Express sendFile from user input — arbitrary file read",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "High".to_string(),
                        owasp_category: "A01:2021 Broken Access".to_string(),
                        vuln_type: "PathTraversal".to_string(),
                        title: "Path Traversal / Directory Traversal".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Validate file paths against a base directory using os.path.realpath() and ensure the result starts with the allowed base path.".to_string(),
                        confidence: 0.75,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 12: SSRF
// ════════════════════════════════════════════════════════════════════

fn detect_ssrf(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r#"(?i)requests\.(get|post|put|delete|head)\s*\(\s*(?:request\.|.*\+|f['"])"#,
                "HTTP request with user-controlled URL — SSRF risk",
            ),
            (
                r"(?i)urllib\.request\.urlopen\s*\(\s*(?:request\.|.*\+)",
                "urlopen with user input — SSRF vulnerability",
            ),
        ],
        "javascript" | "typescript" => vec![(
            r"(?i)(?:fetch|axios\.\w+|got)\s*\(\s*(?:req\.|.*\+|`)",
            "HTTP request with user-controlled URL — SSRF risk",
        )],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "High".to_string(),
                        owasp_category: "A10:2021 SSRF".to_string(),
                        vuln_type: "SSRF".to_string(),
                        title: "Server-Side Request Forgery (SSRF)".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Validate URLs against an allowlist. Block private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, localhost).".to_string(),
                        confidence: 0.72,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 13: Insecure Deserialization
// ════════════════════════════════════════════════════════════════════

fn detect_insecure_deserialization(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str, &str)> = match lang {
        "python" => vec![
            (r"pickle\.loads?\s*\(", "pickle deserialization of untrusted data — allows arbitrary code execution",
             "# Use JSON for data serialization:\n# import json\n# data = json.loads(raw_data)"),
            (r"yaml\.load\s*\([^)]*\)\s*$", "yaml.load() without SafeLoader — arbitrary code execution risk",
             "# Use safe loader:\n# data = yaml.safe_load(raw_data)\n# Or: yaml.load(raw_data, Loader=yaml.SafeLoader)"),
            (r"yaml\.load\s*\((?!.*SafeLoader|.*safe_load)", "yaml.load() without SafeLoader — code execution via YAML",
             "# Use yaml.safe_load() instead"),
            (r"marshal\.loads?\s*\(", "marshal deserialization — can execute arbitrary code",
             "# Use JSON or msgpack for safe deserialization"),
            (r"shelve\.open\s*\(", "shelve uses pickle internally — unsafe for untrusted data",
             "# Use a database or JSON-based storage instead"),
        ],
        "javascript" | "typescript" => vec![
            (r"(?i)serialize\s*\(|unserialize\s*\(", "Unsafe serialization/deserialization library",
             "// Use JSON.parse/JSON.stringify for safe serialization"),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc, fix) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 1);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Critical".to_string(),
                        owasp_category: "A08:2021 Integrity Failures".to_string(),
                        vuln_type: "InsecureDeserialization".to_string(),
                        title: "Insecure Deserialization".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: fix.to_string(),
                        confidence: 0.88,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 14: Unsafe File Operations
// ════════════════════════════════════════════════════════════════════

fn detect_unsafe_file_ops(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();
    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                r"(?i)chmod\s*\(\s*.*0o?777",
                "Setting world-writable permissions (777) — major security risk",
            ),
            (
                r"(?i)tempfile\.mktemp\s*\(",
                "tempfile.mktemp() is insecure (race condition) — use mkstemp()",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                r"(?i)chmod.*0o?777|chmodSync.*0o?777",
                "Setting world-writable permissions — security risk",
            ),
            (
                r"(?i)writeFile.*\.env|writeFile.*config",
                "Writing to sensitive configuration file dynamically",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(trimmed) {
                    let (ctx, _, end) = get_line_context(lines, i, 0);
                    vulns.push(SecurityVulnerability {
                        id: next_id(counter),
                        file: file.to_string(),
                        line: i + 1,
                        end_line: end,
                        severity: "Medium".to_string(),
                        owasp_category: "A05:2021 Misconfiguration".to_string(),
                        vuln_type: "UnsafeFileOps".to_string(),
                        title: "Unsafe File Operation".to_string(),
                        description: desc.to_string(),
                        original_code: ctx,
                        fixed_code: "Use restrictive file permissions (0o600/0o644). Use tempfile.mkstemp() for temp files.".to_string(),
                        confidence: 0.80,
                        ai_explanation: None,
                        detection_layer: "L1-Pattern".to_string(),
                    });
                    break;
                }
            }
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 15: Error Handling Issues
// ════════════════════════════════════════════════════════════════════

fn detect_error_handling(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        match lang {
            "python" => {
                if (trimmed.starts_with("except") && trimmed.ends_with(':')) || trimmed == "except:"
                {
                    // Check for bare except with just pass
                    for j in (i + 1)..lines.len().min(i + 4) {
                        let next = lines[j].trim();
                        if next.is_empty() {
                            continue;
                        }
                        if next == "pass" {
                            let (ctx, _, end) = get_line_context(lines, i, 2);
                            vulns.push(SecurityVulnerability {
                                id: next_id(counter),
                                file: file.to_string(),
                                line: i + 1,
                                end_line: end,
                                severity: "Medium".to_string(),
                                owasp_category: "A09:2021 Logging Failures".to_string(),
                                vuln_type: "SilentExceptionSwallow".to_string(),
                                title: "Silent Exception Swallowing".to_string(),
                                description: "Bare except: pass silently swallows all exceptions — hides security errors and bugs.".to_string(),
                                original_code: ctx,
                                fixed_code: "except Exception as e:\n    logging.error(f\"Error occurred: {e}\")\n    raise  # Re-raise or handle appropriately".to_string(),
                                confidence: 0.90,
                                ai_explanation: None,
                                detection_layer: "L1-Pattern".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
            "javascript" | "typescript" => {
                if trimmed.starts_with("catch") && trimmed.contains('{') {
                    let next_idx = i + 1;
                    if next_idx < lines.len() {
                        let next = lines[next_idx].trim();
                        if next == "}" || next.is_empty() {
                            let (ctx, _, end) = get_line_context(lines, i, 2);
                            vulns.push(SecurityVulnerability {
                                id: next_id(counter),
                                file: file.to_string(),
                                line: i + 1,
                                end_line: end,
                                severity: "Medium".to_string(),
                                owasp_category: "A09:2021 Logging Failures".to_string(),
                                vuln_type: "SilentExceptionSwallow".to_string(),
                                title: "Empty Catch Block".to_string(),
                                description: "Empty catch block silently swallows errors — may hide security issues.".to_string(),
                                original_code: ctx,
                                fixed_code: "catch (error) {\n  console.error('Error:', error);\n  throw error; // Re-throw or handle\n}".to_string(),
                                confidence: 0.88,
                                ai_explanation: None,
                                detection_layer: "L1-Pattern".to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    vulns
}

// ════════════════════════════════════════════════════════════════════
// DETECTOR 16: Insecure Randomness
// ════════════════════════════════════════════════════════════════════

fn detect_insecure_randomness(
    file: &str,
    lang: &str,
    lines: &[&str],
    counter: &mut u64,
) -> Vec<SecurityVulnerability> {
    let mut vulns = Vec::new();

    // Look for security-sensitive context + insecure random in nearby lines
    let security_contexts = [
        "token", "session", "secret", "nonce", "salt", "key", "password", "otp", "code",
    ];

    for (i, line) in lines.iter().enumerate() {
        let lower = line.to_lowercase();
        let has_security_context = security_contexts.iter().any(|ctx| lower.contains(ctx));
        if !has_security_context {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        let insecure_random = match lang {
            "python" => {
                lower.contains("random.")
                    && !lower.contains("secrets.")
                    && !lower.contains("systemrandom")
            }
            "javascript" | "typescript" => lower.contains("math.random"),
            _ => false,
        };

        if insecure_random {
            let (ctx, _, end) = get_line_context(lines, i, 1);
            let fix = match lang {
                "python" => "# Use secrets module for cryptographic randomness:\n# import secrets\n# token = secrets.token_hex(32)",
                _ => "// Use crypto.randomBytes():\n// const crypto = require('crypto');\n// const token = crypto.randomBytes(32).toString('hex');",
            };
            vulns.push(SecurityVulnerability {
                id: next_id(counter),
                file: file.to_string(),
                line: i + 1,
                end_line: end,
                severity: "High".to_string(),
                owasp_category: "A02:2021 Crypto Failures".to_string(),
                vuln_type: "InsecureRandomness".to_string(),
                title: "Insecure Random for Security Context".to_string(),
                description: "Using non-cryptographic random in a security-sensitive context (tokens, keys, sessions).".to_string(),
                original_code: ctx,
                fixed_code: fix.to_string(),
                confidence: 0.82,
                ai_explanation: None,
                detection_layer: "L1-Pattern".to_string(),
            });
        }
    }
    vulns
}

// ── Helpers ───────────────────────────────────────────────────────

fn redact_secret(line: &str) -> String {
    let re = Regex::new(r#"(["'])[^"']{4}([^"']*)(["'])"#).unwrap();
    re.replace_all(line, "${1}****${3}").to_string()
}

fn language_from_path(path: &Path) -> Option<&'static str> {
    // Check filename first for special files without extensions
    if let Some(name) = path.file_name().and_then(|v| v.to_str()) {
        match name {
            "Dockerfile" | "dockerfile" => return Some("dockerfile"),
            ".env" | ".env.local" | ".env.production" | ".env.development" => return Some("env"),
            "Makefile" | "makefile" => return Some("makefile"),
            _ => {}
        }
    }
    match path.extension().and_then(|v| v.to_str()) {
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Some("javascript"),
        Some("ts") | Some("tsx") | Some("mts") | Some("cts") => Some("typescript"),
        Some("py") | Some("pyw") => Some("python"),
        Some("rs") => Some("rust"),
        Some("go") => Some("go"),
        Some("java") => Some("java"),
        Some("c") | Some("h") => Some("c"),
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => Some("cpp"),
        Some("rb") => Some("ruby"),
        Some("php") => Some("php"),
        Some("yml") | Some("yaml") => Some("yaml"),
        Some("json") => Some("json"),
        Some("html") | Some("htm") => Some("html"),
        Some("xml") => Some("xml"),
        Some("toml") => Some("toml"),
        Some("cfg") | Some("ini") | Some("conf") => Some("config"),
        Some("sh") | Some("bash") | Some("zsh") => Some("shell"),
        Some("sql") => Some("sql"),
        Some("env") => Some("env"),
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
            | Some("ml_engine")
            | Some("src-tauri")
            | Some(".gemini")
            | Some(".agents")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eval_as_command_injection() {
        let lines = vec!["result = eval(user_input)"];
        let mut counter = 0;
        let caps = FileCapabilities {
            has_shell_exec: true,
            ..Default::default()
        };
        let vulns = detect_command_injection("test.py", "python", &lines, &mut counter, &caps);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vuln_type, "CommandInjection");
    }

    #[test]
    fn detects_bare_except_pass() {
        let lines = vec!["try:", "    do_something()", "except:", "    pass"];
        let mut counter = 0;
        let vulns = detect_error_handling("test.py", "python", &lines, &mut counter);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vuln_type, "SilentExceptionSwallow");
    }

    #[test]
    fn detects_hardcoded_password() {
        let lines = vec![r#"password = "supersecretpassword123""#];
        let mut counter = 0;
        let vulns = detect_hardcoded_secrets("test.py", "python", &lines, &mut counter);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vuln_type, "HardcodedSecret");
    }
}
