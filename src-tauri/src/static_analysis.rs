use std::{collections::HashSet, fs, path::Path};

use regex::Regex;
use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use crate::workspace::{canonicalize_workspace, validate_repository_scope};

const MAX_SCAN_FILES: usize = 2_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BUGS: usize = 200;

// ── Public types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticAnalysisRequest {
    pub workspace_root: String,
    pub issue_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticBugReport {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub severity: String, // Critical, High, Medium, Low, Info
    pub bug_type: String, // LogicError, DivideByZero, OffByOne, …
    pub description: String,
    pub evidence_snippet: String,
    pub suggested_fix_hint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticAnalysisSummary {
    pub workspace_root: String,
    pub scanned_files: usize,
    pub total_bugs: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub bugs: Vec<StaticBugReport>,
    pub warnings: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────

pub async fn detect_static_bugs(
    request: StaticAnalysisRequest,
) -> Result<StaticAnalysisSummary, String> {
    let workspace_root = canonicalize_workspace(&request.workspace_root)?;
    validate_repository_scope(&workspace_root)?;

    let issue_keywords: Vec<String> = request
        .issue_hint
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_lowercase())
        .collect();

    let mut bugs: Vec<StaticBugReport> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;

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
            warnings.push("Stopped after scanning 2 000 files.".to_string());
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

        let mut file_bugs = run_all_detectors(&relative, lang, &source, &issue_keywords);
        let remaining = MAX_BUGS.saturating_sub(bugs.len());
        file_bugs.truncate(remaining);
        bugs.extend(file_bugs);

        if bugs.len() >= MAX_BUGS {
            warnings.push(format!(
                "Stopped after collecting {} bug reports.",
                MAX_BUGS
            ));
            break;
        }
    }

    // Sort by severity priority
    bugs.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));

    let critical_count = bugs.iter().filter(|b| b.severity == "Critical").count();
    let high_count = bugs.iter().filter(|b| b.severity == "High").count();
    let medium_count = bugs.iter().filter(|b| b.severity == "Medium").count();
    let low_count = bugs.iter().filter(|b| b.severity == "Low").count();

    Ok(StaticAnalysisSummary {
        workspace_root: workspace_root.display().to_string(),
        scanned_files,
        total_bugs: bugs.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        bugs,
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

fn run_all_detectors(
    file: &str,
    lang: &str,
    source: &str,
    issue_keywords: &[String],
) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // 1. Logic-inversion detector (function name vs. actual operation)
    bugs.extend(detect_logic_inversion(file, lang, &lines));

    // 2. Divide by zero
    bugs.extend(detect_divide_by_zero(file, lang, &lines));

    // 3. Off-by-one in loops
    bugs.extend(detect_off_by_one(file, lang, &lines));

    // 4. Unreachable code after return/throw/panic
    bugs.extend(detect_unreachable_code(file, lang, &lines));

    // 5. Unsafe unwrap chains (Rust-specific)
    if lang == "rust" {
        bugs.extend(detect_unsafe_unwrap(file, &lines));
    }

    // 6. Taint flow: dangerous sinks
    bugs.extend(detect_taint_sinks(file, lang, &lines));

    // 7. FIXME/HACK/BUG/XXX markers
    bugs.extend(detect_bug_markers(file, &lines));

    // 8. Null/None comparisons that are suspicious
    bugs.extend(detect_null_issues(file, lang, &lines));

    // 9. Variable shadowing in nested scopes
    bugs.extend(detect_variable_shadowing(file, lang, &lines));

    // 10. Empty exception handlers (catch/except that silently swallow errors)
    bugs.extend(detect_empty_exception_handlers(file, lang, &lines));

    // 11. Hardcoded secrets/credentials
    bugs.extend(detect_hardcoded_secrets(file, &lines));

    // 12. Issue-keyword-specific boosting: if user mentioned a function etc, flag related lines
    if !issue_keywords.is_empty() {
        bugs.extend(detect_keyword_related_issues(file, &lines, issue_keywords));
    }

    bugs
}

// ── Individual detectors ──────────────────────────────────────────

fn detect_logic_inversion(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();

    // Match: function/def named *add* but body uses subtraction, and vice versa
    let operations = [
        ("add", "+", "-", "subtraction"),
        ("subtract", "-", "+", "addition"),
        ("sub", "-", "+", "addition"),
        ("multiply", "*", "/", "division"),
        ("mul", "*", "/", "division"),
        ("divide", "/", "*", "multiplication"),
        ("div", "/", "*", "multiplication"),
        ("increment", "+", "-", "decrement"),
        ("decrement", "-", "+", "increment"),
    ];

    // Find function boundaries
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let func_name = extract_func_name(trimmed, lang);
        let func_name = match func_name {
            Some(n) => n.to_lowercase(),
            None => continue,
        };

        for &(keyword, _expected_op, wrong_op, wrong_desc) in &operations {
            if !func_name.contains(keyword) {
                continue;
            }

            // Scan function body (up to 20 lines ahead)
            let body_end = (i + 20).min(lines.len());
            for j in (i + 1)..body_end {
                let body_line = lines[j].trim();
                // Check for return statements with the wrong operator
                if body_line.starts_with("return ") || body_line.contains("return ") {
                    // Look for "a <wrong_op> b" patterns
                    if contains_arithmetic_op(body_line, wrong_op)
                        && !contains_arithmetic_op(body_line, _expected_op)
                    {
                        bugs.push(StaticBugReport {
                            file: file.to_string(),
                            line: j + 1,
                            column: 1,
                            severity: "High".to_string(),
                            bug_type: "LogicError".to_string(),
                            description: format!(
                                "Function `{}` appears to perform {} instead of the expected operation. The function name suggests '{}' but the return uses '{}'.",
                                func_name, wrong_desc, keyword, wrong_op
                            ),
                            evidence_snippet: body_line.to_string(),
                            suggested_fix_hint: format!(
                                "Replace '{}' with '{}' in the return statement.",
                                wrong_op, _expected_op
                            ),
                        });
                    }
                }
            }
        }
    }

    bugs
}

fn detect_divide_by_zero(file: &str, _lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let re = Regex::new(r"[/\%]\s*0(?:\s*[;,)\]}]|\s*$)").unwrap();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }
        if re.is_match(trimmed) {
            // Exclude 0.0 patterns (valid floats)
            if trimmed.contains("/ 0.") || trimmed.contains("/0.") {
                continue;
            }
            bugs.push(StaticBugReport {
                file: file.to_string(),
                line: i + 1,
                column: 1,
                severity: "Critical".to_string(),
                bug_type: "DivideByZero".to_string(),
                description: "Potential division or modulo by zero literal.".to_string(),
                evidence_snippet: trimmed.to_string(),
                suggested_fix_hint:
                    "Add a guard to check the divisor is not zero before this operation."
                        .to_string(),
            });
        }
    }

    bugs
}

fn detect_off_by_one(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    // Pattern: `for ... i <= len` or `i <= .length` or `i <= .len()`
    let re = match lang {
        "python" => Regex::new(r"range\s*\(\s*\d+\s*,\s*len\s*\(").ok(),
        "javascript" | "typescript" => Regex::new(r"(<=)\s*\w+\.(length|size|count)").ok(),
        "rust" => Regex::new(r"(<=)\s*\w+\.len\(\)").ok(),
        _ => None,
    };

    if let Some(re) = re {
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }
            if (trimmed.contains("for ") || trimmed.contains("while ")) && re.is_match(trimmed) {
                bugs.push(StaticBugReport {
                    file: file.to_string(),
                    line: i + 1,
                    column: 1,
                    severity: "High".to_string(),
                    bug_type: "OffByOne".to_string(),
                    description: "Possible off-by-one error: loop condition uses `<=` with a collection length, which may access one element beyond the valid range.".to_string(),
                    evidence_snippet: trimmed.to_string(),
                    suggested_fix_hint: "Use `<` instead of `<=` when comparing against collection length.".to_string(),
                });
            }
        }
    }

    bugs
}

fn detect_unreachable_code(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let exit_keywords: &[&str] = match lang {
        "python" => &["return ", "raise ", "sys.exit(", "exit("],
        "rust" => &["return ", "panic!(", "unreachable!(", "std::process::exit("],
        "javascript" | "typescript" => &["return ", "throw ", "process.exit("],
        _ => &["return "],
    };

    let mut inside_func = false;
    let mut _brace_depth: i32 = 0;
    let mut indent_level: Option<usize> = None;
    let mut just_exited = false;
    let mut exit_line = 0usize;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Track function entry
        if is_function_start(trimmed, lang) {
            inside_func = true;
            _brace_depth = 0;
            just_exited = false;
        }

        // Track braces for C-like languages
        for ch in trimmed.chars() {
            if ch == '{' {
                _brace_depth += 1;
            }
            if ch == '}' {
                _brace_depth -= 1;
            }
        }

        if !inside_func {
            continue;
        }

        // Python: use indentation
        if lang == "python" {
            let current_indent = line.len() - line.trim_start().len();
            if just_exited {
                if let Some(exit_indent) = indent_level {
                    if current_indent >= exit_indent
                        && !trimmed.starts_with("def ")
                        && !trimmed.starts_with("class ")
                        && !trimmed.starts_with("elif ")
                        && !trimmed.starts_with("else:")
                        && !trimmed.starts_with("except")
                        && !trimmed.starts_with("finally")
                    {
                        bugs.push(StaticBugReport {
                            file: file.to_string(),
                            line: i + 1,
                            column: 1,
                            severity: "Medium".to_string(),
                            bug_type: "UnreachableCode".to_string(),
                            description: format!("Code at line {} appears to be unreachable — it follows a return/raise/exit at the same or deeper indentation level (line {}).", i + 1, exit_line),
                            evidence_snippet: trimmed.to_string(),
                            suggested_fix_hint: "Remove this unreachable code or restructure the control flow.".to_string(),
                        });
                        just_exited = false;
                    } else {
                        just_exited = false;
                    }
                }
            }

            if exit_keywords.iter().any(|kw| trimmed.starts_with(kw)) {
                just_exited = true;
                indent_level = Some(current_indent);
                exit_line = i + 1;
            }
        } else {
            // C-like: check if line after return/throw at same brace depth is reachable
            if just_exited
                && !trimmed.starts_with('}')
                && !trimmed.starts_with("else")
                && !trimmed.starts_with("case ")
                && !trimmed.starts_with("default:")
            {
                bugs.push(StaticBugReport {
                    file: file.to_string(),
                    line: i + 1,
                    column: 1,
                    severity: "Medium".to_string(),
                    bug_type: "UnreachableCode".to_string(),
                    description: format!("Code at line {} may be unreachable — it follows a return/throw/panic at line {}.", i + 1, exit_line),
                    evidence_snippet: trimmed.to_string(),
                    suggested_fix_hint: "Remove this unreachable code or restructure the control flow.".to_string(),
                });
                just_exited = false;
            }

            if exit_keywords
                .iter()
                .any(|kw| trimmed.starts_with(kw) || trimmed.contains(kw))
            {
                // Only flag if not inside a nested block
                let is_end_of_statement =
                    trimmed.ends_with(';') || trimmed.ends_with(':') || !trimmed.contains('{');
                if is_end_of_statement {
                    just_exited = true;
                    exit_line = i + 1;
                }
            } else {
                just_exited = false;
            }
        }
    }

    bugs
}

fn detect_unsafe_unwrap(file: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let re = Regex::new(r"\.\s*unwrap\s*\(\s*\)").unwrap();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        // Ignore test modules
        if trimmed.contains("#[test]") || trimmed.contains("#[cfg(test)]") {
            break; // stop scanning test code
        }
        if re.is_match(trimmed) {
            bugs.push(StaticBugReport {
                file: file.to_string(),
                line: i + 1,
                column: 1,
                severity: "Medium".to_string(),
                bug_type: "PanicRisk".to_string(),
                description: "Bare `.unwrap()` call may panic at runtime if the Result/Option is Err/None.".to_string(),
                evidence_snippet: trimmed.to_string(),
                suggested_fix_hint: "Use `?` operator, `.unwrap_or()`, `.unwrap_or_default()`, or a proper match/if let.".to_string(),
            });
        }
    }

    bugs
}

fn detect_taint_sinks(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let sinks: Vec<&str> = match lang {
        "python" => vec![
            "eval(",
            "exec(",
            "os.system(",
            "subprocess.call(",
            "__import__(",
            "compile(",
        ],
        "javascript" | "typescript" => vec!["eval(", "Function(", "setTimeout(", "setInterval("],
        "rust" => vec!["Command::new("],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for sink in &sinks {
            if trimmed.contains(sink) {
                bugs.push(StaticBugReport {
                    file: file.to_string(),
                    line: i + 1,
                    column: 1,
                    severity: "High".to_string(),
                    bug_type: "SecurityVuln".to_string(),
                    description: format!("Dangerous sink `{}` detected. If user-controlled data reaches this call, it could lead to code injection or command execution.", sink.trim_end_matches('(')),
                    evidence_snippet: trimmed.to_string(),
                    suggested_fix_hint: "Validate and sanitize all inputs before passing to this function. Consider using safer alternatives.".to_string(),
                });
            }
        }
    }

    bugs
}

fn detect_bug_markers(file: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let marker_re = Regex::new(r"(?i)\b(FIXME|HACK|BUG|XXX|TODO|BROKEN|WORKAROUND)\b").unwrap();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Only match in comments
        if !(trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*'))
        {
            continue;
        }
        if let Some(m) = marker_re.find(trimmed) {
            let marker = m.as_str().to_uppercase();
            let sev = match marker.as_str() {
                "BUG" | "BROKEN" => "High",
                "FIXME" | "HACK" | "XXX" => "Medium",
                _ => "Low",
            };
            bugs.push(StaticBugReport {
                file: file.to_string(),
                line: i + 1,
                column: 1,
                severity: sev.to_string(),
                bug_type: "MarkerAnnotation".to_string(),
                description: format!("Developer annotation `{}` found — this code may be intentionally incomplete or known-broken.", marker),
                evidence_snippet: trimmed.to_string(),
                suggested_fix_hint: "Review and resolve the issue described in the comment.".to_string(),
            });
        }
    }

    bugs
}

fn detect_null_issues(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();

    let patterns: Vec<(&str, &str)> = match lang {
        "python" => vec![
            (
                "== None",
                "Use `is None` instead of `== None` for identity comparison.",
            ),
            (
                "!= None",
                "Use `is not None` instead of `!= None` for identity comparison.",
            ),
        ],
        "javascript" | "typescript" => vec![
            (
                "== null",
                "Use strict equality `=== null` instead of loose `== null`.",
            ),
            (
                "== undefined",
                "Use strict equality `=== undefined` instead of loose `== undefined`.",
            ),
        ],
        _ => vec![],
    };

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for (pattern, hint) in &patterns {
            if trimmed.contains(pattern) {
                bugs.push(StaticBugReport {
                    file: file.to_string(),
                    line: i + 1,
                    column: 1,
                    severity: "Low".to_string(),
                    bug_type: "NullComparison".to_string(),
                    description: format!("Loose null/undefined comparison found: `{}`.", pattern),
                    evidence_snippet: trimmed.to_string(),
                    suggested_fix_hint: hint.to_string(),
                });
            }
        }
    }

    bugs
}

fn detect_variable_shadowing(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    if lang != "python" && lang != "javascript" && lang != "typescript" {
        return bugs;
    }

    // Simple approach: track variable declarations by name within nested scopes
    let decl_re = match lang {
        "python" => Regex::new(r"^\s*(\w+)\s*=\s*.+").ok(),
        "javascript" | "typescript" => Regex::new(r"^\s*(?:let|const|var)\s+(\w+)").ok(),
        _ => None,
    };

    let Some(re) = decl_re else { return bugs };
    let mut outer_vars = HashSet::new();
    let mut depth = 0i32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Track scope depth for C-like
        if lang != "python" {
            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                }
                if ch == '}' {
                    depth -= 1;
                }
            }
        }

        if let Some(caps) = re.captures(trimmed) {
            if let Some(name) = caps.get(1).map(|m| m.as_str().to_string()) {
                // Skip short names or common variables
                if name.len() < 2
                    || matches!(name.as_str(), "i" | "j" | "k" | "_" | "self" | "x" | "y")
                {
                    continue;
                }
                if depth > 0 && outer_vars.contains(&name) {
                    bugs.push(StaticBugReport {
                        file: file.to_string(),
                        line: i + 1,
                        column: 1,
                        severity: "Low".to_string(),
                        bug_type: "VariableShadowing".to_string(),
                        description: format!("Variable `{}` is re-declared here, potentially shadowing a previous declaration.", name),
                        evidence_snippet: trimmed.to_string(),
                        suggested_fix_hint: format!("Consider renaming this variable to avoid confusion with the outer `{}`.", name),
                    });
                }
                if depth == 0 {
                    outer_vars.insert(name);
                }
            }
        }
    }

    bugs
}

fn detect_empty_exception_handlers(file: &str, lang: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        match lang {
            "python" => {
                if (trimmed.starts_with("except") && trimmed.ends_with(':')) || trimmed == "except:"
                {
                    // Check if next non-blank line is just `pass`
                    for j in (i + 1)..lines.len().min(i + 4) {
                        let next = lines[j].trim();
                        if next.is_empty() {
                            continue;
                        }
                        if next == "pass" {
                            bugs.push(StaticBugReport {
                                file: file.to_string(),
                                line: i + 1,
                                column: 1,
                                severity: "Medium".to_string(),
                                bug_type: "SilentExceptionSwallow".to_string(),
                                description: "Bare `except: pass` silently swallows all exceptions, hiding potential bugs.".to_string(),
                                evidence_snippet: format!("{}\n    {}", trimmed, next),
                                suggested_fix_hint: "Specify the exception type and at minimum log the error.".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
            "javascript" | "typescript" => {
                if trimmed.starts_with("catch") && trimmed.contains('{') {
                    // Check if the catch body is empty
                    let next_idx = i + 1;
                    if next_idx < lines.len() {
                        let next = lines[next_idx].trim();
                        if next == "}" || next.is_empty() {
                            bugs.push(StaticBugReport {
                                file: file.to_string(),
                                line: i + 1,
                                column: 1,
                                severity: "Medium".to_string(),
                                bug_type: "SilentExceptionSwallow".to_string(),
                                description: "Empty `catch` block silently swallows errors."
                                    .to_string(),
                                evidence_snippet: trimmed.to_string(),
                                suggested_fix_hint:
                                    "At minimum, log the error inside the catch block.".to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    bugs
}

fn detect_hardcoded_secrets(file: &str, lines: &[&str]) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();
    let secret_re = Regex::new(
        r#"(?i)(password|secret|api_?key|token|auth|credential|private_?key)\s*[=:]\s*["'][^"']{8,}["']"#
    ).unwrap();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }
        // Skip .env.example or config template lines that have placeholder values
        if trimmed.contains("your_") || trimmed.contains("_here") || trimmed.contains("placeholder")
        {
            continue;
        }
        if secret_re.is_match(trimmed) {
            bugs.push(StaticBugReport {
                file: file.to_string(),
                line: i + 1,
                column: 1,
                severity: "Critical".to_string(),
                bug_type: "HardcodedSecret".to_string(),
                description: "Hardcoded credential or secret detected. This should be stored in environment variables or a secrets manager.".to_string(),
                evidence_snippet: redact_secret(trimmed),
                suggested_fix_hint: "Move this value to an environment variable or .env file.".to_string(),
            });
        }
    }

    bugs
}

fn detect_keyword_related_issues(
    file: &str,
    lines: &[&str],
    issue_keywords: &[String],
) -> Vec<StaticBugReport> {
    let mut bugs = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let lower = line.to_lowercase();
        // Check if this line matches issue keywords and contains a comment about a bug
        let has_keyword = issue_keywords.iter().any(|kw| lower.contains(kw));
        if !has_keyword {
            continue;
        }
        let trimmed = line.trim();
        // If this is a comment line with "bug", "wrong", "incorrect", "fix", "broken"
        let bug_indicators = [
            "bug",
            "wrong",
            "incorrect",
            "fix",
            "broken",
            "intentional",
            "should",
        ];
        let is_bug_comment = (trimmed.starts_with("//") || trimmed.starts_with('#'))
            && bug_indicators.iter().any(|ind| lower.contains(ind));

        if is_bug_comment {
            bugs.push(StaticBugReport {
                file: file.to_string(),
                line: i + 1,
                column: 1,
                severity: "High".to_string(),
                bug_type: "IssueKeywordMatch".to_string(),
                description: format!(
                    "This comment matches your issue keywords and indicates a known problem: \"{}\"",
                    trimmed
                ),
                evidence_snippet: trimmed.to_string(),
                suggested_fix_hint: "Review the code following this comment for the bug described.".to_string(),
            });
        }
    }

    bugs
}

// ── Helpers ───────────────────────────────────────────────────────

fn extract_func_name<'a>(line: &'a str, lang: &str) -> Option<&'a str> {
    match lang {
        "python" => {
            if line.starts_with("def ") || line.starts_with("async def ") {
                let start = if line.starts_with("async ") {
                    "async def ".len()
                } else {
                    "def ".len()
                };
                let rest = &line[start..];
                rest.split('(').next().map(|s| s.trim())
            } else {
                None
            }
        }
        "javascript" | "typescript" => {
            if line.starts_with("function ") {
                let rest = &line["function ".len()..];
                rest.split('(').next().map(|s| s.trim())
            } else if line.contains("const ") && (line.contains("=>") || line.contains("function"))
            {
                // const myFunc = ...
                let after_const = line.split("const ").nth(1)?;
                after_const
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
            } else {
                None
            }
        }
        "rust" => {
            if line.starts_with("fn ")
                || line.starts_with("pub fn ")
                || line.starts_with("pub async fn ")
                || line.starts_with("async fn ")
            {
                let after_fn = line.split("fn ").nth(1)?;
                after_fn.split('(').next().map(|s| s.trim())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn contains_arithmetic_op(line: &str, op: &str) -> bool {
    // Look for the operator surrounded by spaces or between identifiers/numbers
    // Avoid matching operators in comments
    let code_part = if let Some(pos) = line.find("//") {
        &line[..pos]
    } else if let Some(pos) = line.find('#') {
        &line[..pos]
    } else {
        line
    };

    // For single-char operators, check they're not part of multi-char operators
    match op {
        "+" => code_part.contains(" + ") || code_part.contains("+"),
        "-" => code_part.contains(" - ") || (code_part.contains('-') && !code_part.contains("->")),
        "*" => code_part.contains(" * ") || code_part.contains('*'),
        "/" => code_part.contains(" / ") || (code_part.contains('/') && !code_part.contains("//")),
        _ => code_part.contains(op),
    }
}

fn is_function_start(line: &str, lang: &str) -> bool {
    match lang {
        "python" => line.starts_with("def ") || line.starts_with("async def "),
        "javascript" | "typescript" => {
            line.starts_with("function ")
                || (line.contains("=>") && (line.contains("const ") || line.contains("let ")))
        }
        "rust" => line.contains("fn ") && (line.starts_with("fn ") || line.starts_with("pub ")),
        _ => false,
    }
}

fn redact_secret(line: &str) -> String {
    // Replace anything after = or : that looks like a secret value
    let re = Regex::new(r#"(["'])[^"']{4}([^"']*)(["'])"#).unwrap();
    re.replace_all(line, "${1}****${3}").to_string()
}

fn language_from_path(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|v| v.to_str()) {
        Some("js") | Some("jsx") => Some("javascript"),
        Some("ts") | Some("tsx") => Some("typescript"),
        Some("py") => Some("python"),
        Some("rs") => Some("rust"),
        Some("go") => Some("go"),
        Some("java") => Some("java"),
        Some("c") | Some("h") => Some("c"),
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => Some("cpp"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_logic_inversion_add_subtract() {
        let lines = vec![
            "def add_numbers(a, b):",
            "    # intentional bug",
            "    return a - b",
        ];
        let bugs = detect_logic_inversion("test.py", "python", &lines);
        assert!(!bugs.is_empty(), "Should detect logic inversion");
        assert_eq!(bugs[0].bug_type, "LogicError");
        assert_eq!(bugs[0].severity, "High");
    }

    #[test]
    fn detects_divide_by_zero() {
        let lines = vec!["x = 10", "y = x / 0"];
        let bugs = detect_divide_by_zero("test.py", "python", &lines);
        assert!(!bugs.is_empty(), "Should detect divide by zero");
        assert_eq!(bugs[0].bug_type, "DivideByZero");
    }

    #[test]
    fn detects_bug_marker_comments() {
        let lines = vec!["# FIXME: this is broken", "x = 1"];
        let bugs = detect_bug_markers("test.py", &lines);
        assert!(!bugs.is_empty());
        assert_eq!(bugs[0].bug_type, "MarkerAnnotation");
    }

    #[test]
    fn detects_empty_except_pass() {
        let lines = vec!["try:", "    do_something()", "except:", "    pass"];
        let bugs = detect_empty_exception_handlers("test.py", "python", &lines);
        assert!(!bugs.is_empty());
        assert_eq!(bugs[0].bug_type, "SilentExceptionSwallow");
    }
}
