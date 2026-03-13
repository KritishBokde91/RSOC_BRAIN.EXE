// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Load .env from the project root (two levels up from src-tauri/src/)
    // before any env::var() calls in the application.
    dotenvy::from_filename(
        std::env::current_dir()
            .unwrap_or_default()
            .parent()
            .map(|p| p.join(".env"))
            .unwrap_or_else(|| std::path::PathBuf::from(".env")),
    )
    .ok();
    // Also try CWD .env as fallback
    dotenvy::dotenv().ok();

    aetherverify_lib::run()
}
