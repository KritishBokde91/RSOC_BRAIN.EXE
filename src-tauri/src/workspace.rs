use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_TOP_LEVEL_ENTRIES_WITHOUT_MARKERS: usize = 160;

const REPOSITORY_MARKERS: &[&str] = &[
    ".git",
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "mix.exs",
    "Makefile",
];

const COMMON_PARENT_DIRECTORY_NAMES: &[&str] = &[
    "Development",
    "development",
    "Projects",
    "projects",
    "Code",
    "code",
    "workspace",
    "Workspace",
    "Desktop",
    "Documents",
    "Downloads",
];

pub fn canonicalize_workspace(workspace_root: &str) -> Result<PathBuf, String> {
    let path = Path::new(workspace_root);
    if !path.exists() {
        return Err("Workspace root does not exist".to_string());
    }
    path.canonicalize()
        .map_err(|error| format!("Failed to resolve workspace root: {error}"))
}

pub fn validate_repository_scope(workspace_root: &Path) -> Result<(), String> {
    if workspace_root == Path::new("/") {
        return Err(
            "Workspace root cannot be `/`. Choose a single project or repository directory."
                .to_string(),
        );
    }

    if let Ok(home_dir) = std::env::var("HOME") {
        let home_path = PathBuf::from(home_dir);
        if workspace_root == home_path {
            return Err(
                "Workspace root points to your home directory. Choose a single project or repository directory instead."
                    .to_string(),
            );
        }
    }

    if has_repository_markers(workspace_root) {
        return Ok(());
    }

    if workspace_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| COMMON_PARENT_DIRECTORY_NAMES.contains(&name))
    {
        return Err(format!(
            "`{}` looks like a broad parent directory. Choose the repository root instead.",
            workspace_root.display()
        ));
    }

    let top_level_entries = fs::read_dir(workspace_root)
        .map_err(|error| {
            format!(
                "Failed to inspect workspace root `{}`: {error}",
                workspace_root.display()
            )
        })?
        .take(MAX_TOP_LEVEL_ENTRIES_WITHOUT_MARKERS + 1)
        .count();

    if top_level_entries > MAX_TOP_LEVEL_ENTRIES_WITHOUT_MARKERS {
        return Err(format!(
            "`{}` does not look like a repository root and has more than {} top-level entries. Choose a single project directory instead.",
            workspace_root.display(),
            MAX_TOP_LEVEL_ENTRIES_WITHOUT_MARKERS
        ));
    }

    Ok(())
}

fn has_repository_markers(workspace_root: &Path) -> bool {
    REPOSITORY_MARKERS
        .iter()
        .any(|marker| workspace_root.join(marker).exists())
}

#[cfg(test)]
mod tests {
    use super::validate_repository_scope;
    use std::{fs, path::PathBuf};

    fn create_temp_directory(test_name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("aetherverify-{test_name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("failed to create temporary test directory");
        root
    }

    #[test]
    fn validate_repository_scope_rejects_broad_parent_without_repo_markers() {
        let workspace = create_temp_directory("broad-parent");
        for index in 0..170 {
            fs::create_dir_all(workspace.join(format!("child-{index}")))
                .expect("failed to create child directory");
        }

        let error = validate_repository_scope(&workspace)
            .expect_err("broad parent directory should be rejected");
        assert!(error.contains("does not look like a repository root"));

        fs::remove_dir_all(&workspace).expect("failed to clean up temporary workspace");
    }

    #[test]
    fn validate_repository_scope_accepts_repo_marker_even_with_many_entries() {
        let workspace = create_temp_directory("repo-root");
        fs::write(workspace.join("package.json"), "{}").expect("failed to write repo marker");
        for index in 0..170 {
            fs::create_dir_all(workspace.join(format!("child-{index}")))
                .expect("failed to create child directory");
        }

        validate_repository_scope(&workspace)
            .expect("directory with repository markers should be accepted");

        fs::remove_dir_all(&workspace).expect("failed to clean up temporary workspace");
    }
}
