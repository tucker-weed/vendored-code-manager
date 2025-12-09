use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Local;
use clap::{Parser, Subcommand};
use tempfile::TempDir;

#[derive(Parser)]
#[command(
    name = "vendored-code-manager",
    about = "Manage vendored ADK dependencies."
)]
struct Cli {
    /// Override repository root (defaults to discovering from the binary location or working directory)
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate diffs between local vendored copies and upstream HEAD
    Diff {
        /// Force diff even if SHAs match
        #[arg(long)]
        force: bool,
    },
    /// Re-vendor repositories to latest (or specified) upstream commit
    Revendor {
        /// Force re-vendoring even if SHAs match
        #[arg(long)]
        force: bool,
        /// Specific commit SHA to vendor (defaults to upstream HEAD)
        #[arg(long)]
        sha: Option<String>,
    },
    /// Bootstrap missing third-party repositories
    Init {
        /// Specific commit SHA to vendor when bootstrapping (defaults to upstream HEAD)
        #[arg(long)]
        sha: Option<String>,
        /// Additional git URLs to bootstrap into third_party (can be repeated)
        #[arg(long = "url", value_name = "GIT_URL", num_args = 0.., action = clap::ArgAction::Append)]
        extra_urls: Vec<String>,
    },
    /// Show local vs upstream status and discovered third-party contents
    Status,
}

#[derive(Clone)]
struct Repo {
    name: String,
    pretty: String,
    upstream: String,
    local_dir: PathBuf,
    readme: PathBuf,
    diff_out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = resolve_root(cli.root.as_deref())?;
    let repos = build_repos(&root);

    match cli.command {
        Commands::Diff { force } => diff_repos(&repos, &root, force)?,
        Commands::Revendor { force, sha } => revendor_repos(&repos, &root, force, sha.as_deref())?,
        Commands::Init { sha, extra_urls } => {
            init_repos(&repos, &root, sha.as_deref(), &extra_urls)?
        }
        Commands::Status => status(&repos, &root)?,
    }

    Ok(())
}

fn resolve_root(provided: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = provided {
        return path
            .canonicalize()
            .context("Failed to canonicalize provided --root path");
    }

    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    for anc in cwd.ancestors() {
        if anc.join("third_party").exists()
            || anc.join("pyproject.toml").exists()
            || anc.join("scripts").join("vendor_manager.py").exists()
        {
            return Ok(anc.to_path_buf());
        }
    }

    let compiled_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest dir always has a parent")
        .to_path_buf();

    if compiled_root.join("third_party").exists()
        || compiled_root.join("pyproject.toml").exists()
        || compiled_root
            .join("scripts")
            .join("vendor_manager.py")
            .exists()
    {
        return Ok(compiled_root);
    }

    bail!(
        "Unable to locate repository root from current directory; pass --root <path> explicitly."
    );
}

fn build_repos(root: &Path) -> Vec<Repo> {
    let third_party = root.join("third_party");
    let mut repos = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(discovered) = discover_repos(&third_party, root) {
        for repo in discovered {
            if seen.insert(repo.local_dir.clone()) {
                repos.push(repo);
            }
        }
    }

    repos
}

fn repo_from_url(url: &str, root: &Path) -> Result<Repo> {
    let name = derive_repo_name(url)?;
    let third_party = root.join("third_party");
    let local_dir = third_party.join(&name);
    Ok(Repo {
        pretty: name.replace('_', " ").replace('-', " "),
        name,
        upstream: url.to_string(),
        local_dir: local_dir.clone(),
        readme: local_dir.join("README_UPSTREAM.md"),
        diff_out: root.join(format!(
            "{}.diff",
            local_dir.file_name().unwrap().to_string_lossy()
        )),
    })
}

fn derive_repo_name(url: &str) -> Result<String> {
    let mut trimmed = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow!("Cannot parse repository name from URL: {}", url))?
        .to_string();
    if let Some(stripped) = trimmed.strip_suffix(".git") {
        trimmed = stripped.to_string();
    }
    if trimmed.is_empty() {
        bail!("Cannot parse repository name from URL: {}", url);
    }
    Ok(trimmed)
}

fn discover_repos(third_party: &Path, root: &Path) -> Result<Vec<Repo>> {
    let mut repos = Vec::new();
    if !third_party.exists() {
        return Ok(repos);
    }

    for entry in fs::read_dir(third_party).context("read third_party")? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let readme = path.join("README_UPSTREAM.md");
        let (upstream, _) = match parse_readme_meta(&readme) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let upstream = match upstream {
            Some(u) => u,
            None => continue,
        };

        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        repos.push(Repo {
            name: name.clone(),
            pretty: name.replace('_', " ").replace('-', " "),
            upstream,
            local_dir: path.clone(),
            readme,
            diff_out: root.join(format!("{}.diff", name)),
        });
    }

    Ok(repos)
}

fn diff_repos(repos: &[Repo], root: &Path, force: bool) -> Result<()> {
    let third_party = root.join("third_party");
    if !third_party.exists() {
        println!(
            "third_party directory missing at {}. Run `init` to bootstrap vendors first.",
            third_party.display()
        );
        return Ok(());
    }

    if repos.is_empty() {
        println!(
            "No vendored repositories found in third_party. Run `init --url <git-url>` to add one."
        );
        return Ok(());
    }

    for repo in repos {
        if let Err(err) = diff_repo(repo, root, force) {
            eprintln!("[{}] diff failed: {}", &repo.name, err);
        }
    }
    Ok(())
}

fn diff_repo(repo: &Repo, root: &Path, force: bool) -> Result<()> {
    let local_sha = parse_local_sha(&repo.readme)?;
    let remote_sha = fetch_remote_head_sha(&repo.upstream)?;

    if local_sha.as_deref() == Some(remote_sha.as_str()) && !force {
        println!(
            "[{}] Up to date ({}); no diff generated.",
            &repo.name, remote_sha
        );
        return Ok(());
    }

    if !repo.local_dir.exists() {
        println!(
            "[{}] Local directory missing at {}; run `init` to fetch it first.",
            &repo.name,
            repo.local_dir.display()
        );
        return Ok(());
    }

    let tmp_dir = TempDir::new().context("create temp dir for diff")?;
    let clone_path = tmp_dir.path().join(&repo.name);
    git_clone(&repo.upstream, &clone_path)?;

    let commit_log = build_commit_log(&clone_path, local_sha.as_deref(), &remote_sha)?;
    let diff_body = generate_diff(&repo.local_dir, &clone_path)?;
    write_diff_file(
        &repo.diff_out,
        local_sha.as_deref(),
        &remote_sha,
        commit_log.as_deref(),
        &diff_body,
        root,
    )?;
    println!(
        "[{}] Local {} -> Remote {}; diff written to {}",
        &repo.name,
        local_sha.unwrap_or_else(|| "unknown".to_string()),
        remote_sha,
        display_relative(&repo.diff_out, root)
    );

    Ok(())
}

fn revendor_repos(
    repos: &[Repo],
    root: &Path,
    force: bool,
    target_sha: Option<&str>,
) -> Result<()> {
    ensure_dir(&root.join("third_party"))?;

    if repos.is_empty() {
        println!("No vendored repositories to re-vendor. Run `init --url <git-url>` first.");
        return Ok(());
    }

    for repo in repos {
        if let Err(err) = revendor_repo(repo, root, force, target_sha) {
            eprintln!("[{}] revendor failed: {}", &repo.name, err);
        }
    }
    Ok(())
}

fn revendor_repo(repo: &Repo, root: &Path, force: bool, target_sha: Option<&str>) -> Result<()> {
    let current_sha = parse_local_sha(&repo.readme)?;
    let desired_sha = match target_sha {
        Some(sha) => sha.to_string(),
        None => fetch_remote_head_sha(&repo.upstream)?,
    };

    if current_sha.as_deref() == Some(desired_sha.as_str()) && !force {
        println!(
            "[{}] Already at {}; skipping (use --force to re-vendor).",
            &repo.name, desired_sha
        );
        return Ok(());
    }

    println!(
        "[{}] Re-vendoring to {} (was {}).",
        &repo.name,
        desired_sha,
        current_sha.as_deref().unwrap_or("unknown")
    );

    let tmp_dir = TempDir::new().context("create temp dir for revendor")?;
    let clone_path = tmp_dir.path().join(&repo.name);
    git_clone(&repo.upstream, &clone_path)?;
    if let Some(sha) = target_sha {
        git_checkout(&clone_path, sha)?;
    }
    let actual_sha = git_rev_parse_head(&clone_path)?;

    if repo.local_dir.exists() {
        fs::remove_dir_all(&repo.local_dir)
            .with_context(|| format!("remove {}", repo.local_dir.display()))?;
    }
    ensure_dir(repo.local_dir.parent().unwrap())?;
    fs::rename(&clone_path, &repo.local_dir)
        .with_context(|| format!("move new vendor into {}", repo.local_dir.display()))?;

    ensure_dir(repo.readme.parent().unwrap())?;
    write_readme(&repo.readme, repo, &actual_sha, root)?;
    println!(
        "[{}] Updated vendor at {}",
        &repo.name,
        repo.local_dir.display()
    );

    Ok(())
}

fn init_repos(
    repos: &[Repo],
    root: &Path,
    target_sha: Option<&str>,
    extra_urls: &[String],
) -> Result<()> {
    ensure_dir(&root.join("third_party"))?;

    let mut targets: Vec<Repo> = repos.to_vec();
    for url in extra_urls {
        match repo_from_url(url, root) {
            Ok(extra_repo) => {
                if targets.iter().any(|r| r.local_dir == extra_repo.local_dir) {
                    println!(
                        "[{}] Already tracked at {}; skipping duplicate URL {}",
                        &extra_repo.name,
                        extra_repo.local_dir.display(),
                        url
                    );
                } else {
                    targets.push(extra_repo);
                }
            }
            Err(err) => {
                eprintln!("[extra] Skipping invalid URL {}: {}", url, err);
            }
        }
    }

    if targets.is_empty() {
        println!(
            "No repositories specified or discovered. Provide at least one with `--url <git-url>`."
        );
        return Ok(());
    }

    for repo in targets {
        if repo.local_dir.exists() {
            println!(
                "[{}] Already present at {}; skipping.",
                &repo.name,
                repo.local_dir.display()
            );
            continue;
        }

        let desired_sha = match target_sha {
            Some(sha) => sha.to_string(),
            None => fetch_remote_head_sha(&repo.upstream)?,
        };

        println!(
            "[{}] Bootstrapping (target commit {}).",
            &repo.name, desired_sha
        );

        let tmp_dir = TempDir::new().context("create temp dir for init")?;
        let clone_path = tmp_dir.path().join(&repo.name);
        git_clone(&repo.upstream, &clone_path)?;
        if let Some(sha) = target_sha {
            git_checkout(&clone_path, sha)?;
        }
        let actual_sha = git_rev_parse_head(&clone_path)?;

        ensure_dir(repo.local_dir.parent().unwrap())?;
        fs::rename(&clone_path, &repo.local_dir)
            .with_context(|| format!("move {} into {}", &repo.name, repo.local_dir.display()))?;

        ensure_dir(repo.readme.parent().unwrap())?;
        write_readme(&repo.readme, &repo, &actual_sha, root)?;
        println!(
            "[{}] Vendored into {}",
            &repo.name,
            display_relative(&repo.local_dir, root)
        );
    }

    Ok(())
}

fn status(repos: &[Repo], root: &Path) -> Result<()> {
    println!("Root: {}", root.display());
    let third_party = root.join("third_party");
    if third_party.exists() {
        let entries = third_party_entries(&third_party)?;
        if entries.is_empty() {
            println!("third_party contains no projects yet.");
        } else {
            println!("third_party projects: {}", entries.join(", "));
        }
    } else {
        println!(
            "third_party missing at {} (will be created on init/revendor).",
            third_party.display()
        );
    }

    for repo in repos {
        let local_present = repo.local_dir.exists();
        let local_sha = parse_local_sha(&repo.readme)?;
        let remote_sha = fetch_remote_head_sha(&repo.upstream).ok();

        println!(
            "[{}] present: {} | local SHA: {} | remote HEAD: {} | path: {}",
            &repo.name,
            if local_present { "yes" } else { "no" },
            local_sha.unwrap_or_else(|| "unknown".to_string()),
            remote_sha.unwrap_or_else(|| "unavailable".to_string()),
            display_relative(&repo.local_dir, root)
        );
    }

    Ok(())
}

fn parse_local_sha(readme: &Path) -> Result<Option<String>> {
    parse_readme_meta(readme).map(|(_, sha)| sha)
}

fn parse_readme_meta(readme: &Path) -> Result<(Option<String>, Option<String>)> {
    if !readme.exists() {
        return Ok((None, None));
    }

    let contents =
        fs::read_to_string(readme).with_context(|| format!("read {}", readme.display()))?;
    let mut upstream = None;
    let mut sha = None;

    for line in contents.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("- upstream repository:") {
            upstream = line
                .split_once(':')
                .map(|(_, rest)| rest.trim().to_string());
        }
        if lower.starts_with("- commit:") {
            sha = line
                .split_once(':')
                .map(|(_, rest)| rest.trim().to_string());
        }
    }

    Ok((upstream, sha))
}

fn fetch_remote_head_sha(url: &str) -> Result<String> {
    let output = run_capture(Command::new("git").args(["ls-remote", url, "HEAD"]))?;
    let sha = output.split_whitespace().next().unwrap_or("").to_string();
    if sha.is_empty() {
        bail!("Failed to parse remote HEAD for {}", url);
    }
    Ok(sha)
}

fn git_clone(url: &str, dest: &Path) -> Result<()> {
    run(Command::new("git").args([
        "clone",
        "--depth",
        "1",
        url,
        dest.to_string_lossy().as_ref(),
    ]))
    .with_context(|| format!("clone {}", url))
}

fn git_checkout(repo_dir: &Path, sha: &str) -> Result<()> {
    run(Command::new("git")
        .current_dir(repo_dir)
        .args(["checkout", sha]))
    .with_context(|| format!("checkout {}", sha))
}

fn git_rev_parse_head(repo_dir: &Path) -> Result<String> {
    run_capture(
        Command::new("git")
            .current_dir(repo_dir)
            .args(["rev-parse", "HEAD"]),
    )
}

fn git_fetch_ref(repo_dir: &Path, reference: &str) -> Result<()> {
    run(Command::new("git")
        .current_dir(repo_dir)
        .args(["fetch", "--depth", "2000", "origin", reference]))
}

fn generate_diff(local_dir: &Path, remote_dir: &Path) -> Result<String> {
    let output = Command::new("diff")
        .args([
            "-ruN",
            local_dir.to_string_lossy().as_ref(),
            remote_dir.to_string_lossy().as_ref(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("run diff")?;

    if !(output.status.success() || output.status.code() == Some(1)) {
        bail!("diff command failed with status {:?}", output.status.code());
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn write_readme(readme_path: &Path, repo: &Repo, sha: &str, root: &Path) -> Result<()> {
    let today = Local::now().date_naive();
    let relative_dir = repo
        .local_dir
        .strip_prefix(root)
        .unwrap_or(&repo.local_dir)
        .display();

    let content = format!(
        "# {} (vendored)\n\n- Upstream repository: {}\n- Commit: {} (fetched {})\n- Files vendored: entire repository contents placed under `{}/`\n- Local modifications: none (kept read-only; wrap via adapters in `src/promptgraphtools/adk_runtime/`)\n\nThis copy is provided under the upstream Apache-2.0 license (see `LICENSE` in this directory).\n",
        repo.pretty, repo.upstream, sha, today, relative_dir
    );

    fs::write(readme_path, content).with_context(|| format!("write {}", readme_path.display()))
}

fn build_commit_log(
    upstream_clone: &Path,
    local_sha: Option<&str>,
    remote_sha: &str,
) -> Result<Option<String>> {
    // Ensure we have the local commit in the clone so the range is valid.
    if let Some(local) = local_sha {
        if let Err(err) = git_fetch_ref(upstream_clone, local) {
            eprintln!(
                "[warn] failed to fetch local commit {} into temp clone: {}",
                local, err
            );
        }
    }

    let range = match local_sha {
        Some(local) => format!("{}..{}", local, remote_sha),
        None => format!("{}", remote_sha),
    };

    let args = if local_sha.is_some() {
        vec!["log", "--oneline", "--no-decorate", "--reverse", &range]
    } else {
        vec!["log", "--oneline", "--no-decorate", "-n", "50"]
    };

    match run_capture(Command::new("git").current_dir(upstream_clone).args(args)) {
        Ok(log) => Ok(Some(log)),
        Err(_) => Ok(None),
    }
}

fn write_diff_file(
    out_file: &Path,
    local_sha: Option<&str>,
    remote_sha: &str,
    commit_log: Option<&str>,
    diff_body: &str,
    root: &Path,
) -> Result<()> {
    ensure_dir(out_file.parent().unwrap())?;
    let mut file =
        File::create(out_file).with_context(|| format!("open {}", out_file.display()))?;

    writeln!(file, "# Vendored diff")?;
    writeln!(
        file,
        "# Local SHA: {}",
        local_sha.unwrap_or("unknown (not recorded in README_UPSTREAM.md)")
    )?;
    writeln!(file, "# Remote SHA: {}", remote_sha)?;
    writeln!(file, "# Generated: {}", Local::now())?;
    writeln!(file, "# Path: {}", display_relative(out_file, root))?;
    writeln!(file, "# Commits between local -> remote (if available):")?;
    match commit_log {
        Some(log) if !log.trim().is_empty() => {
            for line in log.lines() {
                writeln!(file, "#   {}", line)?;
            }
        }
        _ => writeln!(file, "#   <unavailable>")?,
    }
    writeln!(file, "# --- BEGIN DIFF ---")?;
    file.write_all(diff_body.as_bytes())?;
    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().context("failed to start command")?;
    if status.success() {
        Ok(())
    } else {
        bail!("command exited with status {:?}", status.code());
    }
}

fn run_capture(cmd: &mut Command) -> Result<String> {
    let output = cmd.output().context("failed to start command")?;
    if !output.status.success() {
        bail!("command exited with status {:?}", output.status.code());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create dir {}", path.display()))
}

fn third_party_entries(third_party: &Path) -> Result<Vec<String>> {
    if !third_party.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in
        fs::read_dir(third_party).with_context(|| format!("read {}", third_party.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn display_relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}
