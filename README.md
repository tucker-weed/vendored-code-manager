# vendored-code-manager

Rust CLI for managing vendored code in this repository. There are no built-in defaults—every vendor must be provided explicitly via `--url` or already exist under `third_party/`.

## Prerequisites
- Rust toolchain 1.90.0 (enforced via `rust-toolchain.toml`).
- `git` and `diff` available on your PATH.

## Build
```bash
cd vendored-code-manager
cargo build --release
```
The binary lives at `target/release/vendored-code-manager`. You can also run commands with `cargo run -- <command> ...`.

## Install to your CLI toolchain
- From this checkout: `cargo install --path .`
- Can also install directly from GitHub:
  - SSH: `cargo install --git ssh://git@github.com/tucker-weed/vendored-code-manager.git`
  - HTTPS: `cargo install --git https://github.com/tucker-weed/vendored-code-manager.git`
The binary will be placed in `~/.cargo/bin` (ensure that directory is on your `PATH`).

## Commands
- `init --url <git-url> [--url <git-url> ...] [--sha <commit>]` – Clone provided repositories into `../third_party/` and write `README_UPSTREAM.md` for each. `--url` is required when no vendors exist yet; you can repeat it to add multiple repos. `--sha` pins all clones to a specific commit.
- `diff [--force]` – Generate unified diffs between each local vendor and upstream `HEAD`, writing `../<repo>.diff` per project. Each diff file now includes a header with local/remote SHAs and the commit messages between them. Requires at least one vendored repo in `third_party/`.
- `revendor [--sha <commit>] [--force]` – Replace local vendors with the specified commit (or upstream `HEAD`) and refresh README metadata for all discovered vendors.
- `status` – Report discovered third-party directories plus local vs upstream SHAs for each known repo.

### Examples
### Using the installed binary (recommended)
If you installed via `cargo install`, the binary `vendored-code-manager` will be on your `PATH`:
```bash
vendored-code-manager init --url https://github.com/example/some-lib.git
vendored-code-manager init --url https://github.com/example/some-lib.git --url https://github.com/example/other-lib.git --sha <commit>
vendored-code-manager status
vendored-code-manager diff
vendored-code-manager revendor --sha <commit>
```

### Using cargo run (no install)
```bash
cargo run -p vendored-code-manager -- init --url https://github.com/example/some-lib.git
cargo run -p vendored-code-manager -- init --url https://github.com/example/some-lib.git --url https://github.com/example/other-lib.git --sha <commit>
cargo run -p vendored-code-manager -- status
cargo run -p vendored-code-manager -- diff
cargo run -p vendored-code-manager -- revendor --sha <commit>
```

### Notes
- There are no default repositories. If `third_party/` is empty, `init` requires at least one `--url`.
- Paths are resolved relative to your current working directory (it searches upward for `third_party`, `pyproject.toml`, or `scripts/vendor_manager.py`); use `--root <path>` to override.
- `diff` accepts `--force` to regenerate even when local and upstream SHAs match; `revendor` accepts `--force` to re-copy the same commit.
