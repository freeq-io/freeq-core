# FreeQ binary releases

**Status:** preferred install path  
**Goal:** install FreeQ in seconds without compiling Rust on the user’s machine.

## How it works

1. **CI** (`.github/workflows/release.yml`) builds release binaries for each
   supported target when a `v*` tag is pushed.
2. **Packaging** (`scripts/packaging/freeq-package-release.sh`) creates:

   `freeq-core-vX.Y.Z-<target-triple>.tar.gz`

   containing `bin/`, `scripts/`, and user docs.
3. **Installer** downloads the matching asset for the host and links binaries
   into `~/.freeq/bin`.

## Supported targets

| Target triple | Host |
|---------------|------|
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-apple-darwin` | macOS Intel |
| `x86_64-unknown-linux-gnu` | Linux x86_64 |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |

Platform selection uses **Rust target triples** (`cfg(target_os)` / `uname`),
not optional Cargo features. One binary package is built per triple.

## User install (macOS)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
```

## User install (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash
```

Gateway role (accept-only relay):

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh \
  | FREEQ_ROLE=gateway FREEQ_PUBLIC_ENDPOINT=your.host:51820 bash
```

Environment overrides:

| Variable | Meaning |
|----------|---------|
| `FREEQ_VERSION` | `latest` (default) or `v0.2.1` |
| `FREEQ_FROM_SOURCE` | `1` = git clone + cargo build |
| `FREEQ_BIN_DIR` | binary link dir (default `~/.freeq/bin`) |
| `FREEQ_GITHUB_TOKEN` | optional, higher API rate limits |

## Developer: local package

```bash
cargo build --release -p freeq -p freeqd -p freeq-gateway -p freeq-perf-identity
FREEQ_PACKAGE_SKIP_BUILD=1 scripts/packaging/freeq-package-release.sh
# → dist/freeq-core-v*.tar.gz
```

## Publish a release

From the public release repo (or private with promote):

```bash
git tag -a v0.2.1 -m "FreeQ Core v0.2.1"
git push origin v0.2.1   # private
git push public v0.2.1   # public — triggers Release workflow
```

The Release workflow attaches platform tarballs to the GitHub Release.
