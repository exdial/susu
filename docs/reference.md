# susu reference

This document is the detailed user and CLI reference for `susu`. For a short introduction and quick start, see the [README](../README.md).

`susu` is a small Unix CLI for keeping selected dotfiles in a Git repository and restoring them on another machine. Public files are copied into the repository; files explicitly added with `--sensitive` are encrypted before they enter repository storage.

`susu` deliberately has a narrow responsibility:

- `susu` manages dotfile entries and their stored contents.
- Git manages commits, branches, remotes, pushes, pulls, merges, and history.

Available commands are `init`, `add`, `rm`, `list`, `show`, and `apply`.

## Supported platforms

`susu` supports the Go platform values:

- `darwin` (macOS)
- `linux`

Use those exact values with `--exclude-platform`. Other operating systems and platform names are not supported.

## Build and install

Prebuilt `.tar.gz` archives are published on the [GitHub Releases](https://github.com/exdial/susu/releases) page for Linux and macOS on both `amd64` and `arm64`. Every release also publishes `checksums.txt`; each archive contains the `susu` binary, `README.md`, `LICENSE`, and `CHANGELOG.md`.

To build from source, the module requires Go 1.26. The included `mise.toml` pins a compatible Go toolchain.

From the repository root, build with mise:

```bash
mise install
mise exec -- make
```

Or use an already installed compatible Go toolchain:

```bash
make
```

The Makefile builds a minimal `./susu` executable with CGO disabled, filesystem and VCS paths omitted, and linker symbols and DWARF data stripped. Remove the binary with `make clean`.

To build and install the binary with Go:

```bash
make install
```

When using the pinned mise toolchain, run `mise exec -- make install` instead. The target uses `go install`, which writes `susu` to `GOBIN` or, when `GOBIN` is unset, to the `bin` directory under `go env GOPATH`. To install into `$HOME/.local/bin` explicitly:

```bash
GOBIN="$HOME/.local/bin" make install
```

Ensure the selected binary directory is on `PATH`. Release maintainers should follow the [release procedure](releasing.md).

## Quick start

The repository passed to `susu init` must already be the root of a Git repository. This example creates one, adds public, platform-specific, and sensitive files, and then commits the result with Git:

```bash
mkdir -p "$HOME/src"
git init "$HOME/src/dotfiles"

susu init "$HOME/src/dotfiles"

susu add "$HOME/.zshrc"
susu add "$HOME/.gitconfig" "$HOME/.vimrc"
susu add --exclude-platform linux "$HOME/.hammerspoon/init.lua"
susu add --sensitive "$HOME/.kube/config"

susu list

git -C "$HOME/src/dotfiles" status --short
git -C "$HOME/src/dotfiles" add susu.json public encrypted
git -C "$HOME/src/dotfiles" commit -m "Manage dotfiles with susu"
```

The first operation that needs sensitive storage asks for a repository password and confirmation. The password is not requested by `init` and is never stored.

On another machine, let Git retrieve the repository and let `susu` restore the files:

```bash
git clone <repository-url> "$HOME/src/dotfiles"

susu init "$HOME/src/dotfiles"
susu list
susu apply
```

If applicable sensitive entries exist, `apply` asks once for the repository password. Entries excluded for the current platform are skipped.

## Command overview

| Command | Meaning | Data direction |
| --- | --- | --- |
| `susu init <repository>` | Initialize and select a dotfiles repository | repository path -> local binding |
| `susu add [options] <path...>` | Start managing files | filesystem -> repository |
| `susu rm <path...>` | Stop managing files | removes repository entries and copies |
| `susu list` | List managed logical paths | manifest -> stdout |
| `susu show <path>` | Print a stored file | repository -> stdout |
| `susu apply` | Restore applicable managed files | repository -> filesystem |

### `susu init`

```bash
susu init "$HOME/src/dotfiles"
```

`init`:

1. resolves the supplied path to a canonical absolute path;
2. verifies that it exists;
3. verifies that it is a Git repository and that the supplied path is its root;
4. creates `susu.json`, `public/`, and `encrypted/` as needed; and
5. stores a local binding so later commands know which repository to use.

The binding is machine-local; it is not written into the dotfiles repository. Running a repository-dependent command before `init`, or after the configured repository has disappeared, is an error.

`git` is resolved through `PATH`. For root validation and Git common-directory discovery, `susu` removes inherited repository-local and discovery variables such as `GIT_DIR`, `GIT_WORK_TREE`, and `GIT_COMMON_DIR` from the child process environment. These variables therefore cannot redirect the supplied path to another repository or move the `susu` lock into another administrative directory.

`init` does not perform `git init`, clone a remote, or ask for an encryption password. Encryption is initialized lazily by the first sensitive operation.

### `susu add`

Add one or more files:

```bash
susu add "$HOME/.zshrc"
susu add "$HOME/.gitconfig" "$HOME/.vimrc"
```

Add a directory recursively:

```bash
susu add "$HOME/.vim"
```

A directory is expanded into one manifest entry per discovered file. The directory itself is not stored as an opaque entry.

`add` means **start managing**, not synchronize. For each new file it resolves the path, derives a portable logical destination, copies or encrypts its current contents into the repository, and adds an entry to `susu.json`. If an input is already managed, its entry is not duplicated and its stored contents are not silently overwritten. In a mixed invocation, new inputs can still be added while existing entries remain unchanged.

Candidate identity is taken from an opened, validated regular-file descriptor. A different logical path that identifies the same physical regular file as an existing managed destination is reported as already managed; it does not inherit new sensitivity or exclusions, create a source, or request a password. The existing managed leaf is inspected without following a leaf symlink, so a symlink target does not become managed by association. If two new logical candidates in one invocation identify the same file, the entire invocation fails instead of choosing one identity. This detects hard links and any case or normalization aliases that the active filesystem exposes.

The active private `susu` state directory, active repository worktree, and Git common administrative directory are never valid managed inputs. `add` rejects each protected root, every path inside it, and any ancestor input that contains it. Canonical, symlink, physical, and case aliases exposed by the filesystem are checked; the finite set of protected local-state files is also checked by opened-file identity so hard-linked aliases cannot be captured. Direct and ancestor overlaps are rejected before directory walking or a sensitive password prompt. After any required password callback, `add` reopens and validates every new candidate before reading any candidate content or writing any repository source. It repeats the command-wide identity and boundary check before every candidate read, reads from the same descriptor that passed validation, and checks once more before committing `susu.json`. A password-time or later substitution therefore fails before commit; sources created earlier in the invocation are rolled back. Use a narrower input path outside the protected control roots.

Public files use a Git-portable mode policy: non-executable files are stored and applied as `0644`, while files with any executable bit are stored and applied as `0755`. Git does not preserve arbitrary Unix permission bits. Sensitive destinations always use `0600`.

#### Built-in ignored paths

`~/.kube/cache` is generated Kubernetes client cache data and is not manageable. `add` resolves this location from the configured HOME independently of XDG normalization, skips its real directory and physical/case aliases during recursive walking, and ignores explicitly supplied regular files or real directories at or below it. Similar names such as `~/.kube/cache.yaml` and `~/.kube/caches/` remain ordinary candidates. An invocation containing only ignored cache paths makes no repository change and does not request a sensitive password. Explicit symlinks and special files continue to follow the normal object policy below and are rejected rather than silently ignored.

Existing manifests created by earlier versions are not rewritten automatically; the exclusion affects only new `add` candidate discovery.

#### Symlinks and special files

The behavior is intentionally conservative:

- Recursive directory walking skips every symlink, including symlinks to regular files and directories. It never follows them.
- Supplying a path that is a symlink or traverses a symlink component is an error, whether the link is valid, broken, points to a file, or points to a directory.
- Supplying a FIFO, socket, device, or other non-regular special path explicitly is also an error; such entries encountered during a directory walk are skipped.
- `apply` confines every destination operation to its resolved HOME or XDG root. A leaf symlink at a managed destination is atomically replaced by a regular file; symlinks in parent components are rejected.

This policy prevents a recursively added tree from copying the contents of an unexpected symlink target into the repository.

#### Protected local control roots

Three runtime-specific locations are reserved:

```text
$XDG_STATE_HOME/susu/          # state.json, lock, and state staging files
<active-repository>/          # the complete bound worktree
<git-common-directory>/       # shared Git metadata and susu.lock
```

The state fallback is `~/.local/state/susu/`. In an ordinary repository the Git common directory is normally `<active-repository>/.git` and is already inside the protected worktree. For a linked worktree it can be elsewhere, so `susu` resolves and protects it separately. A sibling outside these exact roots remains manageable unless it is a hard-linked alias of one of the finite protected local-state files.

Repositories created by older versions may already contain entries targeting a now-protected root. `list` and `show` can inspect them, `rm` can remove them, and `apply` refuses an applicable protected destination until it is removed. An entry excluded on the current platform remains skipped.

#### Shell expansion

The shell normally expands `~` and wildcard patterns before `susu` receives its arguments. `susu` does not implement its own glob language. For example:

```bash
susu add ~/.bashrc.*
```

The shell decides which matching paths are passed. Quote paths containing spaces:

```bash
susu add "$HOME/Library/Application Support/MTMR/items.json"
```

### Sensitive files: `--sensitive`

Mark sensitive inputs explicitly:

```bash
susu add --sensitive "$HOME/.kube/config"
susu add --sensitive "$HOME/.ssh"
```

A sensitive directory is expanded into individually encrypted file entries. Sensitive plaintext is never copied into the repository or a plaintext temporary file. The only repository copy is ciphertext under `encrypted/`.

There is one password and one random 32-byte master key per repository. On the first sensitive operation, `susu` asks for the password and confirmation using a TTY with echo disabled, creates the encryption metadata, and encrypts the input. Later sensitive operations unlock the same master key with one password prompt per invocation. There is no password or key cache.

See the [encryption and security model](security-model.md) for the encryption design and threat model.

### Platform exclusions: `--exclude-platform`

Associate exclusions with every file added by an invocation:

```bash
susu add --exclude-platform linux "$HOME/.hammerspoon/init.lua"
susu add --exclude-platform linux "$HOME/Library/Application Support/MTMR/items.json"
susu add --exclude-platform darwin "$HOME/.config/a-linux-only-tool/config"
```

The flag accepts only `darwin` and `linux` and may be repeated. Exclusions are stored per entry in `susu.json`. `apply` skips an entry when its exclusions include the current `runtime.GOOS` value.

`susu` does not infer exclusions from path names. For example, a path under `~/Library` is not automatically marked macOS-only; add the exclusion explicitly.

### `susu rm`

Stop managing one or more files:

```bash
susu rm "$HOME/.zshrc"
susu rm "$HOME/.gitconfig" "$HOME/.vimrc"
```

`rm` removes each matching entry from `susu.json` and deletes its stored `public/...` or `encrypted/...enc` repository file. It does **not** delete the original destination from your home or XDG directory.

For example, removing `~/.zshrc` deletes `public/.zshrc` but leaves `~/.zshrc` in place. Git remains responsible for recording that repository change and for retaining or removing older versions from Git history.

### `susu list`

```bash
susu list
```

`list` answers “what files does this repository manage?” using portable logical paths. Output is human-readable and includes relevant entry labels, for example:

```text
~/.bashrc
~/.gitconfig
~/.kube/config [sensitive]
~/.hammerspoon/init.lua [exclude: linux]
${XDG_CONFIG_HOME}/starship.toml
```

It does not expose cryptographic implementation details.

### `susu show`

Print one stored entry to standard output:

```bash
susu show "$HOME/.gitconfig"
susu show "$HOME/.kube/config"
```

For a public entry, `show` reads the repository copy. For a sensitive entry, it prompts for the repository password, authenticates and decrypts the ciphertext in memory, and writes plaintext to stdout. It does not modify the destination, invoke `apply`, create a plaintext temporary file, or leave a decrypted repository copy.

Treat sensitive stdout carefully. Redirecting or piping `susu show` can disclose plaintext to another file, process, terminal log, or scrollback buffer.

`show` accepts one path per invocation.

### `susu apply`

```bash
susu apply
```

`apply` restores the repository snapshot to the local filesystem:

- public entries are copied from `public/...`;
- sensitive entries are authenticated and decrypted directly to their destinations;
- entries excluded for the current platform are skipped;
- applicable destinations overlapping the active private `susu` state directory, active repository worktree, or Git common administrative directory are rejected;
- destinations that alias or are ancestors of one another under the selected platform's comparison rules are rejected;
- required parent directories are created; and
- destination creation and replacement use safe semantics rather than exposing partial results.

Platform filtering and the first protected-destination and alias checks happen before repository-source access or a password prompt. Therefore an excluded protected or aliased entry is skipped normally, while an applicable conflict aborts the invocation without changing any destination. If one or more remaining sensitive entries exist, the password is read once and the unlocked master key is reused only in that process. The complete destination set is checked again immediately after unlock, after every source has been preflighted and every ciphertext authenticated in memory, and before each replacement. Protected-root errors take priority over alias errors at every checkpoint.

For `darwin`, comparison canonicalizes only the configured HOME/XDG root, appends the untouched relative destination, then applies canonical Unicode normalization and locale-independent case folding to each path component. This deliberately fails closed even on a case-sensitive macOS volume. For `linux`, component spelling remains distinct. The comparison never resolves the complete destination, so a managed leaf symlink can still be replaced as a directory entry rather than being confused with its target. Logical manifest identities and the logical-path AAD used for sensitive files are not rewritten.

Portable atomic replacement on both macOS and Linux requires a short-lived, randomly named staging file next to the final destination. For sensitive entries it is created as `0600`, written only after authentication, synced, and atomically renamed. Each replacement tracks only the exact staging name it created and makes a best-effort attempt to remove that name on ordinary failures before rename. A crash or power loss can leave a `.susu-apply-<24 hex characters>.tmp` plaintext residue. Later `apply` invocations do not delete it or any other neighboring staging-like file because ownership cannot be established safely; inspect and remove confirmed residue manually. Atomicity is per destination: an I/O failure after earlier renames can leave those earlier files applied, and the CLI reports them before returning the error.

`apply` is a restore operation and can replace managed destination files. `susu` does not provide `status`, `diff`, automatic conflict handling, or backups, so review `susu list` and your repository changes before applying.

## XDG behavior

Portable logical paths are distinct from the filesystem paths used on a particular machine.

Anything managed under the effective config home is represented with `${XDG_CONFIG_HOME}` in `susu.json`. For example, adding either a file under a configured `XDG_CONFIG_HOME` or the default `~/.config` location produces a logical destination such as:

```text
${XDG_CONFIG_HOME}/starship.toml
```

At runtime it resolves as follows:

```text
XDG_CONFIG_HOME is set   -> ${XDG_CONFIG_HOME}/starship.toml
XDG_CONFIG_HOME is unset -> ~/.config/starship.toml
```

The repository storage path remains stable and separate, for example `public/.config/starship.toml`. Machine-specific paths such as `/Users/alex/.zshrc` or `/home/alex/.zshrc` are not stored in the portable manifest.

The active repository binding uses the XDG state location:

```text
$XDG_STATE_HOME/susu/state.json
```

If `XDG_STATE_HOME` is unset, the fallback is:

```text
~/.local/state/susu/state.json
```

That state file contains the canonical repository path for this machine and must not be committed to the dotfiles repository. `susu init` requires the complete private state directory to remain disjoint from both the selected worktree and its Git common administrative directory. All three roots are rejected by `add` and protected from applicable `apply` destinations. A private sibling `lock` protects binding changes, while `susu.lock` in Git's common administrative directory serializes repository operations across different local state homes. Neither lock is committed.

## Repository layout

`susu` keeps portable metadata, public snapshots, and encrypted snapshots inside the Git repository while preserving destination-shaped directory structure:

```text
dotfiles/
├── susu.json
├── public/
│   ├── .zshrc
│   ├── .gitconfig
│   ├── .vimrc
│   └── .config/
│       ├── starship.toml
│       └── wezterm/
│           └── wezterm.lua
└── encrypted/
    ├── .kube/
    │   └── config.enc
    └── .config/
        └── sops/
            └── age/
                └── keys.txt.enc
```

Directories are not flattened. Each stored file corresponds to one entry in `susu.json`.

### Example `susu.json`

```json
{
  "version": 1,
  "entries": [
    {
      "path": "~/.zshrc",
      "source": "public/.zshrc"
    },
    {
      "path": "${XDG_CONFIG_HOME}/starship.toml",
      "source": "public/.config/starship.toml"
    },
    {
      "path": "~/.kube/config",
      "source": "encrypted/.kube/config.enc",
      "sensitive": true
    },
    {
      "path": "~/.hammerspoon/init.lua",
      "source": "public/.hammerspoon/init.lua",
      "excludePlatforms": [
        "linux"
      ]
    }
  ]
}
```

When sensitive storage is initialized, `susu.json` also carries versioned KDF and wrapped-master-key metadata. The password and plaintext master key are never included.

## Sensitive-file workflow

A safe repository workflow keeps encryption and Git as separate, visible steps:

```bash
susu add --sensitive "$HOME/.kube/config"

susu list
git -C "$HOME/src/dotfiles" status --short
git -C "$HOME/src/dotfiles" add susu.json encrypted
git -C "$HOME/src/dotfiles" commit -m "Manage encrypted kube config"
git -C "$HOME/src/dotfiles" push
```

On another machine:

```bash
git -C "$HOME/src/dotfiles" pull
susu init "$HOME/src/dotfiles"
susu apply
```

Before committing, use `git status` to confirm that the sensitive file appears only as an `.enc` file and that no plaintext was copied into the repository. `susu` cannot remove plaintext that was previously committed to Git history.

## macOS and Linux in one repository

Shared files need no platform flag:

```bash
susu add "$HOME/.zshrc" "$HOME/.gitconfig"
```

Mark macOS-only files so Linux skips them:

```bash
susu add --exclude-platform linux "$HOME/.hammerspoon/init.lua"
susu add --exclude-platform linux "$HOME/Library/Application Support/MTMR/items.json"
```

Mark Linux-only files in the opposite direction:

```bash
susu add --exclude-platform darwin "$HOME/.config/a-linux-only-tool/config"
```

Commit the resulting manifest and storage with Git. After cloning and running `susu init`, the same `susu apply` command works on both supported platforms and filters entries using their explicit metadata.

## Current limitations

- Only `darwin` and `linux` are supported.
- One local `susu` installation binds to one active repository at a time.
- `add` snapshots new entries but does not update or synchronize entries already managed.
- There are no `sync`, `status`, or `diff` commands.
- `add` rejects explicit symlinks, skips all symlinks encountered during directory traversal, and rejects inputs that overlap or contain protected local-state, active-worktree, or Git-common-directory roots; symlinks are not preserved.
- Shell globs are not implemented by `susu`; expansion is the shell's responsibility.
- Sensitive classification is explicit. There is no automatic secret detection.
- Platform exclusions are explicit. Paths do not trigger automatic platform detection.
- There is one password per repository, no password cache, no daemon or agent, and no macOS Keychain or Linux Secret Service integration.
- The master-key design makes password rotation inexpensive, but there is no password-rotation command.
- There is no templating, host-profile system, GUI, TUI, cloud synchronization, remote-repository management, or multi-repository support.
- Public entries, logical paths, filenames, exclusions, and other manifest metadata are not encrypted.
- Public permissions are normalized to `0644` or `0755`; arbitrary Unix mode bits are not preserved through Git.
- An input file is limited to 512 MiB, a serialized repository source read by `show` or `apply` is limited to 1 GiB, and aggregate sensitive plaintext retained during `apply` preflight is limited to 1 GiB.
- `apply` uses a same-directory staging file for atomic replacement; a process crash can leave a sensitive `0600` plaintext staging residue that must be inspected and removed manually. Later `apply` invocations do not scavenge neighboring files by name.
- Darwin destination comparison is intentionally conservative: case- or canonically equivalent spellings are rejected even on a case-sensitive macOS volume. Linux comparison preserves spelling and does not emulate macOS case/normalization behavior.
- Git operations are intentionally not automated. Use Git directly for commit, push, pull, merge, conflict resolution, and history management.

For implementation boundaries and data flow, see [`design.md`](design.md). For cryptographic details and security limitations, see the [encryption and security model](security-model.md).
