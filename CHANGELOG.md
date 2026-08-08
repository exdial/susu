# Changelog

Notable user-facing changes to `susu` are documented in this file. The README describes the current behavior, while this file records version-specific changes.

## [Unreleased]

### Added

- Added regression coverage for controlling-TTY password input, fail-closed crypto metadata validation, and atomic replacement failure semantics.

### Changed

- Consolidated the maintained behavior contract into the CLI reference, architecture design, and security model, with explicit ownership of user behavior, formats and failure semantics, and security requirements and accepted risks.
- Formally accepted mode-`0600` same-directory plaintext staging as the portable atomic `apply` contract. Crash or cleanup residue remains a documented risk requiring manual inspection; later invocations do not scavenge neighboring names.

### Fixed

- Zeroed partial password bytes returned together with a terminal read error.
- Prevented one physical destination from receiving multiple logical identities: `add` now classifies opened candidates by filesystem identity, while `apply` rejects case- and Unicode-normalization-equivalent Darwin destinations before and during restoration.
- Excluded the real `~/.kube/cache` directory, its descendants, and physical/case aliases from recursive and explicit regular-file or directory `add` inputs.
- Prevented inherited Git repository-local and discovery environment variables from redirecting repository-root validation or repository-lock placement.
- Stopped `apply` from deleting neighboring unmanaged files merely because their names match `.susu-apply-*.tmp`. Ordinary pre-rename error cleanup is now limited to the exact staging name created by the current replacement; crash residue requires explicit inspection and manual removal.

## [0.1.1]

### Added

- Automated GitHub releases with macOS/Linux archives and SHA-256 checksums.

### Fixed

- Prevented managed inputs and applicable `apply` destinations from overlapping the active private `susu` state directory, repository worktree, or Git common administrative directory.
- Made repository locking and control-root protection share one canonical Git common directory, including linked worktrees and separate Git directories.
- Preserved trailing whitespace when parsing Git worktree and common-directory paths.

## [0.1.0]

### Added

- The `init`, `add`, `rm`, `list`, `show`, and `apply` commands.
- Management of public dotfiles as repository snapshots and sensitive dotfiles as authenticated ciphertext.
- Password-protected repository master keys with per-file AES-256-GCM encryption.
- Portable HOME and XDG logical paths for sharing one dotfiles repository across machines.
- Explicit `darwin` and `linux` platform exclusions.
- Recursive directory discovery with conservative symlink and special-file handling.
- Preflighted, confined, atomic restoration of public and sensitive files.
- Machine-local active-repository binding and repository-operation locking.

### Known limitations

- Only macOS (`darwin`) and Linux (`linux`) are supported.
- One installation binds to one active repository at a time.
- `add` snapshots only new entries; it does not update entries that are already managed.
- There are no `sync`, `status`, `diff`, password-rotation, conflict-handling, or backup commands.
- `show` accepts one path per invocation.
- Shell glob expansion is delegated to the shell, and symlinks are not managed.
- Passwords and keys are not cached, and there is no Keychain or Secret Service integration.
- Input files are limited to 512 MiB. Serialized repository sources and aggregate sensitive `apply` preflight plaintext are limited to 1 GiB.
- A crash during `apply` could leave a mode-`0600` plaintext staging file. v0.1.0 attempted broad name-based cleanup on a later `apply`, which could also remove unrelated matching files.
