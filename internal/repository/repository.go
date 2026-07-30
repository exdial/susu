// Package repository owns Git-root validation and safe access to repository files.
package repository

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"susu/internal/manifest"
	"susu/internal/safefs"

	"golang.org/x/sys/unix"
)

var (
	// ErrNotInitialized indicates that a directory has no susu.json.
	ErrNotInitialized = errors.New("repository is not initialized by susu")
	// ErrRepositoryMissing indicates that the locally bound repository disappeared.
	ErrRepositoryMissing = errors.New("configured repository no longer exists")
	// ErrNotGitRoot indicates that init/open did not receive the Git worktree root.
	ErrNotGitRoot = errors.New("path is not the Git repository root")
	// ErrUnsafeSource indicates an invalid path or symlink in repository storage.
	ErrUnsafeSource = errors.New("unsafe repository source path")
	// ErrSourceExists indicates storage that susu must not silently overwrite.
	ErrSourceExists = errors.New("repository source already exists")
)

// Repository is one validated, initialized susu repository.
type Repository struct {
	Root               string
	gitCommonDirectory string
}

// Initialize validates an existing Git worktree root, creates storage
// directories and susu.json as needed, and returns its canonical path.
func Initialize(input string) (*Repository, error) {
	root, err := canonicalExistingDirectory(input, false)
	if err != nil {
		return nil, err
	}
	if err := validateGitRoot(root); err != nil {
		return nil, err
	}

	repository, err := newRepository(root)
	if err != nil {
		return nil, err
	}
	release, err := repository.Lock()
	if err != nil {
		return nil, err
	}
	defer func() { _ = release() }()
	if err := repository.ensureStorageDirectories(); err != nil {
		return nil, err
	}

	manifestPath := repository.ManifestPath()
	_, err = os.Lstat(manifestPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := manifest.Save(manifestPath, manifest.New()); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("inspect susu.json %q: %w", manifestPath, err)
	default:
		info, err := os.Lstat(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("inspect susu.json %q: %w", manifestPath, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: susu.json %q is not a regular file", manifest.ErrInvalidManifest, manifestPath)
		}
		if _, err := manifest.Load(manifestPath); err != nil {
			return nil, err
		}
	}
	return repository, nil
}

// Open validates a configured initialized repository. It does not mutate it.
func Open(input string) (*Repository, error) {
	root, err := canonicalExistingDirectory(input, true)
	if err != nil {
		return nil, err
	}
	if err := validateGitRoot(root); err != nil {
		return nil, err
	}
	repository, err := newRepository(root)
	if err != nil {
		return nil, err
	}
	if err := repository.checkStorageDirectories(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(repository.ManifestPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q is missing; run 'susu init <repository>'", ErrNotInitialized, repository.ManifestPath())
		}
		return nil, fmt.Errorf("inspect susu.json %q: %w", repository.ManifestPath(), err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: susu.json %q is not a regular file", manifest.ErrInvalidManifest, repository.ManifestPath())
	}
	return repository, nil
}

// GitCommonDirectory returns the canonical absolute Git common administrative directory.
func (r *Repository) GitCommonDirectory() string {
	return r.gitCommonDirectory
}

// ManifestPath returns the absolute susu.json path.
func (r *Repository) ManifestPath() string {
	return filepath.Join(r.Root, manifest.Filename)
}

// LoadManifest loads the current portable state.
func (r *Repository) LoadManifest() (manifest.Manifest, error) {
	return manifest.Load(r.ManifestPath())
}

// SaveManifest atomically persists portable state.
func (r *Repository) SaveManifest(value manifest.Manifest) error {
	return manifest.Save(r.ManifestPath(), value)
}

// Lock serializes every process mutating or reading this Git repository,
// regardless of which local XDG state directory is bound to it. The lock lives
// in Git's common administrative directory and is never part of the worktree.
func (r *Repository) Lock() (func() error, error) {
	directory, leaf, err := safefs.OpenParent(r.gitCommonDirectory, "susu.lock", false, 0)
	if err != nil {
		return nil, fmt.Errorf("open Git common directory lock path: %w", err)
	}
	file, err := directory.OpenReadWrite(leaf, 0o600)
	_ = directory.Close()
	if err != nil {
		return nil, fmt.Errorf("open repository lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock repository %q: %w", r.Root, err)
	}
	locked := true
	return func() error {
		if !locked {
			return nil
		}
		locked = false
		unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		closeErr := file.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock repository %q: %w", r.Root, unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close repository lock for %q: %w", r.Root, closeErr)
		}
		return nil
	}, nil
}

// SourcePath validates source lexically and returns its absolute storage path.
func (r *Repository) SourcePath(source string) (string, error) {
	if source == "" || strings.IndexByte(source, 0) >= 0 || path.Clean(source) != source || strings.HasPrefix(source, "/") {
		return "", fmt.Errorf("%w: invalid source %q", ErrUnsafeSource, source)
	}
	if !(strings.HasPrefix(source, "public/") || strings.HasPrefix(source, "encrypted/")) {
		return "", fmt.Errorf("%w: source %q must be under public/ or encrypted/", ErrUnsafeSource, source)
	}
	for _, component := range strings.Split(source, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("%w: source %q contains an invalid component", ErrUnsafeSource, source)
		}
	}
	absolute := filepath.Join(r.Root, filepath.FromSlash(source))
	relative, err := filepath.Rel(r.Root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: source %q escapes repository", ErrUnsafeSource, source)
	}
	return absolute, nil
}

// ExistingSource returns a regular, non-symlink repository file. Every parent
// below the repository root must also be a real directory rather than a symlink.
func (r *Repository) ExistingSource(source string) (string, error) {
	absolute, err := r.SourcePath(source)
	if err != nil {
		return "", err
	}
	if err := r.validateParentDirectories(filepath.Dir(absolute), false, 0); err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("open repository source %q: %w", source, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: source %q is not a regular file", ErrUnsafeSource, source)
	}
	return absolute, nil
}

// NewSource prepares real parent directories for a new stored file and refuses
// to return a target that already exists.
func (r *Repository) NewSource(source string, directoryMode os.FileMode) (string, error) {
	absolute, err := r.SourcePath(source)
	if err != nil {
		return "", err
	}
	if err := r.validateParentDirectories(filepath.Dir(absolute), true, directoryMode); err != nil {
		return "", err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", fmt.Errorf("%w: %q", ErrSourceExists, source)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect repository source %q: %w", source, err)
	}
	return absolute, nil
}

// OpenSource opens one regular stored file through a traversal-resistant root.
// Symlinks cannot escape the repository even if path components change while
// the operation is in progress.
func (r *Repository) OpenSource(source string) (*os.File, error) {
	if _, err := r.SourcePath(source); err != nil {
		return nil, err
	}
	file, err := safefs.OpenRegular(r.Root, filepath.FromSlash(source))
	if err != nil {
		return nil, fmt.Errorf("open repository source %q without following symlinks: %w", source, err)
	}
	return file, nil
}

// ReadSource reads a bounded stored file through OpenSource.
func (r *Repository) ReadSource(source string, maxBytes int64) ([]byte, error) {
	file, err := r.OpenSource(source)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect repository source %q: %w", source, err)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("repository source %q is %d bytes, limit is %d", source, info.Size(), maxBytes)
	}
	reader := io.Reader(file)
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes+1)
	}
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read repository source %q: %w", source, err)
	}
	if maxBytes > 0 && int64(len(contents)) > maxBytes {
		return nil, fmt.Errorf("repository source %q exceeds %d bytes", source, maxBytes)
	}
	return contents, nil
}

// WriteNewSource atomically installs a new stored file and never replaces an
// existing path. All operations remain anchored to the repository root.
func (r *Repository) WriteNewSource(source string, contents []byte, mode os.FileMode) error {
	if _, err := r.SourcePath(source); err != nil {
		return err
	}
	directory, leaf, err := safefs.OpenParent(r.Root, filepath.FromSlash(source), true, 0o755)
	if err != nil {
		return fmt.Errorf("prepare repository source %q without following symlinks: %w", source, err)
	}
	defer directory.Close()
	file, temporaryName, err := directory.CreateTemp(".susu-add-", mode)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = directory.Remove(temporaryName)
	}()
	if err := writeAll(file, contents); err != nil {
		return fmt.Errorf("write temporary repository source: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary repository source: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary repository source: %w", err)
	}
	if err := directory.Link(temporaryName, leaf); err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %q", ErrSourceExists, source)
		}
		return fmt.Errorf("install repository source %q: %w", source, err)
	}
	if err := directory.Remove(temporaryName); err != nil {
		_ = directory.Remove(leaf)
		return fmt.Errorf("remove temporary repository source: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Remove(leaf)
		return fmt.Errorf("sync repository source directory for %q: %w", source, err)
	}
	return nil
}

// RemoveSource removes one regular stored source without following symlinks.
func (r *Repository) RemoveSource(source string) error {
	if _, err := r.SourcePath(source); err != nil {
		return err
	}
	directory, leaf, err := safefs.OpenParent(r.Root, filepath.FromSlash(source), false, 0)
	if err != nil {
		return fmt.Errorf("open repository source parent %q: %w", source, err)
	}
	defer directory.Close()
	file, err := directory.OpenRegular(leaf)
	if err != nil {
		return fmt.Errorf("inspect repository source %q: %w", source, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close repository source %q: %w", source, err)
	}
	if err := directory.Remove(leaf); err != nil {
		return fmt.Errorf("remove repository source %q: %w", source, err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync repository source directory for %q: %w", source, err)
	}
	return nil
}

func (r *Repository) ensureStorageDirectories() error {
	for _, name := range []string{"public", "encrypted"} {
		location := filepath.Join(r.Root, name)
		info, err := os.Lstat(location)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(location, 0o755); err != nil {
				return fmt.Errorf("create repository storage directory %q: %w", location, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect repository storage directory %q: %w", location, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: storage path %q is not a real directory", ErrUnsafeSource, location)
		}
	}
	return nil
}

func (r *Repository) checkStorageDirectories() error {
	for _, name := range []string{"public", "encrypted"} {
		location := filepath.Join(r.Root, name)
		info, err := os.Lstat(location)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("repository storage directory %q is missing; rerun 'susu init %s'", location, r.Root)
			}
			return fmt.Errorf("inspect repository storage directory %q: %w", location, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: storage path %q is not a real directory", ErrUnsafeSource, location)
		}
	}
	return nil
}

func (r *Repository) validateParentDirectories(parent string, create bool, mode os.FileMode) error {
	relative, err := filepath.Rel(r.Root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: parent %q escapes repository", ErrUnsafeSource, parent)
	}
	current := r.Root
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := os.Mkdir(current, mode); err != nil {
				return fmt.Errorf("create repository directory %q: %w", current, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect repository directory %q: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: repository parent %q is not a real directory", ErrUnsafeSource, current)
		}
	}
	return nil
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func canonicalExistingDirectory(input string, configured bool) (string, error) {
	if input == "" {
		return "", errors.New("repository path is empty")
	}
	absolute, err := filepath.Abs(input)
	if err != nil {
		return "", fmt.Errorf("resolve repository path %q: %w", input, err)
	}
	absolute = filepath.Clean(absolute)
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		if configured && errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %q", ErrRepositoryMissing, absolute)
		}
		return "", fmt.Errorf("resolve repository path %q: %w", input, err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", fmt.Errorf("make repository path absolute %q: %w", canonical, err)
	}
	canonical = filepath.Clean(canonical)
	if configured && canonical != absolute {
		return "", fmt.Errorf("%w: stored path %q now resolves to %q", ErrRepositoryMissing, absolute, canonical)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		if configured && errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %q", ErrRepositoryMissing, canonical)
		}
		return "", fmt.Errorf("inspect repository path %q: %w", canonical, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repository path %q is not a directory", canonical)
	}
	return canonical, nil
}

func newRepository(root string) (*Repository, error) {
	commonDirectory, err := gitCommonDirectory(root)
	if err != nil {
		return nil, err
	}
	return &Repository{Root: root, gitCommonDirectory: commonDirectory}, nil
}

func gitCommonDirectory(root string) (string, error) {
	common, err := gitRevParsePath(root, "--git-common-dir")
	if err != nil {
		return "", fmt.Errorf("locate Git common directory for %q: %w", root, err)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(root, common)
	}
	resolved, err := canonicalExistingDirectory(common, false)
	if err != nil {
		return "", fmt.Errorf("resolve Git common directory %q: %w", common, err)
	}
	return resolved, nil
}

func validateGitRoot(root string) error {
	gitRootText, err := gitRevParsePath(root, "--show-toplevel")
	if err != nil {
		return fmt.Errorf("Git repository validation failed for %q: %w", root, err)
	}
	gitRoot, err := canonicalExistingDirectory(gitRootText, false)
	if err != nil {
		return fmt.Errorf("resolve Git repository root %q: %w", gitRootText, err)
	}
	if gitRoot != root {
		return fmt.Errorf("%w: supplied %q, Git root is %q", ErrNotGitRoot, root, gitRoot)
	}
	return nil
}

func gitRevParsePath(root, option string) (string, error) {
	var stdout strings.Builder
	var stderr strings.Builder
	command := exec.Command("git", "-C", root, "rev-parse", option)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", errors.New(detail)
	}
	value, err := parseGitPathRecord(stdout.String())
	if err != nil {
		return "", fmt.Errorf("parse git rev-parse %s output: %w", option, err)
	}
	return value, nil
}

func parseGitPathRecord(output string) (string, error) {
	if output == "" {
		return "", errors.New("Git returned empty path output")
	}
	if !strings.HasSuffix(output, "\n") {
		return "", errors.New("Git path output is missing its record terminator")
	}
	record := strings.TrimSuffix(output, "\n")
	if record == "" {
		return "", errors.New("Git returned an empty path record")
	}
	if strings.Contains(record, "\n") {
		return "", errors.New("Git returned multiple or malformed path records")
	}
	return record, nil
}
