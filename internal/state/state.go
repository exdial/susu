// Package state persists the machine-local active repository binding.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxStateFileSize = 64 * 1024

var (
	// ErrNotInitialized indicates that no local repository binding exists.
	ErrNotInitialized = errors.New("susu is not initialized")
	// ErrMalformedState indicates that the local state file cannot be decoded or
	// does not contain a canonical absolute repository path.
	ErrMalformedState = errors.New("malformed local state")
)

// Store reads and writes one machine-local repository binding.
type Store struct {
	path string
}

type stateFile struct {
	Repository string `json:"repository"`
}

// NewStore constructs a store from explicit HOME and XDG_STATE_HOME values.
// An empty xdgStateHome falls back to HOME/.local/state.
func NewStore(home, xdgStateHome string) (*Store, error) {
	var stateRoot string
	var err error
	if xdgStateHome != "" {
		stateRoot, err = cleanAbsoluteRoot("XDG_STATE_HOME", xdgStateHome)
	} else {
		cleanHome, homeErr := cleanAbsoluteRoot("HOME", home)
		if homeErr != nil {
			return nil, homeErr
		}
		stateRoot = filepath.Join(cleanHome, ".local", "state")
	}
	if err != nil {
		return nil, err
	}

	return &Store{path: filepath.Join(stateRoot, "susu", "state.json")}, nil
}

// NewStoreFromEnv constructs a store from HOME and XDG_STATE_HOME in the
// process environment. No other environment variables affect state location.
func NewStoreFromEnv() (*Store, error) {
	return NewStore(os.Getenv("HOME"), os.Getenv("XDG_STATE_HOME"))
}

// Path returns the absolute path of this store's state file.
func (s *Store) Path() string {
	return s.path
}

// Save atomically replaces the binding with a canonical absolute repository
// path. The susu state directory and state file are restricted to the user.
func (s *Store) Save(repository string) error {
	canonical, err := canonicalRepository(repository)
	if err != nil {
		return err
	}

	contents, err := json.MarshalIndent(stateFile{Repository: canonical}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode local state: %w", err)
	}
	contents = append(contents, '\n')

	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create local state directory %q: %w", directory, err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("set local state directory permissions %q: %w", directory, err)
	}

	temporary, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary local state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary local state permissions: %w", err)
	}
	written, err := temporary.Write(contents)
	if err != nil {
		return fmt.Errorf("write temporary local state: %w", err)
	}
	if written != len(contents) {
		return fmt.Errorf("write temporary local state: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary local state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary local state: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace local state %q: %w", s.path, err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync local state directory %q: %w", directory, err)
	}

	return nil
}

// Lock acquires the process-wide lock for the active susu installation. The
// lock serializes repository reads and mutations so concurrent commands cannot
// lose manifest updates or observe a source/manifest transition midway through.
func (s *Store) Lock() (func() error, error) {
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create local state directory %q: %w", directory, err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("set local state directory permissions %q: %w", directory, err)
	}
	lockPath := filepath.Join(directory, "lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open local susu lock %q: %w", lockPath, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set local susu lock permissions %q: %w", lockPath, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock susu state %q: %w", lockPath, err)
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
			return fmt.Errorf("unlock susu state %q: %w", lockPath, unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close susu lock %q: %w", lockPath, closeErr)
		}
		return nil
	}, nil
}

// Load returns the configured repository. A missing state file wraps
// ErrNotInitialized; invalid JSON or repository data wraps ErrMalformedState.
func (s *Store) Load() (string, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: local state file %q does not exist", ErrNotInitialized, s.path)
		}
		return "", fmt.Errorf("inspect local state %q: %w", s.path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: local state %q is not a regular file", ErrMalformedState, s.path)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return "", fmt.Errorf("open local state %q: %w", s.path, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxStateFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read local state %q: %w", s.path, err)
	}
	if len(contents) > maxStateFileSize {
		return "", fmt.Errorf("%w: state file exceeds %d bytes", ErrMalformedState, maxStateFileSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var decoded stateFile
	if err := decoder.Decode(&decoded); err != nil {
		return "", fmt.Errorf("%w: decode %q: %v", ErrMalformedState, s.path, err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", fmt.Errorf("%w: %q contains multiple JSON values", ErrMalformedState, s.path)
		}
		return "", fmt.Errorf("%w: trailing data in %q: %v", ErrMalformedState, s.path, err)
	}

	if err := validateStoredRepository(decoded.Repository); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedState, err)
	}
	return decoded.Repository, nil
}

func cleanAbsoluteRoot(name, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%s contains NUL", name)
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s must be absolute: %q", name, value)
	}
	return filepath.Clean(value), nil
}

func canonicalRepository(repository string) (string, error) {
	if repository == "" {
		return "", errors.New("repository path is empty")
	}
	if strings.IndexByte(repository, 0) >= 0 {
		return "", errors.New("repository path contains NUL")
	}

	absolute, err := filepath.Abs(repository)
	if err != nil {
		return "", fmt.Errorf("make repository path absolute: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func validateStoredRepository(repository string) error {
	if repository == "" {
		return errors.New("repository path is empty")
	}
	if strings.IndexByte(repository, 0) >= 0 {
		return errors.New("repository path contains NUL")
	}
	if !filepath.IsAbs(repository) {
		return fmt.Errorf("repository path is not absolute: %q", repository)
	}
	if filepath.Clean(repository) != repository {
		return fmt.Errorf("repository path is not canonical: %q", repository)
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
