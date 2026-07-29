// Package paths converts between local filesystem paths and portable susu paths.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// HomePrefix is the portable prefix for paths below the user's home directory.
	HomePrefix = "~"
	// XDGConfigHomePrefix is the portable prefix for paths below XDG_CONFIG_HOME.
	XDGConfigHomePrefix = "${XDG_CONFIG_HOME}"
)

var (
	// ErrInvalidPath indicates that a filesystem path or resolver root is invalid.
	ErrInvalidPath = errors.New("invalid filesystem path")
	// ErrUnrepresentable indicates that a path is outside both portable roots.
	ErrUnrepresentable = errors.New("path is outside HOME and XDG_CONFIG_HOME")
	// ErrInvalidLogicalPath indicates that a portable path is malformed.
	ErrInvalidLogicalPath = errors.New("invalid logical path")
)

// Resolver converts filesystem paths to portable logical paths and back.
// It performs lexical normalization only and never requires a path to exist.
type Resolver struct {
	home             string
	xdgConfigHome    string
	workingDirectory string
}

// NewResolver creates a resolver with explicit HOME and XDG_CONFIG_HOME values.
// An empty xdgConfigHome uses HOME/.config. Relative inputs are interpreted from
// the process's current working directory at construction time.
func NewResolver(home, xdgConfigHome string) (*Resolver, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	return NewResolverAt(home, xdgConfigHome, workingDirectory)
}

// NewResolverAt is like NewResolver, but takes the working directory used for
// relative input paths. It is useful when callers need deterministic resolution.
func NewResolverAt(home, xdgConfigHome, workingDirectory string) (*Resolver, error) {
	cleanHome, err := cleanAbsolute("HOME", home)
	if err != nil {
		return nil, err
	}

	cleanWorkingDirectory, err := cleanAbsolute("working directory", workingDirectory)
	if err != nil {
		return nil, err
	}

	var cleanXDGConfigHome string
	if xdgConfigHome == "" {
		cleanXDGConfigHome = filepath.Join(cleanHome, ".config")
	} else {
		cleanXDGConfigHome, err = cleanAbsolute("XDG_CONFIG_HOME", xdgConfigHome)
		if err != nil {
			return nil, err
		}
	}

	return &Resolver{
		home:             cleanHome,
		xdgConfigHome:    cleanXDGConfigHome,
		workingDirectory: cleanWorkingDirectory,
	}, nil
}

// NewResolverFromEnv creates a resolver from HOME and XDG_CONFIG_HOME in the
// process environment. No other environment variables affect the resolver.
func NewResolverFromEnv() (*Resolver, error) {
	return NewResolver(os.Getenv("HOME"), os.Getenv("XDG_CONFIG_HOME"))
}

// Normalize converts a filesystem path to a portable logical path. Input may
// be absolute, relative to the resolver's working directory, or begin with ~ or
// ${XDG_CONFIG_HOME}. XDG_CONFIG_HOME is checked before HOME when roots overlap.
func (r *Resolver) Normalize(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}
	if strings.IndexByte(input, 0) >= 0 {
		return "", fmt.Errorf("%w: path contains NUL", ErrInvalidPath)
	}

	filesystemPath, err := r.expandInput(input)
	if err != nil {
		return "", err
	}

	if relative, ok := relativeToRoot(r.xdgConfigHome, filesystemPath); ok {
		return logicalPath(XDGConfigHomePrefix, relative), nil
	}
	if relative, ok := relativeToRoot(r.home, filesystemPath); ok {
		return logicalPath(HomePrefix, relative), nil
	}

	return "", fmt.Errorf("%w: %q", ErrUnrepresentable, filesystemPath)
}

// SplitLogical returns the configured filesystem root and a clean relative path
// for a portable logical path. Callers can combine this with os.OpenRoot to keep
// filesystem operations confined even when symlinks are present.
func (r *Resolver) SplitLogical(logical string) (root, relative string, err error) {
	root, relative, err = r.parseLogical(logical)
	if err != nil {
		return "", "", err
	}
	return root, filepath.FromSlash(relative), nil
}

// Resolve converts a portable logical path to an absolute runtime filesystem
// path. Only canonical ~ and ${XDG_CONFIG_HOME} forms are accepted.
func (r *Resolver) Resolve(logical string) (string, error) {
	root, relative, err := r.SplitLogical(logical)
	if err != nil {
		return "", err
	}
	if relative == "" {
		return root, nil
	}

	resolved := filepath.Join(root, relative)
	if _, ok := relativeToRoot(root, resolved); !ok {
		return "", fmt.Errorf("%w: %q escapes its root", ErrInvalidLogicalPath, logical)
	}
	return resolved, nil
}

func (r *Resolver) expandInput(input string) (string, error) {
	var expanded string

	switch {
	case input == HomePrefix:
		expanded = r.home
	case strings.HasPrefix(input, HomePrefix+"/"):
		expanded = filepath.Join(r.home, filepath.FromSlash(input[len(HomePrefix)+1:]))
	case strings.HasPrefix(input, HomePrefix):
		return "", fmt.Errorf("%w: unsupported home prefix in %q", ErrInvalidPath, input)
	case input == XDGConfigHomePrefix:
		expanded = r.xdgConfigHome
	case strings.HasPrefix(input, XDGConfigHomePrefix+"/"):
		expanded = filepath.Join(r.xdgConfigHome, filepath.FromSlash(input[len(XDGConfigHomePrefix)+1:]))
	case strings.HasPrefix(input, XDGConfigHomePrefix):
		return "", fmt.Errorf("%w: malformed XDG_CONFIG_HOME prefix in %q", ErrInvalidPath, input)
	case filepath.IsAbs(input):
		expanded = input
	default:
		expanded = filepath.Join(r.workingDirectory, input)
	}

	return filepath.Clean(expanded), nil
}

func (r *Resolver) parseLogical(logical string) (root, relative string, err error) {
	if logical == "" {
		return "", "", fmt.Errorf("%w: path is empty", ErrInvalidLogicalPath)
	}
	if strings.IndexByte(logical, 0) >= 0 {
		return "", "", fmt.Errorf("%w: path contains NUL", ErrInvalidLogicalPath)
	}

	switch {
	case logical == XDGConfigHomePrefix:
		return r.xdgConfigHome, "", nil
	case strings.HasPrefix(logical, XDGConfigHomePrefix+"/"):
		root = r.xdgConfigHome
		relative = logical[len(XDGConfigHomePrefix)+1:]
	case logical == HomePrefix:
		return r.home, "", nil
	case strings.HasPrefix(logical, HomePrefix+"/"):
		root = r.home
		relative = logical[len(HomePrefix)+1:]
	default:
		return "", "", fmt.Errorf("%w: %q must start with %s/ or %s/", ErrInvalidLogicalPath, logical, HomePrefix, XDGConfigHomePrefix)
	}

	if err := validateLogicalRelative(relative); err != nil {
		return "", "", fmt.Errorf("%w: %q: %v", ErrInvalidLogicalPath, logical, err)
	}
	return root, relative, nil
}

func validateLogicalRelative(relative string) error {
	if relative == "" {
		return errors.New("path has an empty suffix")
	}
	if strings.HasPrefix(relative, "/") || strings.HasSuffix(relative, "/") {
		return errors.New("path has an empty component")
	}
	if path.Clean(relative) != relative {
		return errors.New("path is not in canonical slash form")
	}
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("path contains an invalid component")
		}
	}
	return nil
}

func cleanAbsolute(name, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrInvalidPath, name)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%w: %s contains NUL", ErrInvalidPath, name)
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("%w: %s must be absolute: %q", ErrInvalidPath, name, value)
	}
	return filepath.Clean(value), nil
}

func relativeToRoot(root, target string) (string, bool) {
	relative, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(relative) {
		return "", false
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func logicalPath(prefix, relative string) string {
	if relative == "." {
		return prefix
	}
	return prefix + "/" + filepath.ToSlash(relative)
}
