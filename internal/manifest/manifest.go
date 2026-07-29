// Package manifest reads and writes the portable susu.json repository state.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"susu/internal/cryptox"
)

const (
	// CurrentVersion is the only repository manifest version supported by v0.1.
	CurrentVersion = 1
	// Filename is the portable repository-state filename.
	Filename    = "susu.json"
	maxFileSize = 16 * 1024 * 1024
)

var (
	// ErrInvalidManifest indicates malformed or internally inconsistent susu.json data.
	ErrInvalidManifest = errors.New("invalid susu.json")
	// ErrUnsupportedVersion indicates a repository created with an unknown format.
	ErrUnsupportedVersion = errors.New("unsupported susu.json version")
	// ErrCommitted indicates that the new manifest was renamed into place but a
	// final directory durability check failed. Callers must not roll sources back.
	ErrCommitted = errors.New("susu.json was committed but its durability is uncertain")
)

// Entry describes one individually managed file.
type Entry struct {
	Path             string   `json:"path"`
	Source           string   `json:"source"`
	Sensitive        bool     `json:"sensitive,omitempty"`
	ExcludePlatforms []string `json:"excludePlatforms,omitempty"`
}

// Manifest is the versioned portable state committed to the dotfiles repository.
type Manifest struct {
	Version int               `json:"version"`
	Entries []Entry           `json:"entries"`
	Crypto  *cryptox.Metadata `json:"crypto,omitempty"`
}

// New returns an empty current-version manifest.
func New() Manifest {
	return Manifest{Version: CurrentVersion, Entries: []Entry{}}
}

// Load strictly decodes and validates a manifest from filename.
func Load(filename string) (Manifest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Manifest{}, fmt.Errorf("open susu.json %q: %w", filename, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read susu.json %q: %w", filename, err)
	}
	if len(contents) > maxFileSize {
		return Manifest{}, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalidManifest, maxFileSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var decoded Manifest
	if err := decoder.Decode(&decoded); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode %q: %v", ErrInvalidManifest, filename, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, fmt.Errorf("%w: %q contains multiple JSON values", ErrInvalidManifest, filename)
		}
		return Manifest{}, fmt.Errorf("%w: trailing data in %q: %v", ErrInvalidManifest, filename, err)
	}
	if err := Validate(decoded); err != nil {
		return Manifest{}, err
	}
	if decoded.Entries == nil {
		decoded.Entries = []Entry{}
	}
	return decoded, nil
}

// Save validates and atomically replaces filename with an indented manifest.
func Save(filename string, value Manifest) error {
	if value.Entries == nil {
		value.Entries = []Entry{}
	}
	SortEntries(value.Entries)
	if err := Validate(value); err != nil {
		return err
	}

	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode susu.json: %w", err)
	}
	contents = append(contents, '\n')

	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".susu-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary susu.json in %q: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set temporary susu.json permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary susu.json: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary susu.json: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary susu.json: %w", err)
	}
	if err := os.Rename(temporaryPath, filename); err != nil {
		return fmt.Errorf("replace susu.json %q: %w", filename, err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("%w: sync repository directory %q: %v", ErrCommitted, directory, err)
	}
	return nil
}

// Validate checks the manifest version, entries, platform values, crypto
// metadata, and deterministic storage mapping.
func Validate(value Manifest) error {
	if value.Version != CurrentVersion {
		return fmt.Errorf("%w: got %d, supported version is %d", ErrUnsupportedVersion, value.Version, CurrentVersion)
	}
	if value.Crypto != nil {
		if err := cryptox.ValidateMetadata(*value.Crypto); err != nil {
			return err
		}
	}

	seenPaths := make(map[string]struct{}, len(value.Entries))
	seenSources := make(map[string]struct{}, len(value.Entries))
	logicalPaths := make([]string, 0, len(value.Entries))
	sourcePaths := make([]string, 0, len(value.Entries))
	for index, entry := range value.Entries {
		if err := validateEntry(entry); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrInvalidManifest, index, err)
		}
		if _, exists := seenPaths[entry.Path]; exists {
			return fmt.Errorf("%w: duplicate managed path %q", ErrInvalidManifest, entry.Path)
		}
		seenPaths[entry.Path] = struct{}{}
		logicalPaths = append(logicalPaths, entry.Path)
		if _, exists := seenSources[entry.Source]; exists {
			return fmt.Errorf("%w: duplicate repository source %q", ErrInvalidManifest, entry.Source)
		}
		seenSources[entry.Source] = struct{}{}
		sourcePaths = append(sourcePaths, entry.Source)
		if entry.Sensitive && value.Crypto == nil {
			return fmt.Errorf("%w: sensitive entry %q has no repository crypto metadata", ErrInvalidManifest, entry.Path)
		}
	}
	if first, second, conflict := ancestorConflict(logicalPaths); conflict {
		return fmt.Errorf("%w: managed file %q conflicts with descendant %q", ErrInvalidManifest, first, second)
	}
	if first, second, conflict := ancestorConflict(sourcePaths); conflict {
		return fmt.Errorf("%w: repository source %q conflicts with descendant %q", ErrInvalidManifest, first, second)
	}
	return nil
}

// SourceFor returns the deterministic repository-relative storage path for a
// portable logical destination.
func SourceFor(logical string, sensitive bool) (string, error) {
	relative, err := logicalRelative(logical)
	if err != nil {
		return "", err
	}
	root := "public"
	if sensitive {
		root = "encrypted"
	}
	source := path.Join(root, relative)
	if sensitive {
		source += ".enc"
	}
	return source, nil
}

// Find returns the index of logical, or -1 when it is not managed.
func Find(value Manifest, logical string) int {
	for index := range value.Entries {
		if value.Entries[index].Path == logical {
			return index
		}
	}
	return -1
}

// SortEntries gives manifests and command output deterministic path order.
func SortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
}

func validateEntry(entry Entry) error {
	if entry.Path == "" {
		return errors.New("path is empty")
	}
	if !utf8.ValidString(entry.Path) || hasControlCharacters(entry.Path) {
		return fmt.Errorf("path %q is not safe portable UTF-8 text", entry.Path)
	}
	if !utf8.ValidString(entry.Source) || hasControlCharacters(entry.Source) {
		return fmt.Errorf("source %q is not safe portable UTF-8 text", entry.Source)
	}
	expectedSource, err := SourceFor(entry.Path, entry.Sensitive)
	if err != nil {
		return err
	}
	if entry.Source != expectedSource {
		return fmt.Errorf("source %q does not match deterministic source %q", entry.Source, expectedSource)
	}
	seenPlatforms := make(map[string]struct{}, len(entry.ExcludePlatforms))
	for _, platform := range entry.ExcludePlatforms {
		if platform != "darwin" && platform != "linux" {
			return fmt.Errorf("unsupported platform value %q", platform)
		}
		if _, exists := seenPlatforms[platform]; exists {
			return fmt.Errorf("duplicate excluded platform %q", platform)
		}
		seenPlatforms[platform] = struct{}{}
	}
	return nil
}

func logicalRelative(logical string) (string, error) {
	if !utf8.ValidString(logical) || hasControlCharacters(logical) {
		return "", fmt.Errorf("logical path %q is not safe portable UTF-8 text", logical)
	}
	const (
		homePrefix = "~/"
		xdgPrefix  = "${XDG_CONFIG_HOME}/"
	)
	var rawRelative string
	xdg := false
	switch {
	case strings.HasPrefix(logical, xdgPrefix):
		rawRelative = strings.TrimPrefix(logical, xdgPrefix)
		xdg = true
	case strings.HasPrefix(logical, homePrefix):
		rawRelative = strings.TrimPrefix(logical, homePrefix)
	default:
		return "", fmt.Errorf("logical path %q must start with %q or %q", logical, homePrefix, xdgPrefix)
	}
	if strings.IndexByte(logical, 0) >= 0 || rawRelative == "" || path.Clean(rawRelative) != rawRelative || strings.HasPrefix(rawRelative, "../") || rawRelative == ".." || strings.HasPrefix(rawRelative, "/") {
		return "", fmt.Errorf("logical path %q is not canonical", logical)
	}
	for _, component := range strings.Split(rawRelative, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("logical path %q contains an invalid component", logical)
		}
	}
	if xdg {
		return path.Join(".config", rawRelative), nil
	}
	if rawRelative == ".config" || strings.HasPrefix(rawRelative, ".config/") {
		return "", fmt.Errorf("logical path %q must use ${XDG_CONFIG_HOME}", logical)
	}
	return rawRelative, nil
}

func ancestorConflict(values []string) (string, string, bool) {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	set := make(map[string]struct{}, len(sorted))
	for _, value := range sorted {
		set[value] = struct{}{}
	}
	for _, value := range sorted {
		for separator := strings.LastIndex(value, "/"); separator > 0; separator = strings.LastIndex(value[:separator], "/") {
			ancestor := value[:separator]
			if _, exists := set[ancestor]; exists {
				return ancestor, value, true
			}
		}
	}
	return "", "", false
}

func hasControlCharacters(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return true
		}
	}
	return false
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
