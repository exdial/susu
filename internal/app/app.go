// Package app implements susu's command semantics independently of CLI parsing.
package app

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"susu/internal/cryptox"
	"susu/internal/manifest"
	"susu/internal/paths"
	"susu/internal/repository"
	"susu/internal/safefs"
	"susu/internal/state"
)

const (
	maxManagedFileSize     = int64(512 << 20)
	maxRepositoryFileSize  = int64(1 << 30)
	maxApplySensitiveBytes = int64(1 << 30)
	kubeCacheLogicalPath   = paths.HomePrefix + "/.kube/cache"
)

var (
	// ErrNotManaged indicates that an exact logical path is absent from susu.json.
	ErrNotManaged = errors.New("path is not managed")
	// ErrUnsupportedPlatform indicates a platform other than darwin or linux.
	ErrUnsupportedPlatform = errors.New("unsupported platform value")
	// ErrPasswordRequired indicates that an operation needs an interactive or injected password provider.
	ErrPasswordRequired = errors.New("repository password is required")
	// ErrDestinationConflict indicates that multiple logical paths identify one
	// managed destination or that an add candidate changed physical identity.
	ErrDestinationConflict = errors.New("managed destination conflict")
	// ErrProtectedLocalState indicates that a managed input or destination
	// overlaps or aliases susu's machine-local binding, lock, or state staging directory.
	ErrProtectedLocalState = errors.New("path overlaps susu local state")
	// ErrProtectedRepository indicates that a managed input or destination
	// overlaps the active worktree or its Git common administrative directory.
	ErrProtectedRepository = errors.New("path overlaps active susu repository")
)

// PasswordProvider returns a repository password. create is true only while
// initializing repository encryption, when callers must request confirmation.
type PasswordProvider func(create bool) ([]byte, error)

// Service binds command logic to local state, portable path resolution, and a platform.
type Service struct {
	state    *state.Store
	paths    *paths.Resolver
	platform string
}

// New constructs a service for darwin or linux.
func New(store *state.Store, resolver *paths.Resolver, platform string) (*Service, error) {
	if store == nil {
		return nil, errors.New("local state store is nil")
	}
	if resolver == nil {
		return nil, errors.New("path resolver is nil")
	}
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}
	return &Service{state: store, paths: resolver, platform: platform}, nil
}

// ValidatePlatform accepts the Go runtime values supported by susu v0.1.
func ValidatePlatform(platform string) error {
	if platform != "darwin" && platform != "linux" {
		return fmt.Errorf("%w %q (supported: darwin, linux)", ErrUnsupportedPlatform, platform)
	}
	return nil
}

// Init validates/initializes a repository and stores its canonical local binding.
func (s *Service) Init(input string) (string, error) {
	repo, err := repository.Initialize(input)
	if err != nil {
		return "", err
	}
	if err := s.ensureStateOutsideRepository(repo); err != nil {
		return "", err
	}
	release, err := s.state.Lock()
	if err != nil {
		return "", err
	}
	defer func() { _ = release() }()
	if err := s.state.Save(repo.Root); err != nil {
		return "", fmt.Errorf("save active repository binding: %w", err)
	}
	return repo.Root, nil
}

// AddOptions controls metadata and encryption for newly managed files.
type AddOptions struct {
	Sensitive        bool
	ExcludePlatforms []string
	Password         PasswordProvider
}

// AddResult separates new entries from idempotently skipped paths.
type AddResult struct {
	Added          []string
	AlreadyManaged []string
}

type candidate struct {
	absolute string
	root     string
	relative string
	logical  string
	identity fs.FileInfo
	source   string
}

type managedFileIdentity struct {
	logical string
	info    fs.FileInfo
}

type addIgnorePolicy struct {
	kubeCachePath string
	kubeCacheInfo fs.FileInfo
}

type localStateBoundary struct {
	directory string
	files     []fs.FileInfo
}

type repositoryProtectedRoot struct {
	path  string
	label string
	info  fs.FileInfo
}

type repositoryBoundary struct {
	roots []repositoryProtectedRoot
}

type controlBoundary struct {
	localState *localStateBoundary
	repository *repositoryBoundary
}

type addHooks struct {
	beforeCandidateRead func(logical string) error
}

// Add starts managing regular files. Directories are recursively expanded into
// individual entries; existing entries are skipped without overwriting storage.
func (s *Service) Add(inputs []string, options AddOptions) (AddResult, error) {
	return s.addWithHooks(inputs, options, addHooks{})
}

func (s *Service) addWithHooks(inputs []string, options AddOptions, hooks addHooks) (AddResult, error) {
	if len(inputs) == 0 {
		return AddResult{}, errors.New("add requires at least one path")
	}
	exclusions, err := normalizePlatforms(options.ExcludePlatforms)
	if err != nil {
		return AddResult{}, err
	}
	repo, current, release, err := s.openLocked()
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = release() }()

	boundary, err := s.loadControlBoundary(repo)
	if err != nil {
		return AddResult{}, err
	}
	candidates, err := s.collectCandidates(inputs, options.Sensitive, boundary)
	if err != nil {
		return AddResult{}, err
	}
	managed := make(map[string]manifest.Entry, len(current.Entries))
	sources := make(map[string]string, len(current.Entries))
	for _, entry := range current.Entries {
		managed[entry.Path] = entry
		sources[entry.Source] = entry.Path
	}

	hasNewLogical := false
	for _, item := range candidates {
		if _, exists := managed[item.logical]; !exists {
			hasNewLogical = true
			break
		}
	}
	if !hasNewLogical {
		result := AddResult{AlreadyManaged: make([]string, 0, len(candidates))}
		for _, item := range candidates {
			result.AlreadyManaged = append(result.AlreadyManaged, item.logical)
		}
		return result, nil
	}

	managedIdentities, err := s.loadManagedFileIdentities(current.Entries)
	if err != nil {
		return AddResult{}, err
	}
	result := AddResult{}
	newCandidates := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		if _, exists := managed[item.logical]; exists {
			result.AlreadyManaged = append(result.AlreadyManaged, item.logical)
			continue
		}
		if _, exists := physicalIdentityOwner(item.identity, managedIdentities); exists {
			result.AlreadyManaged = append(result.AlreadyManaged, item.logical)
			continue
		}
		for _, existing := range newCandidates {
			if os.SameFile(item.identity, existing.identity) {
				return AddResult{}, destinationConflict(existing.logical, item.logical)
			}
		}
		if existingPath, exists := sources[item.source]; exists {
			return AddResult{}, fmt.Errorf("repository source %q for %q is already used by %q", item.source, item.logical, existingPath)
		}
		sources[item.source] = item.logical
		newCandidates = append(newCandidates, item)
	}
	if len(newCandidates) == 0 {
		return result, nil
	}

	updated := current
	var masterKey []byte
	if options.Sensitive {
		if options.Password == nil {
			return AddResult{}, ErrPasswordRequired
		}
		create := updated.Crypto == nil
		password, err := options.Password(create)
		if err != nil {
			return AddResult{}, fmt.Errorf("read repository password: %w", err)
		}
		defer cryptox.ZeroBytes(password)
		if create {
			metadata, key, err := cryptox.Initialize(password)
			if err != nil {
				return AddResult{}, err
			}
			updated.Crypto = &metadata
			masterKey = key
		} else {
			key, err := cryptox.Unlock(password, *updated.Crypto)
			if err != nil {
				return AddResult{}, err
			}
			masterKey = key
		}
		defer cryptox.ZeroBytes(masterKey)
	}

	if err := s.preflightCandidates(newCandidates, current.Entries, boundary); err != nil {
		return AddResult{}, err
	}

	created := make([]string, 0, len(newCandidates))
	rollback := func() {
		for _, source := range created {
			_ = repo.RemoveSource(source)
		}
	}
	for _, item := range newCandidates {
		if hooks.beforeCandidateRead != nil {
			if err := hooks.beforeCandidateRead(item.logical); err != nil {
				rollback()
				return AddResult{}, fmt.Errorf("run pre-read hook for %q: %w", item.logical, err)
			}
		}
		if err := s.preflightCandidates(newCandidates, current.Entries, boundary); err != nil {
			rollback()
			return AddResult{}, fmt.Errorf("recheck add candidates before reading %q: %w", item.logical, err)
		}
		contents, openedMode, err := s.readCandidate(item, current.Entries, boundary)
		if err != nil {
			rollback()
			return AddResult{}, fmt.Errorf("read %q: %w", item.absolute, err)
		}
		storedContents := contents
		fileMode := os.FileMode(0o644)
		if openedMode.Perm()&0o111 != 0 {
			fileMode = 0o755
		}
		if options.Sensitive {
			storedContents, err = cryptox.Encrypt(masterKey, item.logical, contents)
			cryptox.ZeroBytes(contents)
			if err != nil {
				rollback()
				return AddResult{}, fmt.Errorf("encrypt %q: %w", item.logical, err)
			}
			fileMode = 0o600
		}

		if err := repo.WriteNewSource(item.source, storedContents, fileMode); err != nil {
			if options.Sensitive {
				cryptox.ZeroBytes(storedContents)
			}
			rollback()
			return AddResult{}, fmt.Errorf("store %q: %w", item.logical, err)
		}
		if options.Sensitive {
			cryptox.ZeroBytes(storedContents)
		}
		created = append(created, item.source)
		updated.Entries = append(updated.Entries, manifest.Entry{
			Path:             item.logical,
			Source:           item.source,
			Sensitive:        options.Sensitive,
			ExcludePlatforms: append([]string(nil), exclusions...),
		})
		result.Added = append(result.Added, item.logical)
	}

	if err := s.preflightCandidates(newCandidates, current.Entries, boundary); err != nil {
		rollback()
		return AddResult{}, fmt.Errorf("recheck add candidates before committing susu.json: %w", err)
	}
	if err := repo.SaveManifest(updated); err != nil {
		if !errors.Is(err, manifest.ErrCommitted) {
			rollback()
			return AddResult{}, err
		}
		return result, err
	}
	return result, nil
}

// RemoveResult reports paths that stopped being managed.
type RemoveResult struct {
	Removed []string
}

// Remove removes exact entries and their repository copies, never destinations.
func (s *Service) Remove(inputs []string) (RemoveResult, error) {
	if len(inputs) == 0 {
		return RemoveResult{}, errors.New("rm requires at least one path")
	}
	repo, current, release, err := s.openLocked()
	if err != nil {
		return RemoveResult{}, err
	}
	defer func() { _ = release() }()

	requested := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		logical, err := s.paths.Normalize(input)
		if err != nil {
			return RemoveResult{}, fmt.Errorf("normalize %q: %w", input, err)
		}
		requested[logical] = struct{}{}
	}
	ordered := make([]string, 0, len(requested))
	for logical := range requested {
		ordered = append(ordered, logical)
	}
	sort.Strings(ordered)

	entries := make(map[string]manifest.Entry, len(current.Entries))
	for _, entry := range current.Entries {
		entries[entry.Path] = entry
	}
	for _, logical := range ordered {
		if _, exists := entries[logical]; !exists {
			return RemoveResult{}, fmt.Errorf("%w: %s", ErrNotManaged, logical)
		}
	}

	for _, logical := range ordered {
		file, err := repo.OpenSource(entries[logical].Source)
		if err != nil {
			return RemoveResult{}, err
		}
		if err := file.Close(); err != nil {
			return RemoveResult{}, fmt.Errorf("close repository source %q: %w", entries[logical].Source, err)
		}
	}

	updated := current
	updated.Entries = make([]manifest.Entry, 0, len(current.Entries)-len(ordered))
	for _, entry := range current.Entries {
		if _, remove := requested[entry.Path]; !remove {
			updated.Entries = append(updated.Entries, entry)
		}
	}
	saveErr := repo.SaveManifest(updated)
	if saveErr != nil && !errors.Is(saveErr, manifest.ErrCommitted) {
		return RemoveResult{}, saveErr
	}
	var cleanupErrors []error
	for _, logical := range ordered {
		if err := repo.RemoveSource(entries[logical].Source); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("manifest no longer manages %q, but removing its stored copy failed: %w", logical, err))
		}
	}
	result := RemoveResult{Removed: ordered}
	if saveErr != nil || len(cleanupErrors) > 0 {
		allErrors := append([]error{saveErr}, cleanupErrors...)
		return result, errors.Join(allErrors...)
	}
	return result, nil
}

// List returns a sorted copy of every managed entry.
func (s *Service) List() ([]manifest.Entry, error) {
	_, current, release, err := s.openLocked()
	if err != nil {
		return nil, err
	}
	defer func() { _ = release() }()
	entries := append([]manifest.Entry(nil), current.Entries...)
	manifest.SortEntries(entries)
	return entries, nil
}

// Show writes one repository version to output without modifying its destination.
func (s *Service) Show(input string, output io.Writer, passwordProvider PasswordProvider) error {
	if output == nil {
		return errors.New("show output is nil")
	}
	repo, current, release, err := s.openLocked()
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	logical, err := s.paths.Normalize(input)
	if err != nil {
		return fmt.Errorf("normalize %q: %w", input, err)
	}
	index := manifest.Find(current, logical)
	if index < 0 {
		return fmt.Errorf("%w: %s", ErrNotManaged, logical)
	}
	entry := current.Entries[index]
	if !entry.Sensitive {
		file, err := repo.OpenSource(entry.Source)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := io.Copy(output, file); err != nil {
			return fmt.Errorf("write %s to stdout: %w", logical, err)
		}
		return nil
	}

	masterKey, err := unlock(current, passwordProvider)
	if err != nil {
		return err
	}
	defer cryptox.ZeroBytes(masterKey)
	encrypted, err := repo.ReadSource(entry.Source, maxRepositoryFileSize)
	if err != nil {
		return err
	}
	plaintext, err := cryptox.Decrypt(masterKey, entry.Path, encrypted)
	if err != nil {
		return fmt.Errorf("decrypt %q: %w", entry.Path, err)
	}
	defer cryptox.ZeroBytes(plaintext)
	if err := writeAll(output, plaintext); err != nil {
		return fmt.Errorf("write %s to stdout: %w", logical, err)
	}
	return nil
}

// ApplyResult reports applicable restored paths and platform-filtered paths.
type ApplyResult struct {
	Applied []string
	Skipped []string
}

type applyDestination struct {
	entry    manifest.Entry
	root     string
	relative string
}

type applyHooks struct {
	afterSourcePreflight     func() error
	beforeDestinationReplace func(logical string) error
}

func (s *Service) resolveApplyDestinations(entries []manifest.Entry) ([]applyDestination, error) {
	destinations := make([]applyDestination, 0, len(entries))
	for _, entry := range entries {
		rootPath, relative, err := s.paths.SplitLogical(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve destination %q: %w", entry.Path, err)
		}
		destinations = append(destinations, applyDestination{entry: entry, root: rootPath, relative: relative})
	}
	return destinations, nil
}

func (s *Service) ensureApplyDestinationsSafe(destinations []applyDestination, boundary *controlBoundary) error {
	for _, destination := range destinations {
		if err := boundary.ensureOutside(filepath.Join(destination.root, destination.relative)); err != nil {
			return fmt.Errorf("apply destination %q: %w; remove the protected entry with 'susu rm <path>' before applying", destination.entry.Path, err)
		}
	}
	return s.ensureNoApplyDestinationConflicts(destinations)
}

func (s *Service) ensureNoApplyDestinationConflicts(destinations []applyDestination) error {
	owners := make(map[string]string, len(destinations))
	for _, destination := range destinations {
		comparisonRoot, err := canonicalProspectivePath(destination.root)
		if err != nil {
			return fmt.Errorf("resolve destination root for %q: %w", destination.entry.Path, err)
		}
		comparison, err := paths.ComparisonKey(filepath.Join(comparisonRoot, destination.relative), s.platform)
		if err != nil {
			return fmt.Errorf("compare destination %q: %w", destination.entry.Path, err)
		}
		if existing, exists := owners[comparison]; exists {
			return destinationConflict(existing, destination.entry.Path)
		}
		owners[comparison] = destination.entry.Path
	}

	comparisons := make([]string, 0, len(owners))
	for comparison := range owners {
		comparisons = append(comparisons, comparison)
	}
	sort.Strings(comparisons)
	for _, comparison := range comparisons {
		for parent := filepath.Dir(comparison); ; {
			if owner, exists := owners[parent]; exists {
				return destinationConflict(owner, owners[comparison])
			}
			next := filepath.Dir(parent)
			if next == parent {
				break
			}
			parent = next
		}
	}
	return nil
}

// Apply restores repository versions to their runtime destinations. It first
// preflights every applicable source and authenticates every ciphertext, so
// repository corruption cannot cause a half-applied invocation.
func (s *Service) Apply(passwordProvider PasswordProvider) (ApplyResult, error) {
	return s.applyWithHooks(passwordProvider, applyHooks{})
}

func (s *Service) applyWithHooks(passwordProvider PasswordProvider, hooks applyHooks) (ApplyResult, error) {
	repo, current, release, err := s.openLocked()
	if err != nil {
		return ApplyResult{}, err
	}
	defer func() { _ = release() }()
	entries := append([]manifest.Entry(nil), current.Entries...)
	manifest.SortEntries(entries)

	applicable := make([]manifest.Entry, 0, len(entries))
	result := ApplyResult{}
	hasSensitive := false
	for _, entry := range entries {
		if excluded(entry, s.platform) {
			result.Skipped = append(result.Skipped, entry.Path)
			continue
		}
		applicable = append(applicable, entry)
		hasSensitive = hasSensitive || entry.Sensitive
	}
	boundary, err := s.loadControlBoundary(repo)
	if err != nil {
		return result, err
	}
	destinations, err := s.resolveApplyDestinations(applicable)
	if err != nil {
		return result, err
	}
	if err := s.ensureApplyDestinationsSafe(destinations, boundary); err != nil {
		return result, err
	}

	var masterKey []byte
	if hasSensitive {
		masterKey, err = unlock(current, passwordProvider)
		if err != nil {
			return result, err
		}
		defer cryptox.ZeroBytes(masterKey)
	}
	if err := s.ensureApplyDestinationsSafe(destinations, boundary); err != nil {
		return result, err
	}

	type preparedFile struct {
		entry         manifest.Entry
		root          string
		relative      string
		contents      []byte
		source        *os.File
		fileMode      os.FileMode
		directoryMode os.FileMode
	}
	prepared := make([]preparedFile, 0, len(destinations))
	defer func() {
		for index := range prepared {
			if prepared[index].source != nil {
				_ = prepared[index].source.Close()
			}
			if prepared[index].entry.Sensitive {
				cryptox.ZeroBytes(prepared[index].contents)
			}
		}
	}()

	var sensitiveBytes int64
	for _, destination := range destinations {
		entry := destination.entry
		var contents []byte
		var sourceFile *os.File
		fileMode := os.FileMode(0o644)
		directoryMode := os.FileMode(0o755)
		if entry.Sensitive {
			stored, _, err := readStoredFile(repo, entry.Source)
			if err != nil {
				return result, err
			}
			contents, err = cryptox.Decrypt(masterKey, entry.Path, stored)
			if err != nil {
				return result, fmt.Errorf("decrypt %q: %w", entry.Path, err)
			}
			sensitiveBytes += int64(len(contents))
			if sensitiveBytes > maxApplySensitiveBytes {
				cryptox.ZeroBytes(contents)
				return result, fmt.Errorf("applicable sensitive plaintext exceeds v0.1 aggregate preflight limit of %d bytes", maxApplySensitiveBytes)
			}
			fileMode = 0o600
			directoryMode = 0o700
		} else {
			var err error
			sourceFile, fileMode, err = openStoredFile(repo, entry.Source)
			if err != nil {
				return result, err
			}
		}
		prepared = append(prepared, preparedFile{
			entry: entry, root: destination.root, relative: destination.relative,
			contents: contents, source: sourceFile,
			fileMode: fileMode, directoryMode: directoryMode,
		})
	}

	if hooks.afterSourcePreflight != nil {
		if err := hooks.afterSourcePreflight(); err != nil {
			return result, fmt.Errorf("run post-source-preflight hook: %w", err)
		}
	}
	if err := s.ensureApplyDestinationsSafe(destinations, boundary); err != nil {
		return result, err
	}

	for index := range prepared {
		item := &prepared[index]
		if hooks.beforeDestinationReplace != nil {
			if err := hooks.beforeDestinationReplace(item.entry.Path); err != nil {
				return result, fmt.Errorf("run pre-replacement hook for %q after restoring %d file(s): %w", item.entry.Path, len(result.Applied), err)
			}
		}
		if err := s.ensureApplyDestinationsSafe(destinations, boundary); err != nil {
			return result, fmt.Errorf("recheck apply destinations after restoring %d file(s): %w", len(result.Applied), err)
		}
		write := func(writer io.Writer) error {
			if item.entry.Sensitive {
				return writeAll(writer, item.contents)
			}
			if _, err := item.source.Seek(0, io.SeekStart); err != nil {
				return err
			}
			_, err := io.Copy(writer, item.source)
			return err
		}
		committed, err := atomicReplaceRooted(item.root, item.relative, item.fileMode, item.directoryMode, write)
		if committed {
			result.Applied = append(result.Applied, item.entry.Path)
			if item.entry.Sensitive {
				cryptox.ZeroBytes(item.contents)
				item.contents = nil
			} else {
				_ = item.source.Close()
				item.source = nil
			}
		}
		if err != nil {
			return result, fmt.Errorf("apply %q after restoring %d file(s): %w", item.entry.Path, len(result.Applied), err)
		}
	}
	return result, nil
}

func (s *Service) openLocked() (*repository.Repository, manifest.Manifest, func() error, error) {
	configuredRoot, err := s.state.Load()
	if err != nil {
		return nil, manifest.Manifest{}, nil, fmt.Errorf("load active repository: %w; run 'susu init <repository>'", err)
	}
	configuredRepository, err := repository.Open(configuredRoot)
	if err != nil {
		return nil, manifest.Manifest{}, nil, err
	}
	if err := s.ensureStateOutsideRepository(configuredRepository); err != nil {
		return nil, manifest.Manifest{}, nil, err
	}
	release, err := s.state.Lock()
	if err != nil {
		return nil, manifest.Manifest{}, nil, err
	}

	configuredRoot, err = s.state.Load()
	if err != nil {
		_ = release()
		return nil, manifest.Manifest{}, nil, fmt.Errorf("reload active repository under lock: %w", err)
	}
	repo, err := repository.Open(configuredRoot)
	if err != nil {
		_ = release()
		return nil, manifest.Manifest{}, nil, err
	}
	if err := s.ensureStateOutsideRepository(repo); err != nil {
		_ = release()
		return nil, manifest.Manifest{}, nil, err
	}
	releaseRepository, err := repo.Lock()
	if err != nil {
		_ = release()
		return nil, manifest.Manifest{}, nil, err
	}
	current, err := repo.LoadManifest()
	if err != nil {
		_ = releaseRepository()
		_ = release()
		return nil, manifest.Manifest{}, nil, err
	}
	combinedRelease := func() error {
		return errors.Join(releaseRepository(), release())
	}
	return repo, current, combinedRelease, nil
}

func (s *Service) collectCandidates(inputs []string, sensitive bool, boundary *controlBoundary) ([]candidate, error) {
	ignorePolicy, err := s.loadAddIgnorePolicy()
	if err != nil {
		return nil, err
	}
	byLogical := make(map[string]candidate)
	bySource := make(map[string]string)
	for _, input := range inputs {
		logical, err := s.paths.Normalize(input)
		if err != nil {
			return nil, fmt.Errorf("normalize %q: %w", input, err)
		}
		rootPath, relative, err := s.paths.SplitLogical(logical)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", input, err)
		}
		absolute := filepath.Join(rootPath, relative)
		if err := boundary.ensureOutside(absolute); err != nil {
			return nil, fmt.Errorf("add input %q: %w; choose a narrower input path", input, err)
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			return nil, fmt.Errorf("open path root for %q: %w", absolute, err)
		}
		name := rootedName(relative)
		if err := rejectSymlinkComponents(root, name, false); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("inspect %q: %w", absolute, err)
		}
		info, err := root.Lstat(name)
		if err != nil {
			_ = root.Close()
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("path does not exist: %q", absolute)
			}
			return nil, fmt.Errorf("inspect %q: %w", absolute, err)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, fmt.Errorf("path %q is a symlink; susu v0.1 manages regular files and real directories only", absolute)
		}
		if info.IsDir() {
			start := filepath.ToSlash(name)
			err = fs.WalkDir(root.FS(), start, func(filename string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				childRelative := filepath.FromSlash(filename)
				childAbsolute := filepath.Join(rootPath, childRelative)
				if entry.IsDir() {
					ignored, ignoreErr := ignorePolicy.ignores(childAbsolute)
					if ignoreErr != nil {
						return fmt.Errorf("check built-in ignore policy for %q: %w", childAbsolute, ignoreErr)
					}
					if ignored {
						return fs.SkipDir
					}
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return nil
				}
				entryInfo, infoErr := entry.Info()
				if infoErr != nil {
					return infoErr
				}
				if !entryInfo.Mode().IsRegular() {
					return nil
				}
				return s.addCandidate(byLogical, bySource, rootPath, childRelative, childAbsolute, sensitive, boundary, ignorePolicy)
			})
			closeErr := root.Close()
			if err != nil {
				return nil, fmt.Errorf("walk directory %q: %w", absolute, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close path root for %q: %w", absolute, closeErr)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			_ = root.Close()
			return nil, fmt.Errorf("path %q is not a regular file or directory", absolute)
		}
		if err := root.Close(); err != nil {
			return nil, fmt.Errorf("close path root for %q: %w", absolute, err)
		}
		if err := s.addCandidate(byLogical, bySource, rootPath, relative, absolute, sensitive, boundary, ignorePolicy); err != nil {
			return nil, err
		}
	}

	result := make([]candidate, 0, len(byLogical))
	for _, item := range byLogical {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].logical < result[j].logical })
	return result, nil
}

func (s *Service) addCandidate(byLogical map[string]candidate, bySource map[string]string, root, relative, absolute string, sensitive bool, boundary *controlBoundary, ignorePolicy addIgnorePolicy) error {
	if err := boundary.ensureOutside(absolute); err != nil {
		return fmt.Errorf("add discovered file %q: %w", absolute, err)
	}
	ignored, err := ignorePolicy.ignores(absolute)
	if err != nil {
		return fmt.Errorf("check built-in ignore policy for %q: %w", absolute, err)
	}
	if ignored {
		return nil
	}
	logical, err := s.paths.Normalize(absolute)
	if err != nil {
		return fmt.Errorf("normalize discovered file %q: %w", absolute, err)
	}
	source, err := manifest.SourceFor(logical, sensitive)
	if err != nil {
		return err
	}
	if _, exists := byLogical[logical]; exists {
		return nil
	}
	if existingLogical, exists := bySource[source]; exists && existingLogical != logical {
		return fmt.Errorf("paths %q and %q map to the same repository source %q", existingLogical, logical, source)
	}

	item := candidate{absolute: absolute, root: root, relative: relative, logical: logical, source: source}
	file, info, err := openCandidate(item, boundary)
	if err != nil {
		return fmt.Errorf("inspect discovered file %q: %w", absolute, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close discovered file %q: %w", absolute, err)
	}
	item.identity = info
	bySource[source] = logical
	byLogical[logical] = item
	return nil
}

func (s *Service) loadAddIgnorePolicy() (addIgnorePolicy, error) {
	kubeCachePath, err := s.paths.Resolve(kubeCacheLogicalPath)
	if err != nil {
		return addIgnorePolicy{}, fmt.Errorf("resolve built-in Kubernetes cache exclusion: %w", err)
	}
	policy := addIgnorePolicy{kubeCachePath: kubeCachePath}
	info, err := os.Lstat(kubeCachePath)
	if err == nil && info.IsDir() {
		policy.kubeCacheInfo = info
	}
	return policy, nil
}

func (p addIgnorePolicy) ignores(candidate string) (bool, error) {
	within, err := pathWithin(p.kubeCachePath, candidate)
	if err != nil || within || p.kubeCacheInfo == nil {
		return within, err
	}
	return physicalAncestorMatches(p.kubeCacheInfo, candidate)
}

func normalizePlatforms(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := ValidatePlatform(value); err != nil {
			return nil, err
		}
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func unlock(current manifest.Manifest, provider PasswordProvider) ([]byte, error) {
	if current.Crypto == nil {
		return nil, fmt.Errorf("%w: sensitive entries have no crypto metadata", manifest.ErrInvalidManifest)
	}
	if provider == nil {
		return nil, ErrPasswordRequired
	}
	password, err := provider(false)
	if err != nil {
		return nil, fmt.Errorf("read repository password: %w", err)
	}
	defer cryptox.ZeroBytes(password)
	return cryptox.Unlock(password, *current.Crypto)
}

func excluded(entry manifest.Entry, platform string) bool {
	for _, excludedPlatform := range entry.ExcludePlatforms {
		if excludedPlatform == platform {
			return true
		}
	}
	return false
}

func (s *Service) loadManagedFileIdentities(entries []manifest.Entry) ([]managedFileIdentity, error) {
	identities := make([]managedFileIdentity, 0, len(entries))
	for _, entry := range entries {
		rootPath, relative, err := s.paths.SplitLogical(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve managed destination %q: %w", entry.Path, err)
		}
		absolute := filepath.Join(rootPath, relative)
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect managed destination %q: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		identities = append(identities, managedFileIdentity{logical: entry.Path, info: info})
	}
	return identities, nil
}

func physicalIdentityOwner(info fs.FileInfo, identities []managedFileIdentity) (string, bool) {
	if info == nil {
		return "", false
	}
	for _, identity := range identities {
		if os.SameFile(info, identity.info) {
			return identity.logical, true
		}
	}
	return "", false
}

func destinationConflict(first, second string) error {
	return fmt.Errorf("%w between %q and %q", ErrDestinationConflict, first, second)
}

func (s *Service) preflightCandidates(candidates []candidate, entries []manifest.Entry, boundary *controlBoundary) error {
	managedIdentities, err := s.loadManagedFileIdentities(entries)
	if err != nil {
		return err
	}
	openedIdentities := make([]managedFileIdentity, 0, len(candidates))
	for _, item := range candidates {
		file, info, err := openCandidate(item, boundary)
		if err != nil {
			return fmt.Errorf("preflight %q: %w", item.absolute, err)
		}
		if existing, exists := physicalIdentityOwner(info, managedIdentities); exists {
			_ = file.Close()
			return destinationConflict(existing, item.logical)
		}
		if existing, exists := physicalIdentityOwner(info, openedIdentities); exists {
			_ = file.Close()
			return destinationConflict(existing, item.logical)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close preflight source %q: %w", item.absolute, err)
		}
		openedIdentities = append(openedIdentities, managedFileIdentity{logical: item.logical, info: info})
	}
	return nil
}

func (s *Service) readCandidate(item candidate, entries []manifest.Entry, boundary *controlBoundary) ([]byte, os.FileMode, error) {
	file, info, err := openCandidate(item, boundary)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	managedIdentities, err := s.loadManagedFileIdentities(entries)
	if err != nil {
		return nil, 0, err
	}
	if existing, exists := physicalIdentityOwner(info, managedIdentities); exists {
		return nil, 0, destinationConflict(existing, item.logical)
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxManagedFileSize+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(contents)) > maxManagedFileSize {
		return nil, 0, fmt.Errorf("file exceeds v0.1 limit of %d bytes", maxManagedFileSize)
	}
	return contents, info.Mode(), nil
}

func openCandidate(item candidate, boundary *controlBoundary) (*os.File, fs.FileInfo, error) {
	if err := boundary.ensureOutside(item.absolute); err != nil {
		return nil, nil, err
	}
	file, err := safefs.OpenRegular(item.root, item.relative)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("path changed and is no longer a regular file")
	}
	if err := boundary.ensureOpenedFileOutside(item.absolute, info); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if item.identity != nil && !os.SameFile(item.identity, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: add candidate %q changed physical identity while the command was running", ErrDestinationConflict, item.logical)
	}
	if info.Size() > maxManagedFileSize {
		_ = file.Close()
		return nil, nil, fmt.Errorf("file is %d bytes, v0.1 limit is %d", info.Size(), maxManagedFileSize)
	}
	return file, info, nil
}

func openStoredFile(repo *repository.Repository, source string) (*os.File, os.FileMode, error) {
	file, err := repo.OpenSource(source)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("inspect repository source %q: %w", source, err)
	}
	if info.Size() > maxRepositoryFileSize {
		_ = file.Close()
		return nil, 0, fmt.Errorf("repository source %q is %d bytes, limit is %d", source, info.Size(), maxRepositoryFileSize)
	}
	mode := os.FileMode(0o644)
	if info.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}
	return file, mode, nil
}

func readStoredFile(repo *repository.Repository, source string) ([]byte, os.FileMode, error) {
	file, mode, err := openStoredFile(repo, source)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxRepositoryFileSize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read repository source %q: %w", source, err)
	}
	if int64(len(contents)) > maxRepositoryFileSize {
		return nil, 0, fmt.Errorf("repository source %q exceeds %d bytes", source, maxRepositoryFileSize)
	}
	return contents, mode, nil
}

type atomicReplaceHooks struct {
	afterRename     func(temporaryName string) error
	syncFile        func(file *os.File) error
	closeFile       func(file *os.File) error
	rename          func(directory *safefs.Directory, oldName, newName string) error
	syncDirectory   func(directory *safefs.Directory) error
	removeTemporary func(directory *safefs.Directory, name string) error
}

// atomicReplaceRooted returns committed=true once the final rename has happened,
// even if the subsequent directory durability check reports an error.
func atomicReplaceRooted(rootPath, relative string, fileMode, directoryMode os.FileMode, write func(io.Writer) error) (committed bool, err error) {
	return atomicReplaceRootedWithHooks(rootPath, relative, fileMode, directoryMode, write, atomicReplaceHooks{})
}

func atomicReplaceRootedWithHooks(rootPath, relative string, fileMode, directoryMode os.FileMode, write func(io.Writer) error, hooks atomicReplaceHooks) (committed bool, err error) {
	if relative == "" || filepath.IsAbs(relative) {
		return false, errors.New("destination must be a non-empty path below its logical root")
	}
	if err := os.MkdirAll(rootPath, directoryMode); err != nil {
		return false, fmt.Errorf("create destination root %q: %w", rootPath, err)
	}
	directory, leaf, err := safefs.OpenParent(rootPath, relative, true, directoryMode)
	if err != nil {
		return false, fmt.Errorf("open destination parent without following symlinks: %w", err)
	}
	defer directory.Close()
	file, temporaryName, err := directory.CreateTempExcluding(".susu-apply-", fileMode, leaf)
	if err != nil {
		return false, err
	}
	syncFile := hooks.syncFile
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	closeFile := hooks.closeFile
	if closeFile == nil {
		closeFile = (*os.File).Close
	}
	rename := hooks.rename
	if rename == nil {
		rename = (*safefs.Directory).Rename
	}
	syncDirectory := hooks.syncDirectory
	if syncDirectory == nil {
		syncDirectory = (*safefs.Directory).Sync
	}
	removeTemporaryFile := hooks.removeTemporary
	if removeTemporaryFile == nil {
		removeTemporaryFile = (*safefs.Directory).Remove
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = removeTemporaryFile(directory, temporaryName)
		}
	}()
	if err := write(file); err != nil {
		return false, err
	}
	if err := syncFile(file); err != nil {
		return false, err
	}
	if err := closeFile(file); err != nil {
		return false, err
	}
	if err := rename(directory, temporaryName, leaf); err != nil {
		return false, err
	}
	removeTemporary = false
	if hooks.afterRename != nil {
		if err := hooks.afterRename(temporaryName); err != nil {
			return true, fmt.Errorf("run post-rename hook: %w", err)
		}
	}
	if err := syncDirectory(directory); err != nil {
		return true, fmt.Errorf("destination was replaced but directory sync failed: %w", err)
	}
	return true, nil
}

func rejectSymlinkComponents(root *os.Root, relative string, allowMissing bool) error {
	clean := filepath.Clean(relative)
	if clean == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
	}
	return nil
}

func rootedName(relative string) string {
	if relative == "" {
		return "."
	}
	return relative
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

func (s *Service) loadControlBoundary(repo *repository.Repository) (*controlBoundary, error) {
	stateBoundary, err := s.loadLocalStateBoundary()
	if err != nil {
		return nil, err
	}
	repositoryBoundary, err := loadRepositoryBoundary(repo)
	if err != nil {
		return nil, err
	}
	return &controlBoundary{localState: stateBoundary, repository: repositoryBoundary}, nil
}

func loadRepositoryBoundary(repo *repository.Repository) (*repositoryBoundary, error) {
	if repo == nil {
		return nil, errors.New("repository is nil")
	}
	locations := []struct {
		path  string
		label string
	}{
		{path: repo.Root, label: "repository worktree"},
		{path: repo.GitCommonDirectory(), label: "Git common directory"},
	}
	boundary := &repositoryBoundary{roots: make([]repositoryProtectedRoot, 0, len(locations))}
	for _, location := range locations {
		canonical, err := canonicalProspectivePath(location.path)
		if err != nil {
			return nil, fmt.Errorf("resolve active %s %q: %w", location.label, location.path, err)
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return nil, fmt.Errorf("inspect active %s %q: %w", location.label, canonical, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("active %s %q is not a directory", location.label, canonical)
		}
		boundary.roots = append(boundary.roots, repositoryProtectedRoot{path: canonical, label: location.label, info: info})
	}
	return boundary, nil
}

func (b *controlBoundary) ensureOutside(candidate string) error {
	if err := b.localState.ensureOutside(candidate); err != nil {
		return err
	}
	return b.repository.ensureOutside(candidate)
}

func (b *controlBoundary) ensureOpenedFileOutside(candidate string, candidateInfo fs.FileInfo) error {
	if err := b.localState.ensureFileOutside(candidate, candidateInfo); err != nil {
		return err
	}
	return b.repository.ensureOutside(candidate)
}

func (b *repositoryBoundary) ensureOutside(candidate string) error {
	for _, root := range b.roots {
		currentInfo, err := os.Stat(root.path)
		if err != nil {
			return fmt.Errorf("verify active %s %q: %w", root.label, root.path, err)
		}
		if !currentInfo.IsDir() || !os.SameFile(currentInfo, root.info) {
			return fmt.Errorf("%w: active %s %q changed while the command was running", ErrProtectedRepository, root.label, root.path)
		}
		overlaps, err := pathsOverlap(root.path, candidate)
		if err != nil {
			return fmt.Errorf("verify active %s boundary for %q: %w", root.label, candidate, err)
		}
		if overlaps {
			return fmt.Errorf("%w: %q overlaps or aliases active %s %q", ErrProtectedRepository, candidate, root.label, root.path)
		}
	}
	return nil
}

func (s *Service) loadLocalStateBoundary() (*localStateBoundary, error) {
	directory, err := canonicalProspectivePath(s.state.Directory())
	if err != nil {
		return nil, fmt.Errorf("resolve local state directory %q: %w", s.state.Directory(), err)
	}
	boundary := &localStateBoundary{directory: directory}
	if err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Stat(filename)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		boundary.files = append(boundary.files, info)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("inspect local state directory %q: %w", directory, err)
	}
	return boundary, nil
}

func (b *localStateBoundary) ensureOutside(candidate string) error {
	overlaps, err := pathsOverlap(b.directory, candidate)
	if err != nil {
		return fmt.Errorf("verify local state boundary for %q: %w", candidate, err)
	}
	if !overlaps {
		candidateInfo, statErr := os.Stat(candidate)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect candidate %q for local state aliases: %w", candidate, statErr)
		}
		if statErr == nil {
			if err := b.ensureFileOutside(candidate, candidateInfo); err != nil {
				return err
			}
		}
	}
	if overlaps {
		return b.protectedError(candidate)
	}
	return nil
}

func (b *localStateBoundary) ensureFileOutside(candidate string, candidateInfo fs.FileInfo) error {
	for _, protectedInfo := range b.files {
		if os.SameFile(candidateInfo, protectedInfo) {
			return b.protectedError(candidate)
		}
	}
	return nil
}

func (b *localStateBoundary) protectedError(candidate string) error {
	return fmt.Errorf("%w: %q overlaps or aliases local state directory %q", ErrProtectedLocalState, candidate, b.directory)
}

func pathsOverlap(first, second string) (bool, error) {
	canonicalFirst, err := canonicalProspectivePath(first)
	if err != nil {
		return false, err
	}
	canonicalSecond, err := canonicalProspectivePath(second)
	if err != nil {
		return false, err
	}
	firstContainsSecond, err := pathWithin(canonicalFirst, canonicalSecond)
	if err != nil {
		return false, err
	}
	secondContainsFirst, err := pathWithin(canonicalSecond, canonicalFirst)
	if err != nil {
		return false, err
	}
	if firstContainsSecond || secondContainsFirst {
		return true, nil
	}
	firstPhysicallyContainsSecond, err := physicalAncestorWithinIfExists(first, second)
	if err != nil {
		return false, err
	}
	secondPhysicallyContainsFirst, err := physicalAncestorWithinIfExists(second, first)
	if err != nil {
		return false, err
	}
	return firstPhysicallyContainsSecond || secondPhysicallyContainsFirst, nil
}

func physicalAncestorWithinIfExists(root, target string) (bool, error) {
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return physicalAncestorWithin(root, target)
}

func (s *Service) ensureStateOutsideRepository(repo *repository.Repository) error {
	stateDirectory, err := canonicalProspectivePath(s.state.Directory())
	if err != nil {
		return fmt.Errorf("resolve local state directory %q: %w", s.state.Directory(), err)
	}
	locations := []struct {
		path  string
		label string
	}{
		{path: repo.Root, label: "repository worktree"},
		{path: repo.GitCommonDirectory(), label: "Git common directory"},
	}
	for _, location := range locations {
		overlaps, err := pathsOverlap(stateDirectory, location.path)
		if err != nil {
			return fmt.Errorf("verify local state against active %s: %w", location.label, err)
		}
		if overlaps {
			return fmt.Errorf("local state directory %q must not be stored inside or otherwise overlap active %s %q; choose an XDG_STATE_HOME outside repository and Git metadata", stateDirectory, location.label, location.path)
		}
	}
	return nil
}

func canonicalProspectivePath(input string) (string, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	probe := absolute
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", err
		}
		suffix = append(suffix, filepath.Base(probe))
		probe = parent
	}
}

func physicalAncestorWithin(root, target string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, err
	}
	return physicalAncestorMatches(rootInfo, target)
}

func physicalAncestorMatches(rootInfo fs.FileInfo, target string) (bool, error) {
	probe, err := filepath.Abs(target)
	if err != nil {
		return false, err
	}
	for {
		info, statErr := os.Stat(probe)
		if statErr == nil {
			for {
				if os.SameFile(rootInfo, info) {
					return true, nil
				}
				parent := filepath.Dir(probe)
				if parent == probe {
					return false, nil
				}
				probe = parent
				info, statErr = os.Stat(probe)
				if statErr != nil {
					return false, statErr
				}
			}
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return false, statErr
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return false, statErr
		}
		probe = parent
	}
}

func pathWithin(root, target string) (bool, error) {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

// FormatEntry renders one stable, human-readable list line.
func FormatEntry(entry manifest.Entry) string {
	var annotations []string
	if entry.Sensitive {
		annotations = append(annotations, "sensitive")
	}
	if len(entry.ExcludePlatforms) > 0 {
		annotations = append(annotations, "exclude: "+strings.Join(entry.ExcludePlatforms, ", "))
	}
	if len(annotations) == 0 {
		return entry.Path
	}
	parts := make([]string, len(annotations))
	for index, annotation := range annotations {
		parts[index] = "[" + annotation + "]"
	}
	return entry.Path + " " + strings.Join(parts, " ")
}
