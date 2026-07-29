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
)

var (
	// ErrNotManaged indicates that an exact logical path is absent from susu.json.
	ErrNotManaged = errors.New("path is not managed")
	// ErrUnsupportedPlatform indicates a platform other than darwin or linux.
	ErrUnsupportedPlatform = errors.New("unsupported platform value")
	// ErrPasswordRequired indicates that an operation needs an interactive or injected password provider.
	ErrPasswordRequired = errors.New("repository password is required")
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
	if err := s.ensureStateOutsideRepository(repo.Root); err != nil {
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
	mode     os.FileMode
	source   string
}

// Add starts managing regular files. Directories are recursively expanded into
// individual entries; existing entries are skipped without overwriting storage.
func (s *Service) Add(inputs []string, options AddOptions) (AddResult, error) {
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

	candidates, err := s.collectCandidates(inputs, options.Sensitive)
	if err != nil {
		return AddResult{}, err
	}
	managed := make(map[string]manifest.Entry, len(current.Entries))
	sources := make(map[string]string, len(current.Entries))
	for _, entry := range current.Entries {
		managed[entry.Path] = entry
		sources[entry.Source] = entry.Path
	}

	result := AddResult{}
	newCandidates := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		if _, exists := managed[item.logical]; exists {
			result.AlreadyManaged = append(result.AlreadyManaged, item.logical)
			continue
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

	created := make([]string, 0, len(newCandidates))
	rollback := func() {
		for _, source := range created {
			_ = repo.RemoveSource(source)
		}
	}
	for _, item := range newCandidates {
		contents, openedMode, err := readCandidate(item)
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

// Apply restores repository versions to their runtime destinations. It first
// preflights every applicable source and authenticates every ciphertext, so
// repository corruption cannot cause a half-applied invocation.
func (s *Service) Apply(passwordProvider PasswordProvider) (ApplyResult, error) {
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

	var masterKey []byte
	if hasSensitive {
		masterKey, err = unlock(current, passwordProvider)
		if err != nil {
			return result, err
		}
		defer cryptox.ZeroBytes(masterKey)
	}

	type preparedFile struct {
		entry         manifest.Entry
		root          string
		relative      string
		comparison    string
		contents      []byte
		source        *os.File
		fileMode      os.FileMode
		directoryMode os.FileMode
	}
	prepared := make([]preparedFile, 0, len(applicable))
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
	for _, entry := range applicable {
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
		rootPath, relative, err := s.paths.SplitLogical(entry.Path)
		if err != nil {
			if sourceFile != nil {
				_ = sourceFile.Close()
			}
			if entry.Sensitive {
				cryptox.ZeroBytes(contents)
			}
			return result, fmt.Errorf("resolve destination %q: %w", entry.Path, err)
		}
		comparisonRoot, err := canonicalProspectivePath(rootPath)
		if err != nil {
			if sourceFile != nil {
				_ = sourceFile.Close()
			}
			if entry.Sensitive {
				cryptox.ZeroBytes(contents)
			}
			return result, fmt.Errorf("resolve destination root for %q: %w", entry.Path, err)
		}
		prepared = append(prepared, preparedFile{
			entry: entry, root: rootPath, relative: relative,
			comparison: filepath.Join(comparisonRoot, relative),
			contents:   contents, source: sourceFile,
			fileMode: fileMode, directoryMode: directoryMode,
		})
	}
	destinationOwners := make(map[string]string, len(prepared))
	for _, item := range prepared {
		if existing, exists := destinationOwners[item.comparison]; exists {
			return result, fmt.Errorf("destination conflict between %q and %q", existing, item.entry.Path)
		}
		destinationOwners[item.comparison] = item.entry.Path
	}
	destinations := make([]string, 0, len(destinationOwners))
	for destination := range destinationOwners {
		destinations = append(destinations, destination)
	}
	sort.Strings(destinations)
	for _, destination := range destinations {
		for parent := filepath.Dir(destination); ; {
			if owner, exists := destinationOwners[parent]; exists {
				return result, fmt.Errorf("destination conflict between %q and %q", owner, destinationOwners[destination])
			}
			next := filepath.Dir(parent)
			if next == parent {
				break
			}
			parent = next
		}
	}

	for index := range prepared {
		item := &prepared[index]
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
	if err := s.ensureStateOutsideRepository(configuredRepository.Root); err != nil {
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
	if err := s.ensureStateOutsideRepository(repo.Root); err != nil {
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

func (s *Service) collectCandidates(inputs []string, sensitive bool) ([]candidate, error) {
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
				if filename == start || entry.IsDir() {
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
				childRelative := filepath.FromSlash(filename)
				childAbsolute := filepath.Join(rootPath, childRelative)
				return s.addCandidate(byLogical, bySource, rootPath, childRelative, childAbsolute, entryInfo.Mode(), sensitive)
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
		if err := s.addCandidate(byLogical, bySource, rootPath, relative, absolute, info.Mode(), sensitive); err != nil {
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

func (s *Service) addCandidate(byLogical map[string]candidate, bySource map[string]string, root, relative, absolute string, mode os.FileMode, sensitive bool) error {
	logical, err := s.paths.Normalize(absolute)
	if err != nil {
		return fmt.Errorf("normalize discovered file %q: %w", absolute, err)
	}
	source, err := manifest.SourceFor(logical, sensitive)
	if err != nil {
		return err
	}
	if existingLogical, exists := bySource[source]; exists && existingLogical != logical {
		return fmt.Errorf("paths %q and %q map to the same repository source %q", existingLogical, logical, source)
	}
	bySource[source] = logical
	if _, exists := byLogical[logical]; !exists {
		byLogical[logical] = candidate{absolute: absolute, root: root, relative: relative, logical: logical, mode: mode, source: source}
	}
	return nil
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

func readCandidate(item candidate) ([]byte, os.FileMode, error) {
	file, err := safefs.OpenRegular(item.root, item.relative)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("path changed and is no longer a regular file")
	}
	if info.Size() > maxManagedFileSize {
		return nil, 0, fmt.Errorf("file is %d bytes, v0.1 limit is %d", info.Size(), maxManagedFileSize)
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

// atomicReplaceRooted returns committed=true once the final rename has happened,
// even if the subsequent directory durability check reports an error.
func atomicReplaceRooted(rootPath, relative string, fileMode, directoryMode os.FileMode, write func(io.Writer) error) (committed bool, err error) {
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
	if err := cleanupDirectoryTemps(directory, ".susu-apply-"); err != nil {
		return false, fmt.Errorf("clean stale destination staging files: %w", err)
	}
	file, temporaryName, err := directory.CreateTemp(".susu-apply-", fileMode)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = file.Close()
		_ = directory.Remove(temporaryName)
	}()
	if err := write(file); err != nil {
		return false, err
	}
	if err := file.Sync(); err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := directory.Rename(temporaryName, leaf); err != nil {
		return false, err
	}
	if err := directory.Sync(); err != nil {
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

func cleanupDirectoryTemps(directory *safefs.Directory, prefix string) error {
	entries, err := directory.ReadDir()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		if err := directory.Remove(entry.Name()); err != nil {
			return err
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

func (s *Service) ensureStateOutsideRepository(repositoryRoot string) error {
	statePath, err := canonicalProspectivePath(s.state.Path())
	if err != nil {
		return fmt.Errorf("resolve local state path %q: %w", s.state.Path(), err)
	}
	inside, err := pathWithin(repositoryRoot, statePath)
	if err != nil {
		return err
	}
	physicalInside, err := physicalAncestorWithin(repositoryRoot, s.state.Path())
	if err != nil {
		return fmt.Errorf("verify local state filesystem location: %w", err)
	}
	if inside || physicalInside {
		return fmt.Errorf("local state path %q must not be stored inside repository %q; choose an XDG_STATE_HOME outside the repository", statePath, repositoryRoot)
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
