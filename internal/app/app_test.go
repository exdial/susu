package app_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"susu/internal/app"
	"susu/internal/cryptox"
	"susu/internal/manifest"
	"susu/internal/paths"
	"susu/internal/state"
)

const testPassword = "correct horse battery staple for integration tests"

var (
	realHome    string
	testSandbox string
)

func TestMain(m *testing.M) {
	realHome = os.Getenv("HOME")
	tempBase := os.TempDir()
	if realHome != "" && pathWithin(tempBase, realHome) {
		tempBase = "/tmp"
	}
	if realHome != "" && pathWithin(tempBase, realHome) {
		_, _ = fmt.Fprintf(os.Stderr, "cannot create app test sandbox outside real HOME %q\n", realHome)
		os.Exit(1)
	}

	var err error
	testSandbox, err = os.MkdirTemp(tempBase, "susu-app-integration-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create app test sandbox: %v\n", err)
		os.Exit(1)
	}

	isolatedEnvironment := map[string]string{
		"HOME":                filepath.Join(testSandbox, "guard-home"),
		"XDG_CONFIG_HOME":     filepath.Join(testSandbox, "guard-xdg-config"),
		"XDG_STATE_HOME":      filepath.Join(testSandbox, "guard-xdg-state"),
		"XDG_CACHE_HOME":      filepath.Join(testSandbox, "guard-xdg-cache"),
		"XDG_DATA_HOME":       filepath.Join(testSandbox, "guard-xdg-data"),
		"TMPDIR":              filepath.Join(testSandbox, "tmp"),
		"GIT_CONFIG_GLOBAL":   filepath.Join(testSandbox, "gitconfig"),
		"GIT_CONFIG_NOSYSTEM": "1",
	}
	for name, value := range isolatedEnvironment {
		if name != "GIT_CONFIG_NOSYSTEM" && name != "GIT_CONFIG_GLOBAL" {
			if err := os.MkdirAll(value, 0o700); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "create isolated %s directory: %v\n", name, err)
				_ = os.RemoveAll(testSandbox)
				os.Exit(1)
			}
		}
		if err := os.Setenv(name, value); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "set isolated %s: %v\n", name, err)
			_ = os.RemoveAll(testSandbox)
			os.Exit(1)
		}
	}

	code := m.Run()
	if err := os.RemoveAll(testSandbox); err != nil && code == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "remove app test sandbox: %v\n", err)
		code = 1
	}
	os.Exit(code)
}

func TestAddPublicFileStoresContent(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	contents := []byte("export EDITOR=vim\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".zshrc"), contents, 0o640)

	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	assertStrings(t, result.Added, []string{"~/.zshrc"})
	assertStrings(t, result.AlreadyManaged, nil)

	current := mustLoadManifest(t, environment)
	if len(current.Entries) != 1 {
		t.Fatalf("manifest entries = %d, want 1", len(current.Entries))
	}
	entry := current.Entries[0]
	if entry.Path != "~/.zshrc" || entry.Source != "public/.zshrc" || entry.Sensitive {
		t.Fatalf("manifest entry = %+v", entry)
	}

	stored := filepath.Join(environment.repository, "public", ".zshrc")
	assertFileContents(t, stored, contents)
	assertPermissions(t, stored, 0o644)
	assertPathDoesNotExist(t, filepath.Join(environment.repository, "encrypted", ".zshrc.enc"))
}

func TestAddSensitiveFileEncryptsRepositoryCopy(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	plaintext := []byte("integration-secret-7fd978f9f8d14a8a\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".credentials"), plaintext, 0o600)
	var passwordCalls []bool

	result, err := environment.service.Add([]string{destination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	assertStrings(t, result.Added, []string{"~/.credentials"})
	assertPasswordCalls(t, passwordCalls, []bool{true})

	current := mustLoadManifest(t, environment)
	if current.Crypto == nil {
		t.Fatal("sensitive Add() did not initialize repository crypto metadata")
	}
	entry := mustFindEntry(t, current, "~/.credentials")
	if !entry.Sensitive || entry.Source != "encrypted/.credentials.enc" {
		t.Fatalf("sensitive manifest entry = %+v", entry)
	}

	stored := filepath.Join(environment.repository, "encrypted", ".credentials.enc")
	ciphertext := mustReadFile(t, stored)
	if bytes.Equal(ciphertext, plaintext) || bytes.Contains(ciphertext, plaintext) {
		t.Fatalf("encrypted repository copy contains plaintext: %q", ciphertext)
	}
	assertPermissions(t, stored, 0o600)
	assertPathDoesNotExist(t, filepath.Join(environment.repository, "public", ".credentials"))
	assertRepositoryDoesNotContain(t, environment.repository, plaintext)
}

func TestAddMultipleFiles(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	files := map[string][]byte{
		"~/.alpha":          []byte("alpha\n"),
		"~/.omega":          []byte("omega\n"),
		"~/nested/settings": []byte("nested\n"),
	}
	inputs := []string{
		mustWriteFile(t, filepath.Join(environment.home, ".omega"), files["~/.omega"], 0o644),
		mustWriteFile(t, filepath.Join(environment.home, "nested", "settings"), files["~/nested/settings"], 0o600),
		mustWriteFile(t, filepath.Join(environment.home, ".alpha"), files["~/.alpha"], 0o644),
	}

	result, err := environment.service.Add(inputs, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	wantPaths := []string{"~/.alpha", "~/.omega", "~/nested/settings"}
	assertStrings(t, result.Added, wantPaths)
	assertStrings(t, managedPaths(t, environment.service), wantPaths)

	for logical, contents := range files {
		assertFileContents(t, repositorySource(t, environment, logical, false), contents)
	}
}

func TestAddIsIdempotentAndMixedInputsAddOnlyNewFiles(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	original := []byte("original repository snapshot\n")
	existing := mustWriteFile(t, filepath.Join(environment.home, ".existing"), original, 0o644)

	if _, err := environment.service.Add([]string{existing}, app.AddOptions{}); err != nil {
		t.Fatalf("initial Add() error = %v", err)
	}
	storedExisting := repositorySource(t, environment, "~/.existing", false)
	mustWriteFile(t, existing, []byte("new destination contents\n"), 0o644)

	duplicate, err := environment.service.Add([]string{existing}, app.AddOptions{})
	if err != nil {
		t.Fatalf("duplicate Add() error = %v", err)
	}
	assertStrings(t, duplicate.Added, nil)
	assertStrings(t, duplicate.AlreadyManaged, []string{"~/.existing"})
	assertFileContents(t, storedExisting, original)

	newContents := []byte("new file snapshot\n")
	newFile := mustWriteFile(t, filepath.Join(environment.home, ".new"), newContents, 0o600)
	mixed, err := environment.service.Add([]string{newFile, existing}, app.AddOptions{})
	if err != nil {
		t.Fatalf("mixed Add() error = %v", err)
	}
	assertStrings(t, mixed.Added, []string{"~/.new"})
	assertStrings(t, mixed.AlreadyManaged, []string{"~/.existing"})
	assertFileContents(t, storedExisting, original)
	assertFileContents(t, repositorySource(t, environment, "~/.new", false), newContents)
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.existing", "~/.new"})
}

func TestAddTreatsManagedHardLinkAliasAsAlreadyManagedWithoutPassword(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	managed := mustWriteFile(t, filepath.Join(environment.home, ".managed"), []byte("stored snapshot\n"), 0o600)
	if _, err := environment.service.Add([]string{managed}, app.AddOptions{}); err != nil {
		t.Fatalf("initial Add() error = %v", err)
	}
	alias := filepath.Join(environment.home, ".managed-alias")
	if err := os.Link(managed, alias); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	manifestBefore := mustReadFile(t, filepath.Join(environment.repository, manifest.Filename))
	var passwordCalls []bool

	result, err := environment.service.Add([]string{alias}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if err != nil {
		t.Fatalf("Add(hard-link alias) error = %v", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, []string{"~/.managed-alias"})
	assertPasswordCalls(t, passwordCalls, nil)
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.managed"})
	assertFileContents(t, filepath.Join(environment.repository, manifest.Filename), manifestBefore)
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.managed-alias", true))
}

func TestAddRejectsNewHardLinkAliasesBeforePassword(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	first := mustWriteFile(t, filepath.Join(environment.home, ".first-alias"), []byte("same inode\n"), 0o600)
	second := filepath.Join(environment.home, ".second-alias")
	if err := os.Link(first, second); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	var passwordCalls []bool

	result, err := environment.service.Add([]string{second, first}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if !errors.Is(err, app.ErrDestinationConflict) {
		t.Fatalf("Add(new hard-link aliases) error = %v, want ErrDestinationConflict", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, nil)
	assertPasswordCalls(t, passwordCalls, nil)
	current := mustLoadManifest(t, environment)
	if current.Crypto != nil {
		t.Fatal("conflicting Add() initialized repository encryption")
	}
	assertStrings(t, managedPaths(t, environment.service), nil)
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.first-alias", true))
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.second-alias", true))
}

func TestAddRechecksManagedPhysicalAliasAfterPassword(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	managed := mustWriteFile(t, filepath.Join(environment.home, ".managed-before-password"), []byte("managed\n"), 0o600)
	if _, err := environment.service.Add([]string{managed}, app.AddOptions{}); err != nil {
		t.Fatalf("initial Add() error = %v", err)
	}
	candidate := mustWriteFile(t, filepath.Join(environment.home, ".candidate-after-password"), []byte("candidate\n"), 0o600)
	manifestBefore := mustReadFile(t, filepath.Join(environment.repository, manifest.Filename))
	var passwordCalls []bool
	passwordProvider := func(create bool) ([]byte, error) {
		passwordCalls = append(passwordCalls, create)
		if err := os.Remove(managed); err != nil {
			return nil, err
		}
		if err := os.Link(candidate, managed); err != nil {
			return nil, err
		}
		return []byte(testPassword), nil
	}

	result, err := environment.service.Add([]string{candidate}, app.AddOptions{Sensitive: true, Password: passwordProvider})
	if !errors.Is(err, app.ErrDestinationConflict) {
		t.Fatalf("Add(password-time alias) error = %v, want ErrDestinationConflict", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, nil)
	assertPasswordCalls(t, passwordCalls, []bool{true})
	assertFileContents(t, filepath.Join(environment.repository, manifest.Filename), manifestBefore)
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.candidate-after-password", true))
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.managed-before-password"})
}

func TestAddDoesNotFollowManagedLeafSymlinkForIdentity(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	managed := mustWriteFile(t, filepath.Join(environment.home, ".managed-link"), []byte("managed snapshot\n"), 0o600)
	if _, err := environment.service.Add([]string{managed}, app.AddOptions{}); err != nil {
		t.Fatalf("initial Add() error = %v", err)
	}
	candidate := mustWriteFile(t, filepath.Join(environment.home, ".symlink-target-candidate"), []byte("new candidate\n"), 0o600)
	if err := os.Remove(managed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(candidate, managed); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	result, err := environment.service.Add([]string{candidate}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(target of managed leaf symlink) error = %v", err)
	}
	assertStrings(t, result.Added, []string{"~/.symlink-target-candidate"})
	assertStrings(t, result.AlreadyManaged, nil)
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.managed-link", "~/.symlink-target-candidate"})
	assertFileContents(t, repositorySource(t, environment, "~/.symlink-target-candidate", false), []byte("new candidate\n"))
}

func TestAddHandlesCaseAliasedXDGAndHomeIdentities(t *testing.T) {
	t.Run("existing managed alias", func(t *testing.T) {
		environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", xdgConfigUnderHomeCase: true})
		xdgPath := mustWriteFile(t, filepath.Join(environment.xdgConfigHome, "item"), []byte("managed\n"), 0o600)
		homeAlias := filepath.Join(environment.home, "config", "item")
		if !sameExistingFile(xdgPath, homeAlias) {
			t.Skip("test filesystem is case-sensitive")
		}
		if _, err := environment.service.Add([]string{xdgPath}, app.AddOptions{}); err != nil {
			t.Fatalf("initial XDG Add() error = %v", err)
		}
		var passwordCalls []bool

		result, err := environment.service.Add([]string{homeAlias}, app.AddOptions{
			Sensitive: true,
			Password:  recordingPasswordProvider(testPassword, &passwordCalls),
		})
		if err != nil {
			t.Fatalf("Add(case-aliased managed path) error = %v", err)
		}
		assertStrings(t, result.Added, nil)
		assertStrings(t, result.AlreadyManaged, []string{"~/config/item"})
		assertPasswordCalls(t, passwordCalls, nil)
		assertStrings(t, managedPaths(t, environment.service), []string{"${XDG_CONFIG_HOME}/item"})
	})

	t.Run("two new aliases", func(t *testing.T) {
		environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", xdgConfigUnderHomeCase: true})
		xdgPath := mustWriteFile(t, filepath.Join(environment.xdgConfigHome, "item"), []byte("candidate\n"), 0o600)
		homeAlias := filepath.Join(environment.home, "config", "item")
		if !sameExistingFile(xdgPath, homeAlias) {
			t.Skip("test filesystem is case-sensitive")
		}
		var passwordCalls []bool

		result, err := environment.service.Add([]string{xdgPath, homeAlias}, app.AddOptions{
			Sensitive: true,
			Password:  recordingPasswordProvider(testPassword, &passwordCalls),
		})
		if !errors.Is(err, app.ErrDestinationConflict) {
			t.Fatalf("Add(case-aliased new paths) error = %v, want ErrDestinationConflict", err)
		}
		assertStrings(t, result.Added, nil)
		assertStrings(t, result.AlreadyManaged, nil)
		assertPasswordCalls(t, passwordCalls, nil)
		assertStrings(t, managedPaths(t, environment.service), nil)
	})
}

func TestAddExpandsDirectoriesRecursively(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	directory := filepath.Join(environment.home, "tree")
	files := map[string][]byte{
		"~/tree/.hidden":         []byte("hidden\n"),
		"~/tree/nested/two.conf": []byte("two\n"),
		"~/tree/one.txt":         []byte("one\n"),
	}
	mustWriteFile(t, filepath.Join(directory, ".hidden"), files["~/tree/.hidden"], 0o600)
	mustWriteFile(t, filepath.Join(directory, "one.txt"), files["~/tree/one.txt"], 0o644)
	mustWriteFile(t, filepath.Join(directory, "nested", "two.conf"), files["~/tree/nested/two.conf"], 0o640)
	if err := os.MkdirAll(filepath.Join(directory, "empty", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := environment.service.Add([]string{directory}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(directory) error = %v", err)
	}
	wantPaths := []string{"~/tree/.hidden", "~/tree/nested/two.conf", "~/tree/one.txt"}
	assertStrings(t, result.Added, wantPaths)
	assertStrings(t, managedPaths(t, environment.service), wantPaths)
	for logical, contents := range files {
		assertFileContents(t, repositorySource(t, environment, logical, false), contents)
	}
}

func TestAddIgnoresKubeCacheDuringRecursiveTraversal(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	kubeDirectory := filepath.Join(environment.home, ".kube")
	kept := map[string][]byte{
		"~/.kube/cache.yaml":       []byte("cache configuration\n"),
		"~/.kube/caches/keep.json": []byte("not the cache directory\n"),
		"~/.kube/config":           []byte("cluster configuration\n"),
	}
	for logical, contents := range kept {
		absolute, err := environment.resolver.Resolve(logical)
		if err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, absolute, contents, 0o600)
	}
	ignored := map[string][]byte{
		"~/.kube/cache/discovery/example": []byte("discovery cache\n"),
		"~/.kube/cache/http/response":     []byte("HTTP cache\n"),
	}
	for logical, contents := range ignored {
		absolute, err := environment.resolver.Resolve(logical)
		if err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, absolute, contents, 0o600)
	}
	cacheDirectory := filepath.Join(kubeDirectory, "cache")
	if err := os.Chmod(cacheDirectory, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cacheDirectory, 0o700) })

	result, err := environment.service.Add([]string{kubeDirectory}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(%q) error = %v", kubeDirectory, err)
	}
	wantPaths := []string{"~/.kube/cache.yaml", "~/.kube/caches/keep.json", "~/.kube/config"}
	assertStrings(t, result.Added, wantPaths)
	assertStrings(t, managedPaths(t, environment.service), wantPaths)
	for logical, contents := range kept {
		assertFileContents(t, repositorySource(t, environment, logical, false), contents)
	}
	for logical := range ignored {
		assertPathDoesNotExist(t, repositorySource(t, environment, logical, false))
	}
}

func TestAddIgnoresExplicitKubeCachePathsWithoutPassword(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	cacheDirectory := filepath.Join(environment.home, ".kube", "cache")
	cachedFile := mustWriteFile(t, filepath.Join(cacheDirectory, "discovery", "example"), []byte("discovery cache\n"), 0o600)
	var passwordCalls []bool

	result, err := environment.service.Add([]string{cacheDirectory, cachedFile}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if err != nil {
		t.Fatalf("Add(kube cache) error = %v", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, nil)
	assertPasswordCalls(t, passwordCalls, nil)
	assertStrings(t, managedPaths(t, environment.service), nil)
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.kube/cache/discovery/example", true))
}

func TestAddIgnoresKubeCacheWhenXDGConfigOverlaps(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{xdgConfigUnderKube: true})
	config := mustWriteFile(t, filepath.Join(environment.home, ".kube", "config"), []byte("cluster configuration\n"), 0o600)
	cached := mustWriteFile(t, filepath.Join(environment.home, ".kube", "cache", "discovery", "example"), []byte("discovery cache\n"), 0o600)

	result, err := environment.service.Add([]string{filepath.Join(environment.home, ".kube")}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(overlapping XDG kube directory) error = %v", err)
	}
	wantPaths := []string{"${XDG_CONFIG_HOME}/config"}
	assertStrings(t, result.Added, wantPaths)
	assertStrings(t, managedPaths(t, environment.service), wantPaths)
	assertFileContents(t, repositorySource(t, environment, "${XDG_CONFIG_HOME}/config", false), mustReadFile(t, config))
	assertPathDoesNotExist(t, repositorySource(t, environment, "${XDG_CONFIG_HOME}/cache/discovery/example", false))
	assertFileContents(t, cached, []byte("discovery cache\n"))
}

func TestAddIgnoresCaseAliasedKubeCache(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	kubeDirectory := filepath.Join(environment.home, ".kube")
	cacheDirectory := filepath.Join(kubeDirectory, "Cache")
	cachedFile := mustWriteFile(t, filepath.Join(cacheDirectory, "discovery", "example"), []byte("discovery cache\n"), 0o600)
	lowercaseInfo, err := os.Stat(filepath.Join(kubeDirectory, "cache"))
	if err != nil {
		t.Skip("test filesystem is case-sensitive")
	}
	cacheInfo, err := os.Stat(cacheDirectory)
	if err != nil || !os.SameFile(cacheInfo, lowercaseInfo) {
		t.Skip("test filesystem is case-sensitive")
	}
	mustWriteFile(t, filepath.Join(kubeDirectory, "config"), []byte("cluster configuration\n"), 0o600)

	result, err := environment.service.Add([]string{kubeDirectory}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(case-aliased kube cache) error = %v", err)
	}
	assertStrings(t, result.Added, []string{"~/.kube/config"})
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.kube/config"})
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/.kube/Cache/discovery/example", false))

	explicit, err := environment.service.Add([]string{cachedFile}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(explicit case-aliased kube cache file) error = %v", err)
	}
	assertStrings(t, explicit.Added, nil)
	assertStrings(t, managedPaths(t, environment.service), []string{"~/.kube/config"})
}

func TestKubeCacheSymlinkDoesNotBroadenAddExclusion(t *testing.T) {
	tests := []struct {
		name   string
		target func(*testEnvironment) string
	}{
		{name: "home target", target: func(environment *testEnvironment) string { return environment.home }},
		{name: "self loop", target: func(*testEnvironment) string { return "cache" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			kubeDirectory := filepath.Join(environment.home, ".kube")
			if err := os.MkdirAll(kubeDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			cacheLink := filepath.Join(kubeDirectory, "cache")
			if err := os.Symlink(test.target(environment), cacheLink); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			ordinary := mustWriteFile(t, filepath.Join(environment.home, ".zshrc"), []byte("ordinary\n"), 0o600)

			result, err := environment.service.Add([]string{ordinary}, app.AddOptions{})
			if err != nil {
				t.Fatalf("Add(unrelated file) with kube cache symlink error = %v", err)
			}
			assertStrings(t, result.Added, []string{"~/.zshrc"})
			assertFileContents(t, repositorySource(t, environment, "~/.zshrc", false), []byte("ordinary\n"))

			if _, err := environment.service.Add([]string{cacheLink}, app.AddOptions{}); err == nil {
				t.Fatal("Add() accepted an explicit kube cache symlink")
			}
			assertStrings(t, managedPaths(t, environment.service), []string{"~/.zshrc"})
		})
	}
}

func TestAddRejectsExplicitSymlinksAndSkipsWalkedSymlinks(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	outsideFile := mustWriteFile(t, filepath.Join(environment.root, "targets", "actual.conf"), []byte("must not be copied\n"), 0o640)
	explicitFileLink := filepath.Join(environment.home, "linked config")
	if err := os.Symlink(outsideFile, explicitFileLink); err != nil {
		t.Fatalf("create regular-file symlink: %v", err)
	}

	walkRoot := filepath.Join(environment.home, "walk root")
	mustWriteFile(t, filepath.Join(walkRoot, "local.txt"), []byte("local\n"), 0o644)
	walkedFileLink := filepath.Join(walkRoot, "linked file")
	if err := os.Symlink(outsideFile, walkedFileLink); err != nil {
		t.Fatalf("create walked file symlink: %v", err)
	}
	outsideDirectory := filepath.Join(environment.root, "directory target")
	mustWriteFile(t, filepath.Join(outsideDirectory, "must-not-be-added.txt"), []byte("not followed\n"), 0o600)
	directoryLink := filepath.Join(walkRoot, "linked directory")
	if err := os.Symlink(outsideDirectory, directoryLink); err != nil {
		t.Fatalf("create directory symlink: %v", err)
	}

	result, err := environment.service.Add([]string{walkRoot}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(directory) error = %v", err)
	}
	wantPaths := []string{"~/walk root/local.txt"}
	assertStrings(t, result.Added, wantPaths)
	assertStrings(t, managedPaths(t, environment.service), wantPaths)
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/walk root/linked file", false))
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/walk root/linked directory/must-not-be-added.txt", false))

	if _, err := environment.service.Add([]string{explicitFileLink}, app.AddOptions{}); err == nil {
		t.Fatal("Add() accepted an explicitly supplied file symlink")
	}
	if _, err := environment.service.Add([]string{directoryLink}, app.AddOptions{}); err == nil {
		t.Fatal("Add() accepted an explicitly supplied directory symlink")
	}
	parentLink := filepath.Join(environment.home, "outside parent")
	if err := os.Symlink(filepath.Dir(outsideFile), parentLink); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}
	if _, err := environment.service.Add([]string{filepath.Join(parentLink, filepath.Base(outsideFile))}, app.AddOptions{}); err == nil {
		t.Fatal("Add() escaped through a parent symlink")
	}
	assertStrings(t, managedPaths(t, environment.service), wantPaths)
}

func TestAddRejectsLocalStatePathsBeforePassword(t *testing.T) {
	tests := []struct {
		name  string
		input func(*testEnvironment) string
	}{
		{name: "state file", input: func(environment *testEnvironment) string { return environment.store.Path() }},
		{name: "state directory", input: func(environment *testEnvironment) string { return environment.store.Directory() }},
		{name: "state lock", input: func(environment *testEnvironment) string {
			return filepath.Join(environment.store.Directory(), "lock")
		}},
		{name: "state staging file", input: func(environment *testEnvironment) string {
			return filepath.Join(environment.store.Directory(), ".state-orphan.tmp")
		}},
		{name: "ancestor containing state", input: func(environment *testEnvironment) string { return environment.home }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			var passwordCalls []bool
			result, err := environment.service.Add([]string{test.input(environment)}, app.AddOptions{
				Sensitive: true,
				Password:  recordingPasswordProvider(testPassword, &passwordCalls),
			})
			if !errors.Is(err, app.ErrProtectedLocalState) {
				t.Fatalf("Add() error = %v, want ErrProtectedLocalState", err)
			}
			if !strings.Contains(err.Error(), "choose a narrower input path") {
				t.Fatalf("Add() error is not actionable: %v", err)
			}
			assertStrings(t, result.Added, nil)
			assertStrings(t, result.AlreadyManaged, nil)
			assertPasswordCalls(t, passwordCalls, nil)
			assertStrings(t, managedPaths(t, environment.service), nil)
			boundRepository, loadErr := environment.store.Load()
			if loadErr != nil || boundRepository != environment.repository {
				t.Fatalf("local state changed after rejected Add(): repository = %q, error = %v", boundRepository, loadErr)
			}
		})
	}
}

func TestAddAllowsSiblingOutsideLocalStateDirectory(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(
		t,
		filepath.Join(filepath.Dir(environment.store.Directory()), "other", "config"),
		[]byte("ordinary local state sibling\n"),
		0o600,
	)

	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add() sibling error = %v", err)
	}
	assertStrings(t, result.Added, []string{"~/.local/state/other/config"})
}

func TestAddProtectsCustomLocalStateDirectory(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	customStore, err := state.NewStore(environment.home, filepath.Join(environment.home, "custom-state"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.New(customStore, environment.resolver, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Init(environment.repository); err != nil {
		t.Fatal(err)
	}

	var passwordCalls []bool
	_, err = service.Add([]string{customStore.Path()}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Add(custom state) error = %v, want ErrProtectedLocalState", err)
	}
	assertPasswordCalls(t, passwordCalls, nil)
}

func TestAddRejectsCaseAliasedLocalStatePath(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	aliasedDirectory := filepath.Join(
		filepath.Dir(environment.store.Directory()),
		strings.ToUpper(filepath.Base(environment.store.Directory())),
	)
	aliasedState := filepath.Join(aliasedDirectory, filepath.Base(environment.store.Path()))
	stateInfo, err := os.Stat(environment.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(aliasedState)
	if err != nil || !os.SameFile(stateInfo, aliasInfo) {
		t.Skip("test filesystem is case-sensitive")
	}

	if _, err := environment.service.Add([]string{aliasedState}, app.AddOptions{}); !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Add(case alias) error = %v, want ErrProtectedLocalState", err)
	}
}

func TestAddRejectsSymlinkedLocalStatePath(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	stateBefore := mustReadFile(t, environment.store.Path())
	aliasDirectory := filepath.Join(environment.home, "state-root-link")
	if err := os.Symlink(environment.store.Directory(), aliasDirectory); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	alias := filepath.Join(aliasDirectory, filepath.Base(environment.store.Path()))

	var passwordCalls []bool
	result, err := environment.service.Add([]string{alias}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &passwordCalls),
	})
	if !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Add(state symlink alias) error = %v, want ErrProtectedLocalState", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, nil)
	assertPasswordCalls(t, passwordCalls, nil)
	assertStrings(t, managedPaths(t, environment.service), nil)
	assertFileContents(t, environment.store.Path(), stateBefore)
}

func TestAddRejectsHardLinkedLocalStateFileDuringDirectoryWalk(t *testing.T) {
	tests := []struct {
		name    string
		target  func(*testEnvironment) string
		prepare func(*testing.T, string)
	}{
		{
			name:   "state file",
			target: func(environment *testEnvironment) string { return environment.store.Path() },
		},
		{
			name: "state lock",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), "lock")
			},
		},
		{
			name: "state staging file",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), ".state-orphan.tmp")
			},
			prepare: func(t *testing.T, target string) {
				mustWriteFile(t, target, []byte("orphaned local state staging data\n"), 0o600)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			target := test.target(environment)
			if test.prepare != nil {
				test.prepare(t, target)
			}
			targetBefore := mustReadFile(t, target)
			stateBefore := mustReadFile(t, environment.store.Path())
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore := mustReadFile(t, manifestPath)

			aliasDirectory := filepath.Join(environment.home, "state-aliases")
			if err := os.MkdirAll(aliasDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(aliasDirectory, "protected-copy")
			if err := os.Link(target, alias); err != nil {
				t.Skipf("hard links are unavailable: %v", err)
			}
			logical, err := environment.resolver.Normalize(alias)
			if err != nil {
				t.Fatal(err)
			}

			var passwordCalls []bool
			_, err = environment.service.Add([]string{aliasDirectory}, app.AddOptions{
				Sensitive: true,
				Password:  recordingPasswordProvider(testPassword, &passwordCalls),
			})
			if !errors.Is(err, app.ErrProtectedLocalState) {
				t.Fatalf("Add(hard-link directory) error = %v, want ErrProtectedLocalState", err)
			}
			assertPasswordCalls(t, passwordCalls, nil)
			assertStrings(t, managedPaths(t, environment.service), nil)
			assertPathDoesNotExist(t, repositorySource(t, environment, logical, true))
			assertFileContents(t, manifestPath, manifestBefore)
			assertFileContents(t, environment.store.Path(), stateBefore)
			assertFileContents(t, target, targetBefore)
			assertFileContents(t, alias, targetBefore)
		})
	}
}

func TestAddRechecksHardLinkedLocalStateFileAfterPassword(t *testing.T) {
	tests := []struct {
		name    string
		target  func(*testEnvironment) string
		prepare func(*testing.T, string)
	}{
		{
			name:   "state file",
			target: func(environment *testEnvironment) string { return environment.store.Path() },
		},
		{
			name: "state lock",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), "lock")
			},
		},
		{
			name: "state staging file",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), ".state-orphan.tmp")
			},
			prepare: func(t *testing.T, target string) {
				mustWriteFile(t, target, []byte("orphaned local state staging data\n"), 0o600)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			target := test.target(environment)
			if test.prepare != nil {
				test.prepare(t, target)
			}
			targetBefore := mustReadFile(t, target)
			stateBefore := mustReadFile(t, environment.store.Path())
			earlier := mustWriteFile(
				t,
				filepath.Join(environment.home, "preflight-before", "nested", "ordinary"),
				[]byte("ordinary earlier candidate\n"),
				0o600,
			)
			candidate := mustWriteFile(
				t,
				filepath.Join(environment.home, "z-late-state-alias"),
				[]byte("ordinary late candidate\n"),
				0o600,
			)
			probe := candidate + ".hard-link-probe"
			if err := os.Link(target, probe); err != nil {
				t.Skipf("hard links are unavailable: %v", err)
			}
			if err := os.Remove(probe); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore := mustReadFile(t, manifestPath)

			var passwordCalls []bool
			passwordProvider := func(create bool) ([]byte, error) {
				passwordCalls = append(passwordCalls, create)
				if err := os.Remove(candidate); err != nil {
					return nil, err
				}
				if err := os.Link(target, candidate); err != nil {
					return nil, err
				}
				return []byte(testPassword), nil
			}

			result, err := environment.service.Add(
				[]string{earlier, candidate},
				app.AddOptions{Sensitive: true, Password: passwordProvider},
			)
			if !errors.Is(err, app.ErrProtectedLocalState) {
				t.Fatalf("Add(late hard link) error = %v, want ErrProtectedLocalState", err)
			}
			assertStrings(t, result.Added, nil)
			assertStrings(t, result.AlreadyManaged, nil)
			assertPasswordCalls(t, passwordCalls, []bool{true})
			assertStrings(t, managedPaths(t, environment.service), nil)
			earlierSource := repositorySource(t, environment, "~/preflight-before/nested/ordinary", true)
			assertPathDoesNotExist(t, earlierSource)
			assertPathDoesNotExist(t, filepath.Dir(filepath.Dir(earlierSource)))
			assertPathDoesNotExist(t, repositorySource(t, environment, "~/z-late-state-alias", true))
			assertFileContents(t, manifestPath, manifestBefore)
			assertFileContents(t, environment.store.Path(), stateBefore)
			assertFileContents(t, target, targetBefore)
			assertFileContents(t, candidate, targetBefore)
		})
	}
}

func TestAddRejectsRepositoryPathsBeforePasswordOrMutation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	const stagingSuffix = "0123456789abcdef01234567"
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestInput := filepath.Join(environment.repositoryInput, manifest.Filename)
	repositoryLock := filepath.Join(environment.gitCommonDirectory, "susu.lock")
	stagingFiles := map[string][]byte{
		filepath.Join(environment.repository, ".susu-123456789.tmp"):                       []byte("manifest staging sentinel\n"),
		filepath.Join(environment.repository, "public", ".susu-add-"+stagingSuffix+".tmp"): []byte("add staging sentinel\n"),
		filepath.Join(environment.repository, ".susu-apply-"+stagingSuffix+".tmp"):         []byte("apply staging sentinel\n"),
	}
	for filename, contents := range stagingFiles {
		mustWriteFile(t, filename, contents, 0o600)
	}
	if _, err := os.Stat(repositoryLock); err != nil {
		t.Fatalf("repository lock does not exist: %v", err)
	}
	manifestBefore := mustReadFile(t, manifestPath)
	encryptedBefore := mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted"))

	tests := []struct {
		name  string
		input string
	}{
		{name: "exact worktree", input: environment.repositoryInput},
		{name: "manifest", input: manifestInput},
		{name: "public storage", input: filepath.Join(environment.repositoryInput, "public")},
		{name: "encrypted storage", input: filepath.Join(environment.repositoryInput, "encrypted")},
		{name: "Git directory", input: environment.gitCommonDirectory},
		{name: "repository lock", input: repositoryLock},
		{name: "manifest staging file", input: filepath.Join(environment.repositoryInput, ".susu-123456789.tmp")},
		{name: "add staging file", input: filepath.Join(environment.repositoryInput, "public", ".susu-add-"+stagingSuffix+".tmp")},
		{name: "apply staging file", input: filepath.Join(environment.repositoryInput, ".susu-apply-"+stagingSuffix+".tmp")},
		{name: "representable ancestor", input: filepath.Dir(environment.repositoryInput)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var passwordCalls []bool
			result, err := environment.service.Add([]string{test.input}, app.AddOptions{
				Sensitive: true,
				Password:  recordingPasswordProvider(testPassword, &passwordCalls),
			})
			if !errors.Is(err, app.ErrProtectedRepository) {
				t.Fatalf("Add(%q) error = %v, want ErrProtectedRepository", test.input, err)
			}
			if !strings.Contains(err.Error(), "choose a narrower input path") {
				t.Fatalf("Add(%q) error is not actionable: %v", test.input, err)
			}
			assertStrings(t, result.Added, nil)
			assertStrings(t, result.AlreadyManaged, nil)
			assertPasswordCalls(t, passwordCalls, nil)
			assertFileContents(t, manifestPath, manifestBefore)
			assertStrings(t, mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted")), encryptedBefore)
			for filename, contents := range stagingFiles {
				assertFileContents(t, filename, contents)
			}
		})
	}
}

func TestAddAllowsSiblingOutsideRepository(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	contents := []byte("nearby repository sibling\n")
	destination := mustWriteFile(t, filepath.Join(environment.repositoryInput+"-sibling", "config"), contents, 0o644)
	entry := mustEntryForDestination(t, environment, destination, false)

	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(repository sibling) error = %v", err)
	}
	assertStrings(t, result.Added, []string{entry.Path})
	assertFileContents(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)), contents)
}

func TestAddRejectsRepositorySymlinkAndCaseAliases(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestBefore := mustReadFile(t, manifestPath)
	encryptedBefore := mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted"))

	t.Run("symlink alias", func(t *testing.T) {
		alias := filepath.Join(environment.home, "active-repository-link")
		if err := os.Symlink(environment.repository, alias); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		var passwordCalls []bool
		result, err := environment.service.Add([]string{alias}, app.AddOptions{
			Sensitive: true,
			Password:  recordingPasswordProvider(testPassword, &passwordCalls),
		})
		if !errors.Is(err, app.ErrProtectedRepository) {
			t.Fatalf("Add(repository symlink alias) error = %v, want ErrProtectedRepository", err)
		}
		assertStrings(t, result.Added, nil)
		assertPasswordCalls(t, passwordCalls, nil)
		assertFileContents(t, manifestPath, manifestBefore)
		assertStrings(t, mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted")), encryptedBefore)
	})

	t.Run("case alias", func(t *testing.T) {
		alias := filepath.Join(filepath.Dir(environment.repositoryInput), strings.ToUpper(filepath.Base(environment.repositoryInput)))
		repositoryInfo, err := os.Stat(environment.repository)
		if err != nil {
			t.Fatal(err)
		}
		aliasInfo, err := os.Stat(alias)
		if err != nil || !os.SameFile(repositoryInfo, aliasInfo) {
			t.Skip("test filesystem is case-sensitive")
		}

		var passwordCalls []bool
		result, err := environment.service.Add([]string{alias}, app.AddOptions{
			Sensitive: true,
			Password:  recordingPasswordProvider(testPassword, &passwordCalls),
		})
		if !errors.Is(err, app.ErrProtectedRepository) {
			t.Fatalf("Add(repository case alias) error = %v, want ErrProtectedRepository", err)
		}
		assertStrings(t, result.Added, nil)
		assertPasswordCalls(t, passwordCalls, nil)
		assertFileContents(t, manifestPath, manifestBefore)
		assertStrings(t, mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted")), encryptedBefore)
	})
}

func TestAddRechecksRepositorySymlinkAfterPasswordBeforeMutation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	earlier := mustWriteFile(
		t,
		filepath.Join(environment.home, "a-preflight-before", "nested", "ordinary"),
		[]byte("ordinary earlier candidate\n"),
		0o600,
	)
	candidate := mustWriteFile(
		t,
		filepath.Join(environment.home, "z-late-repository-alias"),
		[]byte("ordinary late candidate\n"),
		0o600,
	)
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestBefore := mustReadFile(t, manifestPath)
	encryptedBefore := mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted"))

	var passwordCalls []bool
	passwordProvider := func(create bool) ([]byte, error) {
		passwordCalls = append(passwordCalls, create)
		if err := os.Remove(candidate); err != nil {
			return nil, err
		}
		if err := os.Symlink(environment.repository, candidate); err != nil {
			return nil, err
		}
		return []byte(testPassword), nil
	}

	result, err := environment.service.Add(
		[]string{earlier, candidate},
		app.AddOptions{Sensitive: true, Password: passwordProvider},
	)
	if !errors.Is(err, app.ErrProtectedRepository) {
		t.Fatalf("Add(late repository symlink) error = %v, want ErrProtectedRepository", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.AlreadyManaged, nil)
	assertPasswordCalls(t, passwordCalls, []bool{true})
	assertPathDoesNotExist(t, filepath.Join(environment.repository, "encrypted", "a-preflight-before"))
	assertPathDoesNotExist(t, repositorySource(t, environment, "~/z-late-repository-alias", true))
	assertFileContents(t, manifestPath, manifestBefore)
	assertStrings(t, mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted")), encryptedBefore)
	assertFileContents(t, earlier, []byte("ordinary earlier candidate\n"))
	if info, statErr := os.Lstat(candidate); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("late candidate was not left as a repository symlink: mode = %v, error = %v", info, statErr)
	}
}

func TestAddRejectsLinkedWorktreeGitCommonPaths(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{linkedWorktree: true, customXDG: true})
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestBefore := mustReadFile(t, manifestPath)
	encryptedBefore := mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted"))
	repositoryLock := filepath.Join(environment.gitCommonDirectory, "susu.lock")

	tests := []struct {
		name  string
		input string
	}{
		{name: "Git common root", input: environment.gitCommonDirectory},
		{name: "repository lock", input: repositoryLock},
		{name: "Git common ancestor", input: filepath.Dir(environment.gitCommonDirectory)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var passwordCalls []bool
			result, err := environment.service.Add([]string{test.input}, app.AddOptions{
				Sensitive: true,
				Password:  recordingPasswordProvider(testPassword, &passwordCalls),
			})
			if !errors.Is(err, app.ErrProtectedRepository) {
				t.Fatalf("Add(%q) error = %v, want ErrProtectedRepository", test.input, err)
			}
			assertStrings(t, result.Added, nil)
			assertPasswordCalls(t, passwordCalls, nil)
			assertFileContents(t, manifestPath, manifestBefore)
			assertStrings(t, mustReadDirectoryNames(t, filepath.Join(environment.repository, "encrypted")), encryptedBefore)
		})
	}
}

func TestListOrdersAndFormatsPlatformExclusions(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	zeta := mustWriteFile(t, filepath.Join(environment.home, ".zeta"), []byte("zeta\n"), 0o644)
	middle := mustWriteFile(t, filepath.Join(environment.home, ".middle"), []byte("middle\n"), 0o644)
	alpha := mustWriteFile(t, filepath.Join(environment.home, ".alpha"), []byte("alpha secret\n"), 0o600)

	if _, err := environment.service.Add([]string{zeta}, app.AddOptions{
		ExcludePlatforms: []string{"linux", "darwin", "linux"},
	}); err != nil {
		t.Fatalf("Add(zeta) error = %v", err)
	}
	if _, err := environment.service.Add([]string{middle}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(middle) error = %v", err)
	}
	var passwordCalls []bool
	if _, err := environment.service.Add([]string{alpha}, app.AddOptions{
		Sensitive:        true,
		ExcludePlatforms: []string{"linux"},
		Password:         recordingPasswordProvider(testPassword, &passwordCalls),
	}); err != nil {
		t.Fatalf("Add(alpha) error = %v", err)
	}
	assertPasswordCalls(t, passwordCalls, []bool{true})

	entries, err := environment.service.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List() returned %d entries, want 3", len(entries))
	}
	lines := make([]string, len(entries))
	for index, entry := range entries {
		lines[index] = app.FormatEntry(entry)
	}
	assertStrings(t, lines, []string{
		"~/.alpha [sensitive] [exclude: linux]",
		"~/.middle",
		"~/.zeta [exclude: darwin, linux]",
	})
	assertStrings(t, mustFindEntry(t, mustLoadManifest(t, environment), "~/.zeta").ExcludePlatforms, []string{"darwin", "linux"})
}

func TestRemoveDeletesRepositoryCopyButLeavesDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(t, filepath.Join(environment.home, ".obsolete"), []byte("stored version\n"), 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	stored := repositorySource(t, environment, "~/.obsolete", false)
	mustWriteFile(t, destination, []byte("current destination\n"), 0o600)

	result, err := environment.service.Remove([]string{destination})
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	assertStrings(t, result.Removed, []string{"~/.obsolete"})
	assertPathDoesNotExist(t, stored)
	assertFileContents(t, destination, []byte("current destination\n"))
	assertStrings(t, managedPaths(t, environment.service), nil)
}

func TestShowPublicUsesStoredCopy(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(t, filepath.Join(environment.home, ".show-public"), []byte("stored public\n"), 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	mustWriteFile(t, destination, []byte("new local value\n"), 0o644)

	var output bytes.Buffer
	unexpectedPassword := func(bool) ([]byte, error) {
		t.Fatal("public Show() requested a password")
		return nil, nil
	}
	if err := environment.service.Show("~/.show-public", &output, unexpectedPassword); err != nil {
		t.Fatalf("Show() error = %v", err)
	}
	if got, want := output.String(), "stored public\n"; got != want {
		t.Fatalf("Show() output = %q, want %q", got, want)
	}
	assertFileContents(t, destination, []byte("new local value\n"))
}

func TestShowEncryptedAndReportsPasswordOrCiphertextErrors(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	plaintext := []byte("show-only-secret-f01f34ba\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".show-secret"), plaintext, 0o600)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	mustWriteFile(t, destination, []byte("local value remains\n"), 0o600)

	var wrongCalls []bool
	var wrongOutput bytes.Buffer
	err := environment.service.Show("~/.show-secret", &wrongOutput, recordingPasswordProvider("wrong password", &wrongCalls))
	if !errors.Is(err, cryptox.ErrInvalidPassword) {
		t.Fatalf("Show() wrong-password error = %v, want ErrInvalidPassword", err)
	}
	assertPasswordCalls(t, wrongCalls, []bool{false})
	if wrongOutput.Len() != 0 {
		t.Fatalf("wrong-password Show() wrote %q", wrongOutput.String())
	}

	var correctCalls []bool
	var output bytes.Buffer
	if err := environment.service.Show("~/.show-secret", &output, recordingPasswordProvider(testPassword, &correctCalls)); err != nil {
		t.Fatalf("Show() error = %v", err)
	}
	assertPasswordCalls(t, correctCalls, []bool{false})
	if !bytes.Equal(output.Bytes(), plaintext) {
		t.Fatalf("Show() output = %q, want %q", output.Bytes(), plaintext)
	}
	assertFileContents(t, destination, []byte("local value remains\n"))
	assertRepositoryDoesNotContain(t, environment.repository, plaintext)

	stored := repositorySource(t, environment, "~/.show-secret", true)
	var envelope cryptox.Envelope
	if err := json.Unmarshal(mustReadFile(t, stored), &envelope); err != nil {
		t.Fatalf("decode encrypted repository copy: %v", err)
	}
	if len(envelope.Ciphertext) == 0 {
		t.Fatal("encrypted repository copy has empty ciphertext")
	}
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 0x01
	corrupted, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, stored, corrupted, 0o600)

	var corruptCalls []bool
	var corruptOutput bytes.Buffer
	err = environment.service.Show("~/.show-secret", &corruptOutput, recordingPasswordProvider(testPassword, &corruptCalls))
	if !errors.Is(err, cryptox.ErrCorruptCiphertext) {
		t.Fatalf("Show() corrupted-ciphertext error = %v, want ErrCorruptCiphertext", err)
	}
	assertPasswordCalls(t, corruptCalls, []bool{false})
	if corruptOutput.Len() != 0 {
		t.Fatalf("corrupted-ciphertext Show() wrote %q", corruptOutput.String())
	}
	assertFileContents(t, destination, []byte("local value remains\n"))
}

func TestApplyRestoresPublicAndMultipleSensitiveFilesWithOnePasswordRead(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	publicContents := []byte("public profile\n")
	firstSecret := []byte("first-sensitive-value-18acb3\n")
	secondSecret := []byte("second-sensitive-value-b77d01\n")
	publicDestination := mustWriteFile(t, filepath.Join(environment.home, ".profile"), publicContents, 0o640)
	firstDestination := mustWriteFile(t, filepath.Join(environment.home, ".secrets", "alpha"), firstSecret, 0o600)
	secondDestination := mustWriteFile(t, filepath.Join(environment.home, ".secrets", "beta"), secondSecret, 0o600)

	if _, err := environment.service.Add([]string{publicDestination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(public) error = %v", err)
	}
	var addPasswordCalls []bool
	addResult, err := environment.service.Add([]string{secondDestination, firstDestination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, &addPasswordCalls),
	})
	if err != nil {
		t.Fatalf("Add(sensitive files) error = %v", err)
	}
	assertStrings(t, addResult.Added, []string{"~/.secrets/alpha", "~/.secrets/beta"})
	assertPasswordCalls(t, addPasswordCalls, []bool{true})

	if err := os.Remove(publicDestination); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(environment.home, ".secrets")); err != nil {
		t.Fatal(err)
	}

	var applyPasswordCalls []bool
	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &applyPasswordCalls))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"~/.profile", "~/.secrets/alpha", "~/.secrets/beta"})
	assertStrings(t, result.Skipped, nil)
	assertPasswordCalls(t, applyPasswordCalls, []bool{false})
	assertFileContents(t, publicDestination, publicContents)
	assertFileContents(t, firstDestination, firstSecret)
	assertFileContents(t, secondDestination, secondSecret)
	assertPermissions(t, publicDestination, 0o644)
	assertPermissions(t, firstDestination, 0o600)
	assertPermissions(t, secondDestination, 0o600)
	assertRepositoryDoesNotContain(t, environment.repository, firstSecret)
	assertRepositoryDoesNotContain(t, environment.repository, secondSecret)
}

func TestApplyRejectsDarwinCaseAndUnicodeDestinationAliases(t *testing.T) {
	tests := []struct {
		name    string
		entries func(*testing.T, *testEnvironment) []manifest.Entry
	}{
		{
			name: "HOME and XDG case alias",
			entries: func(t *testing.T, environment *testEnvironment) []manifest.Entry {
				return []manifest.Entry{
					mustLogicalEntry(t, "${XDG_CONFIG_HOME}/item", true),
					mustLogicalEntry(t, "~/config/item", false),
				}
			},
		},
		{
			name: "NFC and NFD alias",
			entries: func(t *testing.T, environment *testEnvironment) []manifest.Entry {
				return []manifest.Entry{
					mustLogicalEntry(t, "~/caf\u00e9", true),
					mustLogicalEntry(t, "~/cafe\u0301", false),
				}
			},
		},
		{
			name: "case-aliased ancestor",
			entries: func(t *testing.T, environment *testEnvironment) []manifest.Entry {
				return []manifest.Entry{
					mustLogicalEntry(t, "${XDG_CONFIG_HOME}/parent", true),
					mustLogicalEntry(t, "~/config/PARENT/child", false),
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", xdgConfigUnderHomeCase: true})
			current := manifest.New()
			current.Crypto = mustCryptoMetadata(t)
			current.Entries = test.entries(t, environment)
			mustSaveManifest(t, environment, current)
			var passwordCalls []bool

			result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
			if !errors.Is(err, app.ErrDestinationConflict) {
				t.Fatalf("Apply(aliased destinations) error = %v, want ErrDestinationConflict", err)
			}
			assertStrings(t, result.Applied, nil)
			assertStrings(t, result.Skipped, nil)
			assertPasswordCalls(t, passwordCalls, nil)
			for _, entry := range current.Entries {
				assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)))
			}
		})
	}
}

func TestApplyPrioritizesProtectedRootErrorsOverDestinationAliases(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", repositoryUnderHome: true})
	protectedDestination := filepath.Join(environment.repositoryInput, "protected")
	protected := mustEntryForDestination(t, environment, protectedDestination, true)
	alias := mustLogicalEntry(t, "~/SRC/REPOSITORY/PROTECTED", false)
	current := manifest.New()
	current.Crypto = mustCryptoMetadata(t)
	current.Entries = []manifest.Entry{protected, alias}
	mustSaveManifest(t, environment, current)
	var passwordCalls []bool

	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if !errors.Is(err, app.ErrProtectedRepository) {
		t.Fatalf("Apply(protected alias conflict) error = %v, want ErrProtectedRepository", err)
	}
	if errors.Is(err, app.ErrDestinationConflict) {
		t.Fatalf("Apply(protected alias conflict) returned lower-priority ErrDestinationConflict: %v", err)
	}
	assertStrings(t, result.Applied, nil)
	assertStrings(t, result.Skipped, nil)
	assertPasswordCalls(t, passwordCalls, nil)
}

func TestApplyRechecksDestinationAliasesAfterPassword(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", customXDG: true})
	current := manifest.New()
	current.Crypto = mustCryptoMetadata(t)
	current.Entries = []manifest.Entry{
		mustLogicalEntry(t, "${XDG_CONFIG_HOME}/shared", true),
		mustLogicalEntry(t, "~/shared", false),
	}
	mustSaveManifest(t, environment, current)
	var passwordCalls []bool
	passwordProvider := func(create bool) ([]byte, error) {
		passwordCalls = append(passwordCalls, create)
		if err := os.RemoveAll(environment.xdgConfigHome); err != nil {
			return nil, err
		}
		if err := os.Symlink(environment.home, environment.xdgConfigHome); err != nil {
			return nil, err
		}
		return []byte(testPassword), nil
	}

	result, err := environment.service.Apply(passwordProvider)
	if !errors.Is(err, app.ErrDestinationConflict) {
		t.Fatalf("Apply(password-time destination alias) error = %v, want ErrDestinationConflict", err)
	}
	assertStrings(t, result.Applied, nil)
	assertStrings(t, result.Skipped, nil)
	assertPasswordCalls(t, passwordCalls, []bool{false})
	for _, entry := range current.Entries {
		assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)))
	}
}

func TestApplySkipsExcludedDarwinDestinationAlias(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin", xdgConfigUnderHomeCase: true})
	applied := mustLogicalEntry(t, "${XDG_CONFIG_HOME}/item", false)
	excluded := mustLogicalEntry(t, "~/config/ITEM", true)
	excluded.ExcludePlatforms = []string{"darwin"}
	current := manifest.New()
	current.Crypto = mustCryptoMetadata(t)
	current.Entries = []manifest.Entry{applied, excluded}
	mustSaveManifest(t, environment, current)
	storedContents := []byte("applicable snapshot\n")
	mustWriteFile(t, filepath.Join(environment.repository, filepath.FromSlash(applied.Source)), storedContents, 0o644)
	var passwordCalls []bool

	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if err != nil {
		t.Fatalf("Apply(excluded alias) error = %v", err)
	}
	assertStrings(t, result.Applied, []string{applied.Path})
	assertStrings(t, result.Skipped, []string{excluded.Path})
	assertPasswordCalls(t, passwordCalls, nil)
	assertFileContents(t, filepath.Join(environment.xdgConfigHome, "item"), storedContents)
	assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(excluded.Source)))
}

func TestApplyKeepsLinuxCaseVariantsDistinct(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "linux", xdgConfigUnderHomeCase: true})
	first := mustLogicalEntry(t, "${XDG_CONFIG_HOME}/item", false)
	second := mustLogicalEntry(t, "~/config/ITEM", false)
	current := manifest.New()
	current.Entries = []manifest.Entry{first, second}
	mustSaveManifest(t, environment, current)
	mustWriteFile(t, filepath.Join(environment.repository, filepath.FromSlash(first.Source)), []byte("first\n"), 0o644)
	mustWriteFile(t, filepath.Join(environment.repository, filepath.FromSlash(second.Source)), []byte("second\n"), 0o644)

	result, err := environment.service.Apply(nil)
	if err != nil {
		t.Fatalf("Apply(Linux case variants) error = %v", err)
	}
	assertStrings(t, result.Applied, []string{first.Path, second.Path})
	assertStrings(t, result.Skipped, nil)
}

func TestApplyReplacesLeafSymlinkWithoutFollowingItsTarget(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "darwin"})
	storedContents := []byte("managed snapshot\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".leaf-symlink"), storedContents, 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	outside := mustWriteFile(t, filepath.Join(environment.root, "outside-target"), []byte("outside unchanged\n"), 0o600)
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, destination); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	result, err := environment.service.Apply(nil)
	if err != nil {
		t.Fatalf("Apply(leaf symlink) error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"~/.leaf-symlink"})
	info, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("destination mode after Apply() = %v, want regular file", info.Mode())
	}
	assertFileContents(t, destination, storedContents)
	assertFileContents(t, outside, []byte("outside unchanged\n"))
}

func TestSensitiveApplyReplacesLeafSymlinkWithoutFollowingItsTarget(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	storedContents := []byte("sensitive managed snapshot\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".sensitive-leaf-symlink"), storedContents, 0o600)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add(sensitive) error = %v", err)
	}
	outsideContents := []byte("outside target remains unchanged\n")
	outside := mustWriteFile(t, filepath.Join(environment.root, "sensitive-outside-target"), outsideContents, 0o600)
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, destination); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	var passwordCalls []bool

	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if err != nil {
		t.Fatalf("Apply(sensitive leaf symlink) error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"~/.sensitive-leaf-symlink"})
	assertPasswordCalls(t, passwordCalls, []bool{false})
	info, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("sensitive destination mode after Apply() = %v, want regular file", info.Mode())
	}
	assertPermissions(t, destination, 0o600)
	assertFileContents(t, destination, storedContents)
	assertFileContents(t, outside, outsideContents)
}

func TestSensitiveApplyBreaksExistingDestinationHardLinks(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	storedContents := []byte("sensitive repository snapshot\n")
	destination := mustWriteFile(t, filepath.Join(environment.home, ".sensitive-hard-link"), storedContents, 0o600)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add(sensitive) error = %v", err)
	}
	alias := filepath.Join(environment.root, "existing-hard-link-alias")
	if err := os.Link(destination, alias); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	localContents := []byte("local inode contents before apply\n")
	mustWriteFile(t, destination, localContents, 0o600)
	if !sameExistingFile(destination, alias) {
		t.Fatal("hard-link fixture paths do not identify the same file")
	}
	var passwordCalls []bool

	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if err != nil {
		t.Fatalf("Apply(sensitive hard link) error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"~/.sensitive-hard-link"})
	assertPasswordCalls(t, passwordCalls, []bool{false})
	assertFileContents(t, destination, storedContents)
	assertFileContents(t, alias, localContents)
	if sameExistingFile(destination, alias) {
		t.Fatal("Apply() wrote through the existing hard link instead of installing a new inode")
	}
}

func TestApplyPreservesUnmanagedStagingLikeFiles(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	directory := filepath.Join(environment.home, ".config", "staging-safety")
	destination := mustWriteFile(t, filepath.Join(directory, "managed"), []byte("stored value\n"), 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	mustWriteFile(t, destination, []byte("local value\n"), 0o644)

	unmanaged := map[string][]byte{
		filepath.Join(directory, ".susu-apply-user-backup.tmp"):              []byte("user backup\n"),
		filepath.Join(directory, ".susu-apply-0123456789abcdef01234567.tmp"): []byte("exact-shape unmanaged file\n"),
	}
	for filename, contents := range unmanaged {
		mustWriteFile(t, filename, contents, 0o600)
	}

	result, err := environment.service.Apply(nil)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"${XDG_CONFIG_HOME}/staging-safety/managed"})
	assertFileContents(t, destination, []byte("stored value\n"))
	for filename, contents := range unmanaged {
		assertFileContents(t, filename, contents)
	}
}

func TestApplyPreflightsCorruptedSensitiveDataBeforeChangingPublicDestinations(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	publicDestination := mustWriteFile(t, filepath.Join(environment.home, ".a-public"), []byte("repository public\n"), 0o644)
	sensitiveDestination := mustWriteFile(t, filepath.Join(environment.home, ".z-sensitive"), []byte("repository secret\n"), 0o600)
	if _, err := environment.service.Add([]string{publicDestination}, app.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.service.Add([]string{sensitiveDestination}, app.AddOptions{Sensitive: true, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, publicDestination, []byte("local public must remain\n"), 0o644)
	stored := repositorySource(t, environment, "~/.z-sensitive", true)
	serialized, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cryptox.Envelope
	if err := json.Unmarshal(serialized, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 0x01
	corrupted, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, stored, corrupted, 0o600)

	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, nil))
	if !errors.Is(err, cryptox.ErrCorruptCiphertext) {
		t.Fatalf("Apply() error = %v, want ErrCorruptCiphertext", err)
	}
	assertStrings(t, result.Applied, nil)
	assertFileContents(t, publicDestination, []byte("local public must remain\n"))
}

func TestApplyHonorsPlatformExclusions(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "linux"})
	darwinOnly := mustWriteFile(t, filepath.Join(environment.home, ".darwin-only"), []byte("darwin\n"), 0o644)
	linuxOnly := mustWriteFile(t, filepath.Join(environment.home, ".linux-only"), []byte("linux\n"), 0o644)
	shared := mustWriteFile(t, filepath.Join(environment.home, ".shared"), []byte("shared\n"), 0o644)

	if _, err := environment.service.Add([]string{darwinOnly}, app.AddOptions{ExcludePlatforms: []string{"linux"}}); err != nil {
		t.Fatalf("Add(darwin-only) error = %v", err)
	}
	if _, err := environment.service.Add([]string{linuxOnly}, app.AddOptions{ExcludePlatforms: []string{"darwin"}}); err != nil {
		t.Fatalf("Add(linux-only) error = %v", err)
	}
	if _, err := environment.service.Add([]string{shared}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(shared) error = %v", err)
	}
	removeDestinations(t, darwinOnly, linuxOnly, shared)

	linuxResult, err := environment.service.Apply(nil)
	if err != nil {
		t.Fatalf("linux Apply() error = %v", err)
	}
	assertStrings(t, linuxResult.Applied, []string{"~/.linux-only", "~/.shared"})
	assertStrings(t, linuxResult.Skipped, []string{"~/.darwin-only"})
	assertPathDoesNotExist(t, darwinOnly)
	assertFileContents(t, linuxOnly, []byte("linux\n"))
	assertFileContents(t, shared, []byte("shared\n"))

	removeDestinations(t, darwinOnly, linuxOnly, shared)
	darwinService, err := app.New(environment.store, environment.resolver, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	darwinResult, err := darwinService.Apply(nil)
	if err != nil {
		t.Fatalf("darwin Apply() error = %v", err)
	}
	assertStrings(t, darwinResult.Applied, []string{"~/.darwin-only", "~/.shared"})
	assertStrings(t, darwinResult.Skipped, []string{"~/.linux-only"})
	assertFileContents(t, darwinOnly, []byte("darwin\n"))
	assertPathDoesNotExist(t, linuxOnly)
	assertFileContents(t, shared, []byte("shared\n"))
}

func TestXDGCustomAndFallbackLocations(t *testing.T) {
	for _, test := range []struct {
		name      string
		customXDG bool
	}{
		{name: "custom", customXDG: true},
		{name: "HOME fallback", customXDG: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{customXDG: test.customXDG})
			contents := []byte("xdg integration contents\n")
			destination := mustWriteFile(t, filepath.Join(environment.xdgConfigHome, "tool with spaces", "config.toml"), contents, 0o644)

			result, err := environment.service.Add([]string{destination}, app.AddOptions{})
			if err != nil {
				t.Fatalf("Add() error = %v", err)
			}
			logical := "${XDG_CONFIG_HOME}/tool with spaces/config.toml"
			assertStrings(t, result.Added, []string{logical})
			assertFileContents(t, filepath.Join(environment.repository, "public", ".config", "tool with spaces", "config.toml"), contents)

			wantStatePath := filepath.Join(environment.xdgStateHome, "susu", "state.json")
			if environment.store.Path() != wantStatePath {
				t.Fatalf("state path = %q, want %q", environment.store.Path(), wantStatePath)
			}
			if _, err := os.Stat(environment.store.Path()); err != nil {
				t.Fatalf("state file was not created at XDG location: %v", err)
			}
			manifestJSON := mustReadFile(t, filepath.Join(environment.repository, manifest.Filename))
			for _, localRoot := range []string{environment.home, environment.xdgConfigHome} {
				if bytes.Contains(manifestJSON, []byte(localRoot)) {
					t.Fatalf("manifest contains machine-local root %q: %s", localRoot, manifestJSON)
				}
			}

			if err := os.RemoveAll(filepath.Join(environment.xdgConfigHome, "tool with spaces")); err != nil {
				t.Fatal(err)
			}
			applyResult, err := environment.service.Apply(nil)
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			assertStrings(t, applyResult.Applied, []string{logical})
			assertFileContents(t, destination, contents)
		})
	}
}

func TestPathsWithSpaces(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{pathsWithSpaces: true})
	contents := []byte("items with spaces\n")
	destination := mustWriteFile(
		t,
		filepath.Join(environment.home, "Library", "Application Support", "Tool Name", "items file.json"),
		contents,
		0o644,
	)

	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if err != nil {
		t.Fatalf("Add(path with spaces) error = %v", err)
	}
	logical := "~/Library/Application Support/Tool Name/items file.json"
	assertStrings(t, result.Added, []string{logical})
	assertFileContents(
		t,
		filepath.Join(environment.repository, "public", "Library", "Application Support", "Tool Name", "items file.json"),
		contents,
	)

	var output bytes.Buffer
	if err := environment.service.Show(logical, &output, nil); err != nil {
		t.Fatalf("Show(path with spaces) error = %v", err)
	}
	if !bytes.Equal(output.Bytes(), contents) {
		t.Fatalf("Show(path with spaces) = %q, want %q", output.Bytes(), contents)
	}
	boundRepository, err := environment.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if boundRepository != environment.repository || !strings.Contains(boundRepository, "repository with spaces") {
		t.Fatalf("stored repository binding = %q", boundRepository)
	}
}

func TestApplyRejectsLocalStateDestinationBeforePasswordOrMutation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	publicDestination := mustWriteFile(t, filepath.Join(environment.home, ".a-public"), []byte("stored public\n"), 0o644)
	sensitiveDestination := mustWriteFile(t, filepath.Join(environment.home, ".z-sensitive"), []byte("stored secret\n"), 0o600)
	if _, err := environment.service.Add([]string{publicDestination}, app.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.service.Add([]string{sensitiveDestination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, publicDestination, []byte("local public must remain\n"), 0o644)
	mustWriteFile(t, sensitiveDestination, []byte("local secret must remain\n"), 0o600)
	stateBefore := mustReadFile(t, environment.store.Path())

	protectedLogical, err := environment.resolver.Normalize(environment.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	protectedSource, err := manifest.SourceFor(protectedLogical, false)
	if err != nil {
		t.Fatal(err)
	}
	current := mustLoadManifest(t, environment)
	current.Entries = append(current.Entries, manifest.Entry{Path: protectedLogical, Source: protectedSource})
	mustSaveManifest(t, environment, current)
	assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(protectedSource)))

	var passwordCalls []bool
	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Apply() error = %v, want ErrProtectedLocalState", err)
	}
	if !strings.Contains(err.Error(), "susu rm <path>") {
		t.Fatalf("Apply() error is not actionable: %v", err)
	}
	assertStrings(t, result.Applied, nil)
	assertStrings(t, result.Skipped, nil)
	assertPasswordCalls(t, passwordCalls, nil)
	assertFileContents(t, environment.store.Path(), stateBefore)
	assertFileContents(t, publicDestination, []byte("local public must remain\n"))
	assertFileContents(t, sensitiveDestination, []byte("local secret must remain\n"))
}

func TestApplyRejectsLocalStateDirectoryControlPathsAndAncestor(t *testing.T) {
	tests := []struct {
		name   string
		target func(*testEnvironment) string
	}{
		{name: "state directory", target: func(environment *testEnvironment) string { return environment.store.Directory() }},
		{name: "state lock", target: func(environment *testEnvironment) string { return filepath.Join(environment.store.Directory(), "lock") }},
		{name: "state staging file", target: func(environment *testEnvironment) string {
			return filepath.Join(environment.store.Directory(), ".state-orphan.tmp")
		}},
		{name: "state directory ancestor", target: func(environment *testEnvironment) string { return filepath.Dir(environment.store.Directory()) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			logical, err := environment.resolver.Normalize(test.target(environment))
			if err != nil {
				t.Fatal(err)
			}
			source, err := manifest.SourceFor(logical, false)
			if err != nil {
				t.Fatal(err)
			}
			current := mustLoadManifest(t, environment)
			current.Entries = append(current.Entries, manifest.Entry{Path: logical, Source: source})
			mustSaveManifest(t, environment, current)

			result, err := environment.service.Apply(nil)
			if !errors.Is(err, app.ErrProtectedLocalState) {
				t.Fatalf("Apply() error = %v, want ErrProtectedLocalState", err)
			}
			assertStrings(t, result.Applied, nil)
		})
	}
}

func TestApplyRejectsSymlinkedLocalStateDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	stateBefore := mustReadFile(t, environment.store.Path())
	aliasDirectory := filepath.Join(environment.home, "state-root-link")
	if err := os.Symlink(environment.store.Directory(), aliasDirectory); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	alias := filepath.Join(aliasDirectory, filepath.Base(environment.store.Path()))
	logical, err := environment.resolver.Normalize(alias)
	if err != nil {
		t.Fatal(err)
	}
	source, err := manifest.SourceFor(logical, false)
	if err != nil {
		t.Fatal(err)
	}
	current := mustLoadManifest(t, environment)
	current.Entries = append(current.Entries, manifest.Entry{Path: logical, Source: source})
	mustSaveManifest(t, environment, current)

	result, err := environment.service.Apply(nil)
	if !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Apply(state symlink alias) error = %v, want ErrProtectedLocalState", err)
	}
	assertStrings(t, result.Applied, nil)
	assertFileContents(t, environment.store.Path(), stateBefore)
}

func TestApplyRejectsCaseAliasedLocalStateDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	aliasedDirectory := filepath.Join(
		filepath.Dir(environment.store.Directory()),
		strings.ToUpper(filepath.Base(environment.store.Directory())),
	)
	aliasedState := filepath.Join(aliasedDirectory, filepath.Base(environment.store.Path()))
	stateInfo, err := os.Stat(environment.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(aliasedState)
	if err != nil || !os.SameFile(stateInfo, aliasInfo) {
		t.Skip("test filesystem is case-sensitive")
	}
	stateBefore := mustReadFile(t, environment.store.Path())
	logical, err := environment.resolver.Normalize(aliasedState)
	if err != nil {
		t.Fatal(err)
	}
	source, err := manifest.SourceFor(logical, false)
	if err != nil {
		t.Fatal(err)
	}
	current := mustLoadManifest(t, environment)
	current.Entries = append(current.Entries, manifest.Entry{Path: logical, Source: source})
	mustSaveManifest(t, environment, current)

	result, err := environment.service.Apply(nil)
	if !errors.Is(err, app.ErrProtectedLocalState) {
		t.Fatalf("Apply(state case alias) error = %v, want ErrProtectedLocalState", err)
	}
	assertStrings(t, result.Applied, nil)
	assertFileContents(t, environment.store.Path(), stateBefore)
}

func TestApplyRejectsHardLinkedLocalStateDestination(t *testing.T) {
	tests := []struct {
		name    string
		target  func(*testEnvironment) string
		prepare func(*testing.T, string)
	}{
		{
			name:   "state file",
			target: func(environment *testEnvironment) string { return environment.store.Path() },
		},
		{
			name: "state lock",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), "lock")
			},
		},
		{
			name: "state staging file",
			target: func(environment *testEnvironment) string {
				return filepath.Join(environment.store.Directory(), ".state-orphan.tmp")
			},
			prepare: func(t *testing.T, target string) {
				mustWriteFile(t, target, []byte("orphaned local state staging data\n"), 0o600)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			target := test.target(environment)
			if test.prepare != nil {
				test.prepare(t, target)
			}
			targetBefore := mustReadFile(t, target)
			stateBefore := mustReadFile(t, environment.store.Path())

			aliasDirectory := filepath.Join(environment.home, "state-aliases")
			if err := os.MkdirAll(aliasDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(aliasDirectory, "protected-copy")
			if err := os.Link(target, alias); err != nil {
				t.Skipf("hard links are unavailable: %v", err)
			}
			logical, err := environment.resolver.Normalize(alias)
			if err != nil {
				t.Fatal(err)
			}
			source, err := manifest.SourceFor(logical, false)
			if err != nil {
				t.Fatal(err)
			}
			current := mustLoadManifest(t, environment)
			current.Entries = append(current.Entries, manifest.Entry{Path: logical, Source: source})
			mustSaveManifest(t, environment, current)
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore := mustReadFile(t, manifestPath)

			result, err := environment.service.Apply(nil)
			if !errors.Is(err, app.ErrProtectedLocalState) {
				t.Fatalf("Apply(hard-link destination) error = %v, want ErrProtectedLocalState", err)
			}
			assertStrings(t, result.Applied, nil)
			assertStrings(t, result.Skipped, nil)
			assertFileContents(t, manifestPath, manifestBefore)
			assertFileContents(t, environment.store.Path(), stateBefore)
			assertFileContents(t, target, targetBefore)
			assertFileContents(t, alias, targetBefore)
		})
	}
}

func TestApplySkipsExcludedLocalStateDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "linux"})
	destination := mustWriteFile(t, filepath.Join(environment.home, ".restore"), []byte("stored\n"), 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	excludedSensitive := mustWriteFile(t, filepath.Join(environment.home, ".excluded-secret"), []byte("stored secret\n"), 0o600)
	if _, err := environment.service.Add([]string{excludedSensitive}, app.AddOptions{
		Sensitive:        true,
		ExcludePlatforms: []string{"linux"},
		Password:         recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, excludedSensitive, []byte("local excluded secret must remain\n"), 0o600)
	stateBefore := mustReadFile(t, environment.store.Path())

	protectedLogical, err := environment.resolver.Normalize(environment.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	protectedSource, err := manifest.SourceFor(protectedLogical, true)
	if err != nil {
		t.Fatal(err)
	}
	current := mustLoadManifest(t, environment)
	current.Entries = append(current.Entries, manifest.Entry{
		Path: protectedLogical, Source: protectedSource, Sensitive: true, ExcludePlatforms: []string{"linux"},
	})
	mustSaveManifest(t, environment, current)
	assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(protectedSource)))

	var passwordCalls []bool
	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertStrings(t, result.Applied, []string{"~/.restore"})
	assertStrings(t, result.Skipped, []string{"~/.excluded-secret", protectedLogical})
	assertPasswordCalls(t, passwordCalls, nil)
	assertFileContents(t, destination, []byte("stored\n"))
	assertFileContents(t, excludedSensitive, []byte("local excluded secret must remain\n"))
	assertFileContents(t, environment.store.Path(), stateBefore)
}

func TestRemoveCleansLegacyLocalStateEntryWithoutChangingBinding(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	stateBefore := mustReadFile(t, environment.store.Path())
	protectedLogical, err := environment.resolver.Normalize(environment.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	protectedSource, err := manifest.SourceFor(protectedLogical, false)
	if err != nil {
		t.Fatal(err)
	}
	stored := mustWriteFile(
		t,
		filepath.Join(environment.repository, filepath.FromSlash(protectedSource)),
		[]byte("legacy repository binding\n"),
		0o644,
	)
	current := mustLoadManifest(t, environment)
	current.Entries = append(current.Entries, manifest.Entry{Path: protectedLogical, Source: protectedSource})
	mustSaveManifest(t, environment, current)

	entries, err := environment.service.List()
	if err != nil {
		t.Fatalf("List() legacy entry error = %v", err)
	}
	if len(entries) != 1 || entries[0].Path != protectedLogical {
		t.Fatalf("List() legacy entries = %+v, want %q", entries, protectedLogical)
	}
	var output bytes.Buffer
	if err := environment.service.Show(protectedLogical, &output, nil); err != nil {
		t.Fatalf("Show() legacy entry error = %v", err)
	}
	if got, want := output.String(), "legacy repository binding\n"; got != want {
		t.Fatalf("Show() legacy output = %q, want %q", got, want)
	}
	assertFileContents(t, environment.store.Path(), stateBefore)

	result, err := environment.service.Remove([]string{protectedLogical})
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	assertStrings(t, result.Removed, []string{protectedLogical})
	assertPathDoesNotExist(t, stored)
	assertFileContents(t, environment.store.Path(), stateBefore)
	assertStrings(t, managedPaths(t, environment.service), nil)
}

func TestApplyRejectsRepositoryDestinationsBeforePasswordSourceOrMutation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	storedEarlier := []byte("stored earlier destination\n")
	localEarlier := []byte("local earlier destination must remain\n")
	earlierDestination := mustWriteFile(t, filepath.Join(environment.home, ".a-apply-before"), storedEarlier, 0o644)
	if _, err := environment.service.Add([]string{earlierDestination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(earlier public) error = %v", err)
	}
	cryptoSeed := mustWriteFile(t, filepath.Join(environment.home, ".crypto-seed"), []byte("crypto seed\n"), 0o600)
	if _, err := environment.service.Add([]string{cryptoSeed}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add(crypto seed) error = %v", err)
	}
	base := mustLoadManifest(t, environment)
	if base.Crypto == nil {
		t.Fatal("crypto seed did not initialize repository metadata")
	}
	earlierEntry := mustFindEntry(t, base, "~/.a-apply-before")

	const stagingSuffix = "0123456789abcdef01234567"
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestInput := filepath.Join(environment.repositoryInput, manifest.Filename)
	repositoryLock := filepath.Join(environment.gitCommonDirectory, "susu.lock")
	controlFiles := map[string][]byte{
		repositoryLock: []byte("repository lock sentinel\n"),
		filepath.Join(environment.repository, ".susu-123456789.tmp"):                       []byte("manifest staging sentinel\n"),
		filepath.Join(environment.repository, "public", ".susu-add-"+stagingSuffix+".tmp"): []byte("add staging sentinel\n"),
		filepath.Join(environment.repository, ".susu-apply-"+stagingSuffix+".tmp"):         []byte("apply staging sentinel\n"),
	}
	for filename, contents := range controlFiles {
		mustWriteFile(t, filename, contents, 0o600)
	}

	tests := []struct {
		name        string
		destination string
	}{
		{name: "exact worktree", destination: environment.repositoryInput},
		{name: "manifest", destination: manifestInput},
		{name: "public storage", destination: filepath.Join(environment.repositoryInput, "public")},
		{name: "encrypted storage", destination: filepath.Join(environment.repositoryInput, "encrypted")},
		{name: "Git directory", destination: environment.gitCommonDirectory},
		{name: "repository lock", destination: repositoryLock},
		{name: "manifest staging file", destination: filepath.Join(environment.repositoryInput, ".susu-123456789.tmp")},
		{name: "add staging file", destination: filepath.Join(environment.repositoryInput, "public", ".susu-add-"+stagingSuffix+".tmp")},
		{name: "apply staging file", destination: filepath.Join(environment.repositoryInput, ".susu-apply-"+stagingSuffix+".tmp")},
		{name: "representable ancestor", destination: filepath.Dir(environment.repositoryInput)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mustWriteFile(t, earlierDestination, localEarlier, 0o644)
			protectedEntry := mustEntryForDestination(t, environment, test.destination, true)
			current := manifest.New()
			current.Crypto = base.Crypto
			current.Entries = []manifest.Entry{earlierEntry, protectedEntry}
			mustSaveManifest(t, environment, current)
			protectedSource := filepath.Join(environment.repository, filepath.FromSlash(protectedEntry.Source))
			assertPathDoesNotExist(t, protectedSource)
			manifestBefore := mustReadFile(t, manifestPath)

			var passwordCalls []bool
			result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
			if !errors.Is(err, app.ErrProtectedRepository) {
				t.Fatalf("Apply(%q) error = %v, want ErrProtectedRepository", test.destination, err)
			}
			if !strings.Contains(err.Error(), "susu rm <path>") {
				t.Fatalf("Apply(%q) error is not actionable: %v", test.destination, err)
			}
			assertStrings(t, result.Applied, nil)
			assertStrings(t, result.Skipped, nil)
			assertPasswordCalls(t, passwordCalls, nil)
			assertFileContents(t, earlierDestination, localEarlier)
			assertFileContents(t, manifestPath, manifestBefore)
			assertPathDoesNotExist(t, protectedSource)
			for filename, contents := range controlFiles {
				assertFileContents(t, filename, contents)
			}
		})
	}
}

func TestApplyRejectsRepositorySymlinkAndCaseAliases(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	manifestPath := filepath.Join(environment.repository, manifest.Filename)

	t.Run("symlink alias", func(t *testing.T) {
		alias := filepath.Join(environment.home, "active-repository-destination-link")
		if err := os.Symlink(environment.repository, alias); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		entry := mustEntryForDestination(t, environment, alias, false)
		current := manifest.New()
		current.Entries = []manifest.Entry{entry}
		mustSaveManifest(t, environment, current)
		assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)))
		manifestBefore := mustReadFile(t, manifestPath)

		result, err := environment.service.Apply(nil)
		if !errors.Is(err, app.ErrProtectedRepository) {
			t.Fatalf("Apply(repository symlink alias) error = %v, want ErrProtectedRepository", err)
		}
		assertStrings(t, result.Applied, nil)
		assertFileContents(t, manifestPath, manifestBefore)
		if info, statErr := os.Lstat(alias); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("protected destination symlink changed: mode = %v, error = %v", info, statErr)
		}
	})

	t.Run("case alias", func(t *testing.T) {
		alias := filepath.Join(filepath.Dir(environment.repositoryInput), strings.ToUpper(filepath.Base(environment.repositoryInput)))
		repositoryInfo, err := os.Stat(environment.repository)
		if err != nil {
			t.Fatal(err)
		}
		aliasInfo, err := os.Stat(alias)
		if err != nil || !os.SameFile(repositoryInfo, aliasInfo) {
			t.Skip("test filesystem is case-sensitive")
		}
		entry := mustEntryForDestination(t, environment, alias, false)
		current := manifest.New()
		current.Entries = []manifest.Entry{entry}
		mustSaveManifest(t, environment, current)
		assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)))
		manifestBefore := mustReadFile(t, manifestPath)

		result, err := environment.service.Apply(nil)
		if !errors.Is(err, app.ErrProtectedRepository) {
			t.Fatalf("Apply(repository case alias) error = %v, want ErrProtectedRepository", err)
		}
		assertStrings(t, result.Applied, nil)
		assertFileContents(t, manifestPath, manifestBefore)
	})
}

func TestApplyRejectsLinkedWorktreeGitCommonDestinations(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{linkedWorktree: true, customXDG: true})
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	repositoryLock := filepath.Join(environment.gitCommonDirectory, "susu.lock")
	tests := []struct {
		name        string
		destination string
	}{
		{name: "Git common root", destination: environment.gitCommonDirectory},
		{name: "repository lock", destination: repositoryLock},
		{name: "Git common ancestor", destination: filepath.Dir(environment.gitCommonDirectory)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := mustEntryForDestination(t, environment, test.destination, false)
			current := manifest.New()
			current.Entries = []manifest.Entry{entry}
			mustSaveManifest(t, environment, current)
			assertPathDoesNotExist(t, filepath.Join(environment.repository, filepath.FromSlash(entry.Source)))
			manifestBefore := mustReadFile(t, manifestPath)

			result, err := environment.service.Apply(nil)
			if !errors.Is(err, app.ErrProtectedRepository) {
				t.Fatalf("Apply(%q) error = %v, want ErrProtectedRepository", test.destination, err)
			}
			assertStrings(t, result.Applied, nil)
			assertFileContents(t, manifestPath, manifestBefore)
		})
	}
}

func TestApplyRechecksRepositorySymlinkAfterPasswordBeforeMutation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	earlierStored := []byte("stored earlier apply value\n")
	earlierLocal := []byte("local earlier apply value must remain\n")
	earlierDestination := mustWriteFile(t, filepath.Join(environment.home, ".a-apply-preflight"), earlierStored, 0o644)
	lateDestination := mustWriteFile(t, filepath.Join(environment.home, ".z-late-repository-alias"), []byte("stored sensitive value\n"), 0o600)
	if _, err := environment.service.Add([]string{earlierDestination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(earlier public) error = %v", err)
	}
	if _, err := environment.service.Add([]string{lateDestination}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add(late sensitive) error = %v", err)
	}
	mustWriteFile(t, earlierDestination, earlierLocal, 0o644)
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestBefore := mustReadFile(t, manifestPath)
	earlierSource := repositorySource(t, environment, "~/.a-apply-preflight", false)
	lateSource := repositorySource(t, environment, "~/.z-late-repository-alias", true)
	earlierSourceBefore := mustReadFile(t, earlierSource)
	lateSourceBefore := mustReadFile(t, lateSource)

	var passwordCalls []bool
	passwordProvider := func(create bool) ([]byte, error) {
		passwordCalls = append(passwordCalls, create)
		if err := os.Remove(lateDestination); err != nil {
			return nil, err
		}
		if err := os.Symlink(environment.repository, lateDestination); err != nil {
			return nil, err
		}
		return []byte(testPassword), nil
	}

	result, err := environment.service.Apply(passwordProvider)
	if !errors.Is(err, app.ErrProtectedRepository) {
		t.Fatalf("Apply(late repository symlink) error = %v, want ErrProtectedRepository", err)
	}
	assertStrings(t, result.Applied, nil)
	assertStrings(t, result.Skipped, nil)
	assertPasswordCalls(t, passwordCalls, []bool{false})
	assertFileContents(t, earlierDestination, earlierLocal)
	assertFileContents(t, earlierSource, earlierSourceBefore)
	assertFileContents(t, lateSource, lateSourceBefore)
	assertFileContents(t, manifestPath, manifestBefore)
	if info, statErr := os.Lstat(lateDestination); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("late destination was not left as a repository symlink: mode = %v, error = %v", info, statErr)
	}
}

func TestApplySkipsExcludedSensitiveRepositoryDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{platform: "linux", repositoryUnderHome: true, customXDG: true})
	publicContents := []byte("stored public restore\n")
	publicDestination := mustWriteFile(t, filepath.Join(environment.home, ".restore-outside-repository"), publicContents, 0o644)
	if _, err := environment.service.Add([]string{publicDestination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add(public) error = %v", err)
	}
	cryptoSeed := mustWriteFile(t, filepath.Join(environment.home, ".excluded-crypto-seed"), []byte("crypto seed\n"), 0o600)
	if _, err := environment.service.Add([]string{cryptoSeed}, app.AddOptions{
		Sensitive: true,
		Password:  recordingPasswordProvider(testPassword, nil),
	}); err != nil {
		t.Fatalf("Add(crypto seed) error = %v", err)
	}
	base := mustLoadManifest(t, environment)
	publicEntry := mustFindEntry(t, base, "~/.restore-outside-repository")
	protectedEntry := mustEntryForDestination(t, environment, filepath.Join(environment.repositoryInput, manifest.Filename), true)
	protectedEntry.ExcludePlatforms = []string{"linux"}
	current := manifest.New()
	current.Crypto = base.Crypto
	current.Entries = []manifest.Entry{publicEntry, protectedEntry}
	mustSaveManifest(t, environment, current)
	protectedSource := filepath.Join(environment.repository, filepath.FromSlash(protectedEntry.Source))
	assertPathDoesNotExist(t, protectedSource)
	if err := os.Remove(publicDestination); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	manifestBefore := mustReadFile(t, manifestPath)

	var passwordCalls []bool
	result, err := environment.service.Apply(recordingPasswordProvider(testPassword, &passwordCalls))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertStrings(t, result.Applied, []string{publicEntry.Path})
	assertStrings(t, result.Skipped, []string{protectedEntry.Path})
	assertPasswordCalls(t, passwordCalls, nil)
	assertFileContents(t, publicDestination, publicContents)
	assertFileContents(t, manifestPath, manifestBefore)
	assertPathDoesNotExist(t, protectedSource)
}

func TestLegacyRepositoryEntrySupportsListShowAndRemoveWithoutChangingDestination(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{repositoryUnderHome: true, customXDG: true})
	destinationContents := []byte("protected destination must remain\n")
	storedContents := []byte("legacy stored snapshot\n")
	destination := mustWriteFile(t, filepath.Join(environment.repositoryInput, "legacy-protected-destination"), destinationContents, 0o644)
	entry := mustEntryForDestination(t, environment, destination, false)
	stored := mustWriteFile(
		t,
		filepath.Join(environment.repository, filepath.FromSlash(entry.Source)),
		storedContents,
		0o644,
	)
	current := manifest.New()
	current.Entries = []manifest.Entry{entry}
	mustSaveManifest(t, environment, current)

	entries, err := environment.service.List()
	if err != nil {
		t.Fatalf("List() legacy repository entry error = %v", err)
	}
	if len(entries) != 1 || entries[0].Path != entry.Path {
		t.Fatalf("List() legacy repository entries = %+v, want %q", entries, entry.Path)
	}
	assertFileContents(t, destination, destinationContents)

	var output bytes.Buffer
	if err := environment.service.Show(entry.Path, &output, nil); err != nil {
		t.Fatalf("Show() legacy repository entry error = %v", err)
	}
	if !bytes.Equal(output.Bytes(), storedContents) {
		t.Fatalf("Show() legacy repository output = %q, want %q", output.Bytes(), storedContents)
	}
	assertFileContents(t, destination, destinationContents)

	result, err := environment.service.Remove([]string{entry.Path})
	if err != nil {
		t.Fatalf("Remove() legacy repository entry error = %v", err)
	}
	assertStrings(t, result.Removed, []string{entry.Path})
	assertPathDoesNotExist(t, stored)
	assertFileContents(t, destination, destinationContents)
	assertStrings(t, managedPaths(t, environment.service), nil)
}

func TestApplyDoesNotEscapeThroughDestinationParentSymlink(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(t, filepath.Join(environment.home, "redirect", "victim"), []byte("managed\n"), 0o644)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := os.RemoveAll(filepath.Dir(destination)); err != nil {
		t.Fatal(err)
	}
	outsideDirectory := filepath.Join(environment.root, "outside destination")
	outsideVictim := mustWriteFile(t, filepath.Join(outsideDirectory, "victim"), []byte("outside unchanged\n"), 0o600)
	if err := os.Symlink(outsideDirectory, filepath.Dir(destination)); err != nil {
		t.Skipf("create parent symlink: %v", err)
	}

	if _, err := environment.service.Apply(nil); err == nil {
		t.Fatal("Apply() escaped through a destination parent symlink")
	}
	assertFileContents(t, outsideVictim, []byte("outside unchanged\n"))
}

func TestInitRejectsLocalStateInsideRepository(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	repositoryRoot := filepath.Join(root, "repository")
	for _, directory := range []string{home, repositoryRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	command := exec.Command(gitExecutable, "init", "--quiet", repositoryRoot)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	resolver, err := paths.NewResolverAt(home, "", home)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(home, filepath.Join(repositoryRoot, "local-state"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.New(store, resolver, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Init(repositoryRoot); err == nil || !strings.Contains(err.Error(), "must not be stored inside") {
		t.Fatalf("Init() error = %v, want local-state confinement error", err)
	}
	assertPathDoesNotExist(t, store.Path())
}

func TestInitRejectsLocalStateInsideGitCommonDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	primary := filepath.Join(root, "primary")
	linked := filepath.Join(root, "linked")
	for _, directory := range []string{home, primary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	runTestGit(t, gitExecutable, "init", "--quiet", primary)
	runTestGit(
		t,
		gitExecutable,
		"-C", primary,
		"-c", "user.name=susu tests",
		"-c", "user.email=susu-tests@example.invalid",
		"-c", "commit.gpgSign=false",
		"commit", "--quiet", "--allow-empty", "-m", "linked worktree fixture",
	)
	runTestGit(t, gitExecutable, "-C", primary, "worktree", "add", "--quiet", "--detach", linked, "HEAD")

	resolver, err := paths.NewResolverAt(home, "", home)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(home, filepath.Join(primary, ".git", "local-state"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.New(store, resolver, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Init(linked); err == nil || !strings.Contains(err.Error(), "Git common directory") {
		t.Fatalf("Init() error = %v, want Git-common-directory confinement error", err)
	}
	assertPathDoesNotExist(t, store.Path())
}

func TestInitRejectsCaseAliasedStateInsideRepository(t *testing.T) {
	root := t.TempDir()
	repositoryRoot := filepath.Join(root, "CaseRepository")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasedRoot := filepath.Join(root, "caserepository")
	repositoryInfo, err := os.Stat(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(aliasedRoot)
	if err != nil || !os.SameFile(repositoryInfo, aliasInfo) {
		t.Skip("test filesystem is case-sensitive")
	}
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	if output, err := exec.Command(gitExecutable, "init", "--quiet", repositoryRoot).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := paths.NewResolverAt(home, "", home)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(home, filepath.Join(aliasedRoot, "state"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.New(store, resolver, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Init(repositoryRoot); err == nil {
		t.Fatal("Init() accepted a case-aliased state path inside the repository")
	}
}

func TestConcurrentAddsThroughDifferentStateHomesDoNotLoseManifestUpdates(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	alternateStore, err := state.NewStore(environment.home, filepath.Join(environment.root, "alternate-state"))
	if err != nil {
		t.Fatal(err)
	}
	alternateService, err := app.New(alternateStore, environment.resolver, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alternateService.Init(environment.repository); err != nil {
		t.Fatal(err)
	}
	services := []*app.Service{environment.service, alternateService}
	const count = 8
	files := make([]string, count)
	for index := range files {
		files[index] = mustWriteFile(t, filepath.Join(environment.home, fmt.Sprintf("concurrent-%02d", index)), []byte(fmt.Sprintf("%d\n", index)), 0o644)
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, count)
	for index, filename := range files {
		go func() {
			<-start
			_, err := services[index%len(services)].Add([]string{filename}, app.AddOptions{})
			errorsChannel <- err
		}()
	}
	close(start)
	for range count {
		if err := <-errorsChannel; err != nil {
			t.Fatalf("concurrent Add() error = %v", err)
		}
	}
	entries, err := environment.service.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != count {
		t.Fatalf("managed entries after concurrent adds = %d, want %d", len(entries), count)
	}
}

type testEnvironmentOptions struct {
	platform               string
	customXDG              bool
	xdgConfigUnderKube     bool
	xdgConfigUnderHomeCase bool
	pathsWithSpaces        bool
	repositoryUnderHome    bool
	linkedWorktree         bool
}

type testEnvironment struct {
	root               string
	home               string
	xdgConfigHome      string
	xdgStateHome       string
	repository         string
	repositoryInput    string
	gitCommonDirectory string
	store              *state.Store
	resolver           *paths.Resolver
	service            *app.Service
}

func newTestEnvironment(t *testing.T, options testEnvironmentOptions) *testEnvironment {
	t.Helper()
	root := t.TempDir()
	if testSandbox == "" || !pathWithin(root, testSandbox) {
		t.Fatalf("temporary test root %q is outside isolated sandbox %q", root, testSandbox)
	}
	if realHome != "" && pathWithin(root, realHome) {
		t.Fatalf("temporary test root %q is inside real HOME %q", root, realHome)
	}

	homeName := "home"
	repositoryName := "repository"
	configName := "xdg-config"
	stateName := "xdg-state"
	if options.pathsWithSpaces {
		homeName = "home directory with spaces"
		repositoryName = "repository with spaces"
		configName = "xdg config with spaces"
		stateName = "xdg state with spaces"
	}
	home := filepath.Join(root, homeName)
	repositoryInput := filepath.Join(root, repositoryName)
	if options.repositoryUnderHome {
		repositoryInput = filepath.Join(home, "src", repositoryName)
	}
	configuredXDGConfig := ""
	configuredXDGState := ""
	xdgConfigHome := filepath.Join(home, ".config")
	xdgStateHome := filepath.Join(home, ".local", "state")
	if options.xdgConfigUnderKube {
		configuredXDGConfig = filepath.Join(home, ".kube")
		xdgConfigHome = configuredXDGConfig
	} else if options.xdgConfigUnderHomeCase {
		configuredXDGConfig = filepath.Join(home, "Config")
		xdgConfigHome = configuredXDGConfig
	} else if options.customXDG {
		configuredXDGConfig = filepath.Join(root, configName)
		configuredXDGState = filepath.Join(root, stateName)
		xdgConfigHome = configuredXDGConfig
		xdgStateHome = configuredXDGState
	}
	directories := []string{
		home,
		xdgConfigHome,
		filepath.Join(root, "xdg-cache"),
		filepath.Join(root, "xdg-data"),
		filepath.Join(root, "tmp"),
	}
	if !options.linkedWorktree {
		directories = append(directories, repositoryInput)
	}
	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configuredXDGConfig)
	t.Setenv("XDG_STATE_HOME", configuredXDGState)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "xdg-cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg-data"))
	t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	gitCommonDirectory := filepath.Join(repositoryInput, ".git")
	if options.linkedWorktree {
		primary := filepath.Join(home, "primary-repository")
		if err := os.MkdirAll(primary, 0o700); err != nil {
			t.Fatal(err)
		}
		runTestGit(t, gitExecutable, "init", "--quiet", primary)
		runTestGit(
			t,
			gitExecutable,
			"-C", primary,
			"-c", "user.name=susu tests",
			"-c", "user.email=susu-tests@example.invalid",
			"-c", "commit.gpgSign=false",
			"commit", "--quiet", "--allow-empty", "-m", "linked worktree fixture",
		)
		runTestGit(t, gitExecutable, "-C", primary, "worktree", "add", "--quiet", "--detach", repositoryInput, "HEAD")
		gitCommonDirectory = filepath.Join(primary, ".git")
	} else {
		runTestGit(t, gitExecutable, "init", "--quiet", repositoryInput)
	}

	resolver, err := paths.NewResolverFromEnv()
	if err != nil {
		t.Fatalf("NewResolverFromEnv() error = %v", err)
	}
	store, err := state.NewStoreFromEnv()
	if err != nil {
		t.Fatalf("NewStoreFromEnv() error = %v", err)
	}
	platform := options.platform
	if platform == "" {
		platform = "linux"
	}
	service, err := app.New(store, resolver, platform)
	if err != nil {
		t.Fatalf("app.New() error = %v", err)
	}
	repositoryRoot, err := service.Init(repositoryInput)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	boundRepository, err := store.Load()
	if err != nil {
		t.Fatalf("Load() repository binding error = %v", err)
	}
	if boundRepository != repositoryRoot {
		t.Fatalf("repository binding = %q, want %q", boundRepository, repositoryRoot)
	}

	return &testEnvironment{
		root:               root,
		home:               home,
		xdgConfigHome:      xdgConfigHome,
		xdgStateHome:       xdgStateHome,
		repository:         repositoryRoot,
		repositoryInput:    repositoryInput,
		gitCommonDirectory: gitCommonDirectory,
		store:              store,
		resolver:           resolver,
		service:            service,
	}
}

func runTestGit(t *testing.T, executable string, arguments ...string) {
	t.Helper()
	command := exec.Command(executable, arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func recordingPasswordProvider(password string, calls *[]bool) app.PasswordProvider {
	return func(create bool) ([]byte, error) {
		if calls != nil {
			*calls = append(*calls, create)
		}
		return []byte(password), nil
	}
}

func mustWriteFile(t *testing.T, filename string, contents []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
	return filename
}

func mustReadFile(t *testing.T, filename string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func mustLoadManifest(t *testing.T, environment *testEnvironment) manifest.Manifest {
	t.Helper()
	current, err := manifest.Load(filepath.Join(environment.repository, manifest.Filename))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return current
}

func mustSaveManifest(t *testing.T, environment *testEnvironment, current manifest.Manifest) {
	t.Helper()
	if err := manifest.Save(filepath.Join(environment.repository, manifest.Filename), current); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
}

func mustLogicalEntry(t *testing.T, logical string, sensitive bool) manifest.Entry {
	t.Helper()
	source, err := manifest.SourceFor(logical, sensitive)
	if err != nil {
		t.Fatalf("SourceFor(%q): %v", logical, err)
	}
	return manifest.Entry{Path: logical, Source: source, Sensitive: sensitive}
}

func mustCryptoMetadata(t *testing.T) *cryptox.Metadata {
	t.Helper()
	metadata, masterKey, err := cryptox.Initialize([]byte(testPassword))
	if err != nil {
		t.Fatalf("initialize test repository crypto: %v", err)
	}
	cryptox.ZeroBytes(masterKey)
	return &metadata
}

func sameExistingFile(first, second string) bool {
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}

func mustEntryForDestination(t *testing.T, environment *testEnvironment, destination string, sensitive bool) manifest.Entry {
	t.Helper()
	logical, err := environment.resolver.Normalize(destination)
	if err != nil {
		t.Fatalf("normalize destination %q: %v", destination, err)
	}
	source, err := manifest.SourceFor(logical, sensitive)
	if err != nil {
		t.Fatalf("SourceFor(%q): %v", logical, err)
	}
	return manifest.Entry{Path: logical, Source: source, Sensitive: sensitive}
}

func mustFindEntry(t *testing.T, current manifest.Manifest, logical string) manifest.Entry {
	t.Helper()
	index := manifest.Find(current, logical)
	if index < 0 {
		t.Fatalf("manifest does not contain %q", logical)
	}
	return current.Entries[index]
}

func repositorySource(t *testing.T, environment *testEnvironment, logical string, sensitive bool) string {
	t.Helper()
	source, err := manifest.SourceFor(logical, sensitive)
	if err != nil {
		t.Fatalf("SourceFor(%q): %v", logical, err)
	}
	return filepath.Join(environment.repository, filepath.FromSlash(source))
}

func managedPaths(t *testing.T, service *app.Service) []string {
	t.Helper()
	entries, err := service.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.Path
	}
	return result
}

func mustReadDirectoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read directory %q: %v", directory, err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}

func assertStrings(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("strings = %q, want %q", got, want)
	}
}

func assertPasswordCalls(t *testing.T, got, want []bool) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("password provider create flags = %v, want %v", got, want)
	}
}

func assertFileContents(t *testing.T, filename string, want []byte) {
	t.Helper()
	got := mustReadFile(t, filename)
	if !bytes.Equal(got, want) {
		t.Fatalf("contents of %q = %q, want %q", filename, got, want)
	}
}

func assertPermissions(t *testing.T, filename string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("permissions for %q = %04o, want %04o", filename, got, want)
	}
}

func assertPathDoesNotExist(t *testing.T, filename string) {
	t.Helper()
	_, err := os.Lstat(filename)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %q exists or returned unexpected error: %v", filename, err)
	}
}

func assertRepositoryDoesNotContain(t *testing.T, repository string, plaintext []byte) {
	t.Helper()
	err := filepath.WalkDir(repository, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if bytes.Contains(contents, plaintext) {
			return fmt.Errorf("repository file %q contains sensitive plaintext", filename)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func removeDestinations(t *testing.T, filenames ...string) {
	t.Helper()
	for _, filename := range filenames {
		if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func pathWithin(candidate, root string) bool {
	if candidate == "" || root == "" {
		return false
	}
	candidate = comparablePath(candidate)
	root = comparablePath(root)
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func comparablePath(filename string) string {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return filepath.Clean(filename)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(absolute)
}
