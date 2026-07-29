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
	platform        string
	customXDG       bool
	pathsWithSpaces bool
}

type testEnvironment struct {
	root          string
	home          string
	xdgConfigHome string
	xdgStateHome  string
	repository    string
	store         *state.Store
	resolver      *paths.Resolver
	service       *app.Service
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
	configuredXDGConfig := ""
	configuredXDGState := ""
	xdgConfigHome := filepath.Join(home, ".config")
	xdgStateHome := filepath.Join(home, ".local", "state")
	if options.customXDG {
		configuredXDGConfig = filepath.Join(root, configName)
		configuredXDGState = filepath.Join(root, stateName)
		xdgConfigHome = configuredXDGConfig
		xdgStateHome = configuredXDGState
	}
	for _, directory := range []string{
		home,
		xdgConfigHome,
		filepath.Join(root, "xdg-cache"),
		filepath.Join(root, "xdg-data"),
		filepath.Join(root, "tmp"),
		repositoryInput,
	} {
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
	command := exec.Command(gitExecutable, "init", "--quiet", repositoryInput)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init %q: %v\n%s", repositoryInput, err, output)
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
		root:          root,
		home:          home,
		xdgConfigHome: xdgConfigHome,
		xdgStateHome:  xdgStateHome,
		repository:    repositoryRoot,
		store:         store,
		resolver:      resolver,
		service:       service,
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
