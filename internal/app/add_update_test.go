package app_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"susu/internal/app"
	"susu/internal/cryptox"
	"susu/internal/manifest"
	"susu/internal/repository"
)

func TestAddUpdatePreservesClassificationRegardlessOfFlag(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		for _, flag := range []bool{false, true} {
			t.Run(fmt.Sprintf("sensitive=%t/flag=%t", sensitive, flag), func(t *testing.T) {
				environment := newTestEnvironment(t, testEnvironmentOptions{})
				destination := mustWriteFile(t, filepath.Join(environment.home, "snapshot"), []byte("old\n"), 0o600)
				if _, err := environment.service.Add([]string{destination}, app.AddOptions{Sensitive: sensitive, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
					t.Fatal(err)
				}
				manifestPath := filepath.Join(environment.repository, manifest.Filename)
				manifestBefore := mustReadFile(t, manifestPath)
				manifestInfo, err := os.Stat(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				entryBefore := mustFindEntry(t, mustLoadManifest(t, environment), "~/snapshot")
				plaintext := []byte("updated snapshot secret 9f2e\n")
				mustWriteFile(t, destination, plaintext, 0o711)
				var calls []bool
				result, err := environment.service.Add([]string{destination, destination}, app.AddOptions{Sensitive: flag, Password: recordingPasswordProvider(testPassword, &calls)})
				if err != nil {
					t.Fatal(err)
				}
				assertStrings(t, result.Added, nil)
				assertStrings(t, result.Updated, []string{"~/snapshot"})
				assertStrings(t, result.AlreadyManaged, nil)
				wantCalls := []bool(nil)
				if sensitive {
					wantCalls = []bool{false}
				}
				assertPasswordCalls(t, calls, wantCalls)
				assertFileContents(t, manifestPath, manifestBefore)
				afterInfo, err := os.Stat(manifestPath)
				if err != nil || !os.SameFile(manifestInfo, afterInfo) {
					t.Fatalf("update-only rewrote manifest: %v", err)
				}
				if got := mustFindEntry(t, mustLoadManifest(t, environment), "~/snapshot"); got != entryBefore {
					t.Fatalf("entry changed: %+v", got)
				}
				var shown bytes.Buffer
				if err := environment.service.Show(destination, &shown, recordingPasswordProvider(testPassword, nil)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shown.Bytes(), plaintext) {
					t.Fatalf("Show = %q", shown.Bytes())
				}
				stored := repositorySource(t, environment, "~/snapshot", sensitive)
				if sensitive {
					assertPermissions(t, stored, 0o600)
					assertRepositoryDoesNotContain(t, environment.repository, plaintext)
				} else {
					assertPermissions(t, stored, 0o755)
					mustWriteFile(t, destination, plaintext, 0o600)
					if _, err := environment.service.Add([]string{destination}, app.AddOptions{Sensitive: flag}); err != nil {
						t.Fatal(err)
					}
					assertPermissions(t, stored, 0o644)
				}
				assertPathDoesNotExist(t, repositorySource(t, environment, "~/snapshot", !sensitive))
			})
		}
	}
}

func TestAddRecursiveMixedUpdatesPreserveExistingMetadata(t *testing.T) {
	for _, flag := range []bool{false, true} {
		t.Run(fmt.Sprintf("flag=%t", flag), func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			directory := filepath.Join(environment.home, "tree")
			public := mustWriteFile(t, filepath.Join(directory, "public"), []byte("old public"), 0o644)
			secret := mustWriteFile(t, filepath.Join(directory, "secret"), []byte("old secret"), 0o600)
			for _, input := range []struct {
				path      string
				sensitive bool
			}{{public, false}, {secret, true}} {
				if _, err := environment.service.Add([]string{input.path}, app.AddOptions{Sensitive: input.sensitive, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
					t.Fatal(err)
				}
			}
			before := mustLoadManifest(t, environment)
			mustWriteFile(t, public, []byte("updated public"), 0o644)
			mustWriteFile(t, secret, []byte("updated secret 249c"), 0o600)
			fresh := mustWriteFile(t, filepath.Join(directory, "nested", "new"), []byte("new file 493e"), 0o600)
			var calls []bool
			result, err := environment.service.Add([]string{directory, fresh}, app.AddOptions{Sensitive: flag, Password: recordingPasswordProvider(testPassword, &calls)})
			if err != nil {
				t.Fatal(err)
			}
			assertStrings(t, result.Added, []string{"~/tree/nested/new"})
			assertStrings(t, result.Updated, []string{"~/tree/public", "~/tree/secret"})
			assertStrings(t, result.AlreadyManaged, nil)
			assertPasswordCalls(t, calls, []bool{false})
			after := mustLoadManifest(t, environment)
			if !reflect.DeepEqual(before.Crypto, after.Crypto) {
				t.Fatal("crypto metadata changed")
			}
			for _, entry := range before.Entries {
				if got := mustFindEntry(t, after, entry.Path); got != entry {
					t.Fatalf("entry changed: %+v", got)
				}
			}
			if got := mustFindEntry(t, after, "~/tree/nested/new"); got.Sensitive != flag {
				t.Fatalf("new classification: %+v", got)
			}
			for _, input := range []string{public, secret, fresh} {
				var shown bytes.Buffer
				if err := environment.service.Show(input, &shown, recordingPasswordProvider(testPassword, nil)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shown.Bytes(), mustReadFile(t, input)) {
					t.Fatalf("wrong snapshot for %q", input)
				}
			}
			assertRepositoryDoesNotContain(t, environment.repository, []byte("updated secret 249c"))
		})
	}
}

func TestAddInitialEncryptionWithPublicUpdateUsesEffectiveSources(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	public := mustWriteFile(t, filepath.Join(environment.home, "a"), []byte("old public"), 0o644)
	if _, err := environment.service.Add([]string{public}, app.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	// If the flag were applied to the existing entry, its encrypted source would
	// be an ancestor of the new entry's source instead of remaining public/a.
	secret := mustWriteFile(t, filepath.Join(environment.home, "a.enc", "child"), []byte("new secret 5ae2"), 0o600)
	mustWriteFile(t, public, []byte("updated public"), 0o644)
	var calls []bool
	result, err := environment.service.Add([]string{public, secret}, app.AddOptions{Sensitive: true, Password: recordingPasswordProvider(testPassword, &calls)})
	if err != nil {
		t.Fatal(err)
	}
	assertStrings(t, result.Added, []string{"~/a.enc/child"})
	assertStrings(t, result.Updated, []string{"~/a"})
	assertPasswordCalls(t, calls, []bool{true})
	current := mustLoadManifest(t, environment)
	if current.Crypto == nil {
		t.Fatal("missing initialized crypto metadata")
	}
	if entry := mustFindEntry(t, current, "~/a"); entry.Sensitive || entry.Source != "public/a" {
		t.Fatalf("public entry changed: %+v", entry)
	}
	assertFileContents(t, repositorySource(t, environment, "~/a", false), []byte("updated public"))
	assertRepositoryDoesNotContain(t, environment.repository, []byte("new secret 5ae2"))
	var shown bytes.Buffer
	if err := environment.service.Show(secret, &shown, recordingPasswordProvider(testPassword, nil)); err != nil {
		t.Fatal(err)
	}
	if shown.String() != "new secret 5ae2" {
		t.Fatalf("new secret = %q", shown.String())
	}
}

func TestAddSensitiveAliasOnlyDoesNotUnlockOrRefreshOwner(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	owner := mustWriteFile(t, filepath.Join(environment.home, "owner"), []byte("old secret"), 0o600)
	if _, err := environment.service.Add([]string{owner}, app.AddOptions{Sensitive: true, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
		t.Fatal(err)
	}
	stored := repositorySource(t, environment, "~/owner", true)
	before := mustReadFile(t, stored)
	alias := filepath.Join(environment.home, "alias")
	if err := os.Link(owner, alias); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, alias, []byte("changed secret"), 0o600)
	for _, flag := range []bool{false, true} {
		result, err := environment.service.Add([]string{alias}, app.AddOptions{Sensitive: flag})
		if err != nil {
			t.Fatal(err)
		}
		assertStrings(t, result.AlreadyManaged, []string{"~/alias"})
		assertStrings(t, result.Added, nil)
		assertStrings(t, result.Updated, nil)
		assertFileContents(t, stored, before)
	}
}

func TestAddExactUpdateAcceptsInputReplacedBeforeInvocation(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(t, filepath.Join(environment.home, "managed"), []byte("old"), 0o600)
	if _, err := environment.service.Add([]string{destination}, app.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := mustWriteFile(t, filepath.Join(environment.home, "replacement"), []byte("new inode"), 0o600)
	if err := os.Rename(replacement, destination); err != nil {
		t.Fatal(err)
	}
	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertStrings(t, result.Updated, []string{"~/managed"})
	assertFileContents(t, repositorySource(t, environment, "~/managed", false), []byte("new inode"))
}

func TestAddUpdatePasswordFailurePreventsAllWrites(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong=%t", wrong), func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			secret := mustWriteFile(t, filepath.Join(environment.home, "z-secret"), []byte("old"), 0o600)
			if _, err := environment.service.Add([]string{secret}, app.AddOptions{Sensitive: true, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
				t.Fatal(err)
			}
			stored := repositorySource(t, environment, "~/z-secret", true)
			before := mustReadFile(t, stored)
			mustWriteFile(t, secret, []byte("changed"), 0o600)
			fresh := mustWriteFile(t, filepath.Join(environment.home, "a-new"), []byte("new"), 0o600)
			options := app.AddOptions{}
			want := app.ErrPasswordRequired
			if wrong {
				options.Password = recordingPasswordProvider("wrong password", nil)
				want = cryptox.ErrInvalidPassword
			}
			result, err := environment.service.Add([]string{fresh, secret}, options)
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			assertStrings(t, result.Added, nil)
			assertStrings(t, result.Updated, nil)
			assertFileContents(t, stored, before)
			assertPathDoesNotExist(t, repositorySource(t, environment, "~/a-new", false))
		})
	}
}

func TestAddUpdateRejectsInvalidExistingSourceBeforePasswordOrWrites(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "directory", "parent symlink"} {
		t.Run(kind, func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			destination := mustWriteFile(t, filepath.Join(environment.home, "nested", "secret"), []byte("old"), 0o600)
			if _, err := environment.service.Add([]string{destination}, app.AddOptions{Sensitive: true, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
				t.Fatal(err)
			}
			stored := repositorySource(t, environment, "~/nested/secret", true)
			outside := mustWriteFile(t, filepath.Join(environment.root, "outside", "secret.enc"), []byte("outside sentinel"), 0o600)
			if err := os.Remove(stored); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, stored); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(stored, 0o700); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				if err := os.Remove(filepath.Dir(stored)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), filepath.Dir(stored)); err != nil {
					t.Fatal(err)
				}
			}
			manifestBefore := mustReadFile(t, filepath.Join(environment.repository, manifest.Filename))
			fresh := mustWriteFile(t, filepath.Join(environment.home, "a-new"), []byte("new"), 0o600)
			var calls []bool
			result, err := environment.service.Add([]string{fresh, destination}, app.AddOptions{Password: recordingPasswordProvider(testPassword, &calls)})
			if err == nil {
				t.Fatal("accepted invalid existing source")
			}
			assertPasswordCalls(t, calls, nil)
			assertStrings(t, result.Added, nil)
			assertStrings(t, result.Updated, nil)
			assertPathDoesNotExist(t, repositorySource(t, environment, "~/a-new", false))
			assertFileContents(t, outside, []byte("outside sentinel"))
			assertFileContents(t, filepath.Join(environment.repository, manifest.Filename), manifestBefore)
		})
	}
}

func TestAddNewSourceNeverOverwritesOrphan(t *testing.T) {
	environment := newTestEnvironment(t, testEnvironmentOptions{})
	destination := mustWriteFile(t, filepath.Join(environment.home, "orphan"), []byte("new snapshot"), 0o600)
	stored := mustWriteFile(t, repositorySource(t, environment, "~/orphan", false), []byte("unreferenced sentinel"), 0o644)
	result, err := environment.service.Add([]string{destination}, app.AddOptions{})
	if !errors.Is(err, repository.ErrSourceExists) {
		t.Fatalf("error = %v", err)
	}
	assertStrings(t, result.Added, nil)
	assertStrings(t, result.Updated, nil)
	assertFileContents(t, stored, []byte("unreferenced sentinel"))
	assertStrings(t, managedPaths(t, environment.service), nil)
}

func TestAddUpdateReplacesStoredHardLinkWithoutModifyingAlias(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		t.Run(fmt.Sprintf("sensitive=%t", sensitive), func(t *testing.T) {
			environment := newTestEnvironment(t, testEnvironmentOptions{})
			destination := mustWriteFile(t, filepath.Join(environment.home, "managed"), []byte("old"), 0o600)
			if _, err := environment.service.Add([]string{destination}, app.AddOptions{Sensitive: sensitive, Password: recordingPasswordProvider(testPassword, nil)}); err != nil {
				t.Fatal(err)
			}
			stored := repositorySource(t, environment, "~/managed", sensitive)
			before := mustReadFile(t, stored)
			alias := filepath.Join(environment.root, "stored-alias")
			if err := os.Link(stored, alias); err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, destination, []byte("updated"), 0o600)
			result, err := environment.service.Add([]string{destination}, app.AddOptions{Password: recordingPasswordProvider(testPassword, nil)})
			if err != nil {
				t.Fatal(err)
			}
			assertStrings(t, result.Updated, []string{"~/managed"})
			assertFileContents(t, alias, before)
			if sameExistingFile(stored, alias) {
				t.Fatal("update retained stored hard link")
			}
		})
	}
}
