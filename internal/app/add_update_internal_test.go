package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/exdial/susu/internal/manifest"
	"github.com/exdial/susu/internal/safefs"
)

func writeAddUpdateFile(t *testing.T, filename, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAddUpdateContents(t *testing.T, filename, want string) {
	t.Helper()
	got, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%q = %q, want %q", filename, got, want)
	}
}

func assertAddUpdateAbsent(t *testing.T, filename string) {
	t.Helper()
	if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%q: %v, want absent", filename, err)
	}
}

func TestAddUpdateRechecksExistingSourceBeforeReading(t *testing.T) {
	for _, checkpoint := range []string{"password", "pre-read"} {
		t.Run(checkpoint, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			z := filepath.Join(environment.home, "z")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, z, "old z")
			if _, err := environment.service.Add([]string{a, z}, AddOptions{Sensitive: true, Password: addUpdatePassword}); err != nil {
				t.Fatal(err)
			}
			storedA := filepath.Join(environment.repository, "encrypted", "a.enc")
			storedZ := filepath.Join(environment.repository, "encrypted", "z.enc")
			beforeA, err := os.ReadFile(storedA)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(environment.home, "outside")
			writeAddUpdateFile(t, outside, "unmanaged sentinel")
			mutate := func() error {
				if err := os.Remove(storedZ); err != nil {
					return err
				}
				return os.Symlink(outside, storedZ)
			}
			options := AddOptions{Password: addUpdatePassword}
			hooks := addHooks{}
			if checkpoint == "password" {
				options.Password = func(create bool) ([]byte, error) {
					if err := mutate(); err != nil {
						return nil, err
					}
					return addUpdatePassword(create)
				}
			} else {
				hooks.beforeCandidateRead = func(logical string) error {
					if logical == "~/z" {
						return mutate()
					}
					return nil
				}
			}
			result, err := environment.service.addWithHooks([]string{a, z}, options, hooks)
			if err == nil {
				t.Fatal("accepted substituted repository source")
			}
			want := []string(nil)
			if checkpoint == "pre-read" {
				want = []string{"~/a"}
			} else {
				assertAddUpdateContents(t, storedA, string(beforeA))
			}
			if len(result.Added) != 0 || !reflect.DeepEqual(result.Updated, want) {
				t.Fatalf("result = %+v, want updates %v", result, want)
			}
			assertAddUpdateContents(t, outside, "unmanaged sentinel")
		})
	}
}

func TestAddUpdatePreReadProtectedSubstitutionPreservesEarlierUpdate(t *testing.T) {
	for _, protected := range []string{"state", "repository"} {
		t.Run(protected, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			z := filepath.Join(environment.home, "z")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, z, "old z")
			if _, err := environment.service.Add([]string{a, z}, AddOptions{}); err != nil {
				t.Fatal(err)
			}
			writeAddUpdateFile(t, a, "new a")
			want := ErrProtectedLocalState
			if protected == "repository" {
				want = ErrProtectedRepository
			}
			hooks := addHooks{beforeCandidateRead: func(logical string) error {
				if logical != "~/z" {
					return nil
				}
				if err := os.Remove(z); err != nil {
					return err
				}
				if protected == "state" {
					return os.Link(environment.service.state.Path(), z)
				}
				return os.Symlink(environment.repository, z)
			}}
			result, err := environment.service.addWithHooks([]string{a, z}, AddOptions{}, hooks)
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if !reflect.DeepEqual(result.Updated, []string{"~/a"}) {
				t.Fatalf("result = %+v", result)
			}
			assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "a"), "new a")
			assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "z"), "old z")
		})
	}
}

func addUpdatePassword(bool) ([]byte, error) { return []byte("add update regression password"), nil }

func TestAddUpdateAtomicFailuresReportOnlyCommittedUpdatesAndRollbackNewSources(t *testing.T) {
	injected := errors.New("injected update failure")
	for _, test := range []struct {
		name      string
		committed bool
		hooks     atomicReplaceHooks
	}{
		{name: "file sync", hooks: atomicReplaceHooks{syncFile: func(*os.File) error { return injected }}},
		{name: "close", hooks: atomicReplaceHooks{closeFile: func(*os.File) error { return injected }}},
		{name: "rename", hooks: atomicReplaceHooks{rename: func(*safefs.Directory, string, string) error { return injected }}},
		{name: "post rename", committed: true, hooks: atomicReplaceHooks{afterRename: func(string) error { return injected }}},
		{name: "directory sync", committed: true, hooks: atomicReplaceHooks{syncDirectory: func(*safefs.Directory) error { return injected }}},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			b := filepath.Join(environment.home, "b")
			z := filepath.Join(environment.home, "z")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, z, "old z")
			if _, err := environment.service.Add([]string{a, z}, AddOptions{}); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			writeAddUpdateFile(t, a, "new a")
			writeAddUpdateFile(t, b, "new b")
			writeAddUpdateFile(t, z, "new z")
			public := filepath.Join(environment.repository, "public")
			writeAddUpdateFile(t, filepath.Join(public, ".susu-apply-user-backup.tmp"), "unmanaged sentinel")
			hooks := addHooks{updateAtomicHooks: func(logical string) atomicReplaceHooks {
				if logical == "~/z" {
					return test.hooks
				}
				return atomicReplaceHooks{}
			}}
			result, err := environment.service.addWithHooks([]string{z, b, a}, AddOptions{}, hooks)
			if !errors.Is(err, injected) {
				t.Fatalf("error = %v", err)
			}
			wantUpdated := []string{"~/a"}
			wantZ := "old z"
			if test.committed {
				wantUpdated = append(wantUpdated, "~/z")
				wantZ = "new z"
			}
			if !reflect.DeepEqual(result.Updated, wantUpdated) || len(result.Added) != 0 || len(result.AlreadyManaged) != 0 {
				t.Fatalf("result = %+v, want updates %v only", result, wantUpdated)
			}
			assertAddUpdateContents(t, filepath.Join(public, "a"), "new a")
			assertAddUpdateContents(t, filepath.Join(public, "z"), wantZ)
			assertAddUpdateAbsent(t, filepath.Join(public, "b"))
			assertAddUpdateContents(t, manifestPath, string(manifestBefore))
			assertAddUpdateContents(t, filepath.Join(public, ".susu-apply-user-backup.tmp"), "unmanaged sentinel")
			entries, err := os.ReadDir(public)
			if err != nil || len(entries) != 3 {
				t.Fatalf("unexpected staging residue: %v, %v", entries, err)
			}
		})
	}
}

func TestAddMixedSnapshotsRetainSourcesWhenManifestCommittedWithError(t *testing.T) {
	environment := newInternalApplyEnvironment(t)
	existing := filepath.Join(environment.home, "existing")
	fresh := filepath.Join(environment.home, "new")
	writeAddUpdateFile(t, existing, "old snapshot")
	if _, err := environment.service.Add([]string{existing}, AddOptions{}); err != nil {
		t.Fatal(err)
	}
	writeAddUpdateFile(t, existing, "updated snapshot")
	writeAddUpdateFile(t, fresh, "new snapshot")

	manifestPath := filepath.Join(environment.repository, manifest.Filename)
	saveCalls := 0
	hooks := addHooks{saveManifest: func(updated manifest.Manifest) error {
		saveCalls++
		if err := manifest.Save(manifestPath, updated); err != nil {
			return err
		}
		return fmt.Errorf("injected post-rename directory sync failure: %w", manifest.ErrCommitted)
	}}
	result, err := environment.service.addWithHooks([]string{fresh, existing}, AddOptions{}, hooks)
	if !errors.Is(err, manifest.ErrCommitted) {
		t.Fatalf("error = %v, want ErrCommitted", err)
	}
	if saveCalls != 1 {
		t.Fatalf("manifest save calls = %d, want 1", saveCalls)
	}
	if !reflect.DeepEqual(result.Added, []string{"~/new"}) ||
		!reflect.DeepEqual(result.Updated, []string{"~/existing"}) || len(result.AlreadyManaged) != 0 {
		t.Fatalf("result = %+v, want committed addition and update", result)
	}
	current, err := manifest.Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	wantEntries := []manifest.Entry{
		{Path: "~/existing", Source: "public/existing"},
		{Path: "~/new", Source: "public/new"},
	}
	if !reflect.DeepEqual(current.Entries, wantEntries) {
		t.Fatalf("persisted entries = %+v, want %+v", current.Entries, wantEntries)
	}
	assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "existing"), "updated snapshot")
	assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "new"), "new snapshot")
}

func TestAddUpdateLateFailuresKeepUpdatesAndRollbackOnlyNewSources(t *testing.T) {
	for _, failure := range []string{"pre-read", "identity before read", "identity before manifest", "manifest save", "new orphan"} {
		t.Run(failure, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			b := filepath.Join(environment.home, "b")
			z := filepath.Join(environment.home, "z")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, z, "old z")
			if _, err := environment.service.Add([]string{a, z}, AddOptions{}); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			writeAddUpdateFile(t, a, "new a")
			writeAddUpdateFile(t, b, "new b")
			writeAddUpdateFile(t, z, "new z")
			public := filepath.Join(environment.repository, "public")
			injected := errors.New("late pre-read failure")
			hooks := addHooks{}
			wantUpdated := []string{"~/a"}
			switch failure {
			case "pre-read":
				hooks.beforeCandidateRead = func(logical string) error {
					if logical == "~/z" {
						return injected
					}
					return nil
				}
			case "identity before read":
				hooks.beforeCandidateRead = func(logical string) error {
					if logical != "~/z" {
						return nil
					}
					if err := os.Remove(a); err != nil {
						return err
					}
					return os.Link(z, a)
				}
			case "identity before manifest":
				wantUpdated = append(wantUpdated, "~/z")
				hooks.updateAtomicHooks = func(logical string) atomicReplaceHooks {
					if logical != "~/z" {
						return atomicReplaceHooks{}
					}
					return atomicReplaceHooks{afterRename: func(string) error {
						if err := os.Remove(a); err != nil {
							return err
						}
						return os.Link(z, a)
					}}
				}
			case "manifest save":
				wantUpdated = append(wantUpdated, "~/z")
				hooks.updateAtomicHooks = func(logical string) atomicReplaceHooks {
					if logical != "~/z" {
						return atomicReplaceHooks{}
					}
					return atomicReplaceHooks{afterRename: func(string) error {
						if err := os.Rename(manifestPath, manifestPath+".before"); err != nil {
							return err
						}
						return os.Mkdir(manifestPath, 0o700)
					}}
				}
			case "new orphan":
				writeAddUpdateFile(t, filepath.Join(public, "b"), "orphan sentinel")
			}
			result, err := environment.service.addWithHooks([]string{a, b, z}, AddOptions{}, hooks)
			if err == nil {
				t.Fatal("expected late failure")
			}
			if failure == "pre-read" && !errors.Is(err, injected) {
				t.Fatalf("error = %v", err)
			}
			if (failure == "identity before read" || failure == "identity before manifest") && !errors.Is(err, ErrDestinationConflict) {
				t.Fatalf("error = %v", err)
			}
			if len(result.Added) != 0 || !reflect.DeepEqual(result.Updated, wantUpdated) {
				t.Fatalf("result = %+v, want updates %v only", result, wantUpdated)
			}
			assertAddUpdateContents(t, filepath.Join(public, "a"), "new a")
			wantZ := "old z"
			if len(wantUpdated) == 2 {
				wantZ = "new z"
			}
			assertAddUpdateContents(t, filepath.Join(public, "z"), wantZ)
			if failure == "new orphan" {
				assertAddUpdateContents(t, filepath.Join(public, "b"), "orphan sentinel")
			} else {
				assertAddUpdateAbsent(t, filepath.Join(public, "b"))
			}
			if failure == "manifest save" {
				manifestPath += ".before"
			}
			assertAddUpdateContents(t, manifestPath, string(manifestBefore))
		})
	}
}

func TestAddRejectsMultipleManagedPhysicalOwnersIncludingAliasOnly(t *testing.T) {
	for _, requested := range []string{"a", "b", "alias"} {
		t.Run(requested, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			b := filepath.Join(environment.home, "b")
			alias := filepath.Join(environment.home, "alias")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, b, "old b")
			if _, err := environment.service.Add([]string{a, b}, AddOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(b); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(a, b); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(a, alias); err != nil {
				t.Fatal(err)
			}
			calls := 0
			result, err := environment.service.Add([]string{filepath.Join(environment.home, requested)}, AddOptions{Sensitive: true, Password: func(bool) ([]byte, error) { calls++; return nil, errors.New("unexpected password") }})
			if !errors.Is(err, ErrDestinationConflict) || calls != 0 {
				t.Fatalf("error = %v, calls = %d", err, calls)
			}
			if len(result.Added)+len(result.Updated)+len(result.AlreadyManaged) != 0 {
				t.Fatalf("result = %+v", result)
			}
			assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "a"), "old a")
			assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "b"), "old b")
		})
	}
}

func TestAddUpdatesExactOwnerAndSkipsDifferentLogicalAlias(t *testing.T) {
	environment := newInternalApplyEnvironment(t)
	owner := filepath.Join(environment.home, "z-owner")
	alias := filepath.Join(environment.home, "a-alias")
	writeAddUpdateFile(t, owner, "old")
	if _, err := environment.service.Add([]string{owner}, AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(owner, alias); err != nil {
		t.Fatal(err)
	}
	writeAddUpdateFile(t, owner, "new")
	result, err := environment.service.Add([]string{alias, owner}, AddOptions{Sensitive: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Updated, []string{"~/z-owner"}) || !reflect.DeepEqual(result.AlreadyManaged, []string{"~/a-alias"}) || len(result.Added) != 0 {
		t.Fatalf("result = %+v", result)
	}
	assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "z-owner"), "new")
	assertAddUpdateAbsent(t, filepath.Join(environment.repository, "encrypted", "a-alias.enc"))
}

func TestAddIdentityPreflightAndReadScanPastExactOwner(t *testing.T) {
	environment := newInternalApplyEnvironment(t)
	a := filepath.Join(environment.home, "a")
	b := filepath.Join(environment.home, "b")
	writeAddUpdateFile(t, a, "a")
	writeAddUpdateFile(t, b, "b")
	if _, err := environment.service.Add([]string{a, b}, AddOptions{}); err != nil {
		t.Fatal(err)
	}
	repo, current, release, err := environment.service.openLocked()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	boundary, err := environment.service.loadControlBoundary(repo)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := environment.service.collectCandidates([]string{a}, boundary)
	if err != nil {
		t.Fatal(err)
	}
	if err := environment.service.preflightCandidates(candidates, current.Entries, boundary); err != nil {
		t.Fatalf("self preflight: %v", err)
	}
	if _, _, err := environment.service.readCandidate(candidates[0], current.Entries, boundary); err != nil {
		t.Fatalf("self read: %v", err)
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := environment.service.preflightCandidates(candidates, current.Entries, boundary); !errors.Is(err, ErrDestinationConflict) {
			t.Fatalf("preflight = %v", err)
		}
		if _, _, err := environment.service.readCandidate(candidates[0], current.Entries, boundary); !errors.Is(err, ErrDestinationConflict) {
			t.Fatalf("read = %v", err)
		}
		current.Entries[0], current.Entries[1] = current.Entries[1], current.Entries[0]
	}
}

func TestAddProspectiveManifestConflictsFailWithoutWrites(t *testing.T) {
	for _, test := range []struct {
		name           string
		sourceConflict bool
		sensitive      bool
		existingCrypto bool
		wantCalls      []bool
	}{
		{name: "public logical ancestor"},
		{name: "first sensitive logical ancestor", sensitive: true, wantCalls: []bool{true}},
		{name: "first sensitive source ancestor", sourceConflict: true, sensitive: true, wantCalls: []bool{true}},
		{name: "existing crypto logical ancestor", sensitive: true, existingCrypto: true},
		{name: "existing crypto source ancestor", sourceConflict: true, sensitive: true, existingCrypto: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			if test.existingCrypto {
				seed := filepath.Join(environment.home, "seed")
				writeAddUpdateFile(t, seed, "existing secret")
				if _, err := environment.service.Add([]string{seed}, AddOptions{Sensitive: true, Password: addUpdatePassword}); err != nil {
					t.Fatal(err)
				}
			}
			var inputs []string
			if !test.sourceConflict {
				writeAddUpdateFile(t, a, "old a")
				if _, err := environment.service.Add([]string{a}, AddOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(a); err != nil {
					t.Fatal(err)
				}
				child := filepath.Join(a, "child")
				writeAddUpdateFile(t, child, "child")
				inputs = []string{child}
			} else {
				writeAddUpdateFile(t, a, "a")
				child := filepath.Join(environment.home, "a.enc", "child")
				writeAddUpdateFile(t, child, "child")
				inputs = []string{a, child}
			}
			manifestPath := filepath.Join(environment.repository, manifest.Filename)
			manifestBefore, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var calls []bool
			result, err := environment.service.Add(inputs, AddOptions{Sensitive: test.sensitive, Password: func(create bool) ([]byte, error) {
				calls = append(calls, create)
				return addUpdatePassword(create)
			}})
			if !errors.Is(err, manifest.ErrInvalidManifest) || !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("error = %v, calls = %v, want %v", err, calls, test.wantCalls)
			}
			if len(result.Added)+len(result.Updated)+len(result.AlreadyManaged) != 0 {
				t.Fatalf("result = %+v", result)
			}
			assertAddUpdateContents(t, manifestPath, string(manifestBefore))
			entries, err := os.ReadDir(filepath.Join(environment.repository, "encrypted"))
			wantEntries := 0
			if test.existingCrypto {
				wantEntries = 1
			}
			if err != nil || len(entries) != wantEntries {
				t.Fatalf("encrypted sources = %v, error = %v", entries, err)
			}
			if !test.sourceConflict {
				assertAddUpdateContents(t, filepath.Join(environment.repository, "public", "a"), "old a")
			}
		})
	}
}

func TestAddUpdateRechecksIdentityAndProtectionAfterPassword(t *testing.T) {
	for _, mutation := range []string{"other owner", "candidate inode", "local state", "repository"} {
		t.Run(mutation, func(t *testing.T) {
			environment := newInternalApplyEnvironment(t)
			a := filepath.Join(environment.home, "a")
			b := filepath.Join(environment.home, "b")
			writeAddUpdateFile(t, a, "old a")
			writeAddUpdateFile(t, b, "old b")
			if _, err := environment.service.Add([]string{a, b}, AddOptions{Sensitive: true, Password: addUpdatePassword}); err != nil {
				t.Fatal(err)
			}
			stored := filepath.Join(environment.repository, "encrypted", "a.enc")
			before, err := os.ReadFile(stored)
			if err != nil {
				t.Fatal(err)
			}
			writeAddUpdateFile(t, a, "new a")
			calls := 0
			want := ErrDestinationConflict
			if mutation == "local state" {
				want = ErrProtectedLocalState
			}
			if mutation == "repository" {
				want = ErrProtectedRepository
			}
			provider := func(create bool) ([]byte, error) {
				calls++
				if create {
					return nil, fmt.Errorf("update requested creation")
				}
				switch mutation {
				case "other owner":
					if err := os.Remove(b); err != nil {
						return nil, err
					}
					if err := os.Link(a, b); err != nil {
						return nil, err
					}
				case "candidate inode":
					if err := os.Remove(a); err != nil {
						return nil, err
					}
					if err := os.Link(b, a); err != nil {
						return nil, err
					}
				case "local state":
					if err := os.Remove(a); err != nil {
						return nil, err
					}
					if err := os.Link(environment.service.state.Path(), a); err != nil {
						return nil, err
					}
				case "repository":
					if err := os.Remove(a); err != nil {
						return nil, err
					}
					if err := os.Symlink(environment.repository, a); err != nil {
						return nil, err
					}
				}
				return addUpdatePassword(false)
			}
			result, err := environment.service.Add([]string{a}, AddOptions{Password: provider})
			if !errors.Is(err, want) || calls != 1 {
				t.Fatalf("error = %v, want %v; calls = %d", err, want, calls)
			}
			if len(result.Added)+len(result.Updated) != 0 {
				t.Fatalf("result = %+v", result)
			}
			assertAddUpdateContents(t, stored, string(before))
		})
	}
}
