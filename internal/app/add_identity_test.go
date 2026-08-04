package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"susu/internal/manifest"
	"susu/internal/paths"
	"susu/internal/state"
)

func TestAddRollsBackSourcesWhenCandidateBecomesAliasBeforeRead(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(first, second string) error
	}{
		{
			name: "later candidate changes identity",
			mutate: func(first, second string) error {
				if err := os.Remove(second); err != nil {
					return err
				}
				return os.Link(first, second)
			},
		},
		{
			name: "earlier candidate changes to later identity",
			mutate: func(first, second string) error {
				if err := os.Remove(first); err != nil {
					return err
				}
				return os.Link(second, first)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gitExecutable, err := exec.LookPath("git")
			if err != nil {
				t.Skipf("git unavailable: %v", err)
			}

			root := t.TempDir()
			home := filepath.Join(root, "home")
			repositoryPath := filepath.Join(root, "repository")
			stateHome := filepath.Join(root, "state")
			for _, directory := range []string{home, repositoryPath, stateHome} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command(gitExecutable, "init", "--quiet", repositoryPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, output)
			}

			resolver, err := paths.NewResolverAt(home, "", home)
			if err != nil {
				t.Fatal(err)
			}
			store, err := state.NewStore(home, stateHome)
			if err != nil {
				t.Fatal(err)
			}
			service, err := New(store, resolver, "linux")
			if err != nil {
				t.Fatal(err)
			}
			repositoryRoot, err := service.Init(repositoryPath)
			if err != nil {
				t.Fatal(err)
			}

			first := filepath.Join(home, "a")
			second := filepath.Join(home, "b")
			if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(second, []byte("second\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			hooks := addHooks{beforeCandidateRead: func(logical string) error {
				if logical != "~/b" {
					return nil
				}
				return test.mutate(first, second)
			}}
			result, err := service.addWithHooks([]string{second, first}, AddOptions{}, hooks)
			if !errors.Is(err, ErrDestinationConflict) {
				t.Fatalf("addWithHooks() error = %v, want ErrDestinationConflict", err)
			}
			if len(result.Added) != 0 || len(result.AlreadyManaged) != 0 {
				t.Fatalf("addWithHooks() result = %+v, want empty result", result)
			}

			current, err := manifest.Load(filepath.Join(repositoryRoot, manifest.Filename))
			if err != nil {
				t.Fatal(err)
			}
			if len(current.Entries) != 0 {
				t.Fatalf("manifest entries after rollback = %+v, want none", current.Entries)
			}
			for _, logical := range []string{"~/a", "~/b"} {
				source, err := manifest.SourceFor(logical, false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(repositoryRoot, filepath.FromSlash(source))); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("repository source for %q exists or returned unexpected error: %v", logical, err)
				}
			}
		})
	}
}
