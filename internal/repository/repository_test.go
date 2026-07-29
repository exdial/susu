package repository

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"susu/internal/manifest"
)

func TestInitializeRejectsInvalidPaths(t *testing.T) {
	requireGit(t)

	t.Run("nonexistent path", func(t *testing.T) {
		input := filepath.Join(t.TempDir(), "missing")
		repository, err := Initialize(input)
		if err == nil {
			t.Fatal("Initialize() succeeded for a nonexistent path")
		}
		if repository != nil {
			t.Fatalf("Initialize() repository = %#v after error, want nil", repository)
		}
	})

	t.Run("non-Git directory", func(t *testing.T) {
		input := filepath.Join(t.TempDir(), "not a repository")
		if err := os.Mkdir(input, 0o755); err != nil {
			t.Fatal(err)
		}

		repository, err := Initialize(input)
		if err == nil {
			t.Fatal("Initialize() succeeded for a non-Git directory")
		}
		if repository != nil {
			t.Fatalf("Initialize() repository = %#v after error, want nil", repository)
		}
		if _, statErr := os.Lstat(filepath.Join(input, manifest.Filename)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("Initialize() mutated a non-Git directory: stat error = %v", statErr)
		}
	})

	t.Run("file path", func(t *testing.T) {
		input := filepath.Join(t.TempDir(), "repository-file")
		if err := os.WriteFile(input, []byte("not a directory\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		repository, err := Initialize(input)
		if err == nil {
			t.Fatal("Initialize() succeeded for a file path")
		}
		if repository != nil {
			t.Fatalf("Initialize() repository = %#v after error, want nil", repository)
		}
	})

	t.Run("Git subdirectory", func(t *testing.T) {
		root := initGitRepository(t)
		input := filepath.Join(root, "nested")
		if err := os.Mkdir(input, 0o755); err != nil {
			t.Fatal(err)
		}

		repository, err := Initialize(input)
		if !errors.Is(err, ErrNotGitRoot) {
			t.Fatalf("Initialize() error = %v, want ErrNotGitRoot", err)
		}
		if repository != nil {
			t.Fatalf("Initialize() repository = %#v after error, want nil", repository)
		}
		if _, statErr := os.Lstat(filepath.Join(input, manifest.Filename)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("Initialize() mutated a Git subdirectory: stat error = %v", statErr)
		}
	})
}

func TestInitializeAcceptsExactGitRootAndCreatesFiles(t *testing.T) {
	root := initGitRepository(t)

	repository, err := Initialize(root)
	if err != nil {
		t.Fatalf("Initialize(%q) error = %v", root, err)
	}
	wantRoot := canonicalPath(t, root)
	if repository.Root != wantRoot {
		t.Fatalf("Initialize().Root = %q, want %q", repository.Root, wantRoot)
	}
	if repository.ManifestPath() != filepath.Join(wantRoot, manifest.Filename) {
		t.Fatalf("ManifestPath() = %q", repository.ManifestPath())
	}

	for _, name := range []string{"public", "encrypted"} {
		location := filepath.Join(wantRoot, name)
		info, err := os.Lstat(location)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", location, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%q mode = %v, want a real directory", location, info.Mode())
		}
	}

	info, err := os.Lstat(repository.ManifestPath())
	if err != nil {
		t.Fatalf("Lstat(%q): %v", repository.ManifestPath(), err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%q mode = %v, want a regular file", repository.ManifestPath(), info.Mode())
	}

	gotManifest, err := repository.LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest() error = %v", err)
	}
	if wantManifest := manifest.New(); !reflect.DeepEqual(gotManifest, wantManifest) {
		t.Fatalf("LoadManifest() = %#v, want %#v", gotManifest, wantManifest)
	}
}

func TestInitializeCanonicalizesSymlinkRoot(t *testing.T) {
	root := initGitRepository(t)
	link := filepath.Join(t.TempDir(), "repository-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	repository, err := Initialize(link)
	if err != nil {
		t.Fatalf("Initialize(symlink) error = %v", err)
	}
	wantRoot := canonicalPath(t, root)
	if repository.Root != wantRoot {
		t.Fatalf("Initialize(symlink).Root = %q, want canonical root %q", repository.Root, wantRoot)
	}
	if _, err := os.Stat(filepath.Join(wantRoot, manifest.Filename)); err != nil {
		t.Fatalf("canonical repository was not initialized: %v", err)
	}
}

func TestInitializeIsIdempotent(t *testing.T) {
	root := initGitRepository(t)
	first := mustInitializeRepository(t, root)
	wantManifest := manifest.New()
	wantManifest.Entries = []manifest.Entry{{
		Path:   "~/.zshrc",
		Source: "public/.zshrc",
	}}
	if err := first.SaveManifest(wantManifest); err != nil {
		t.Fatalf("SaveManifest() error = %v", err)
	}
	markerPath := filepath.Join(first.Root, "public", ".zshrc")
	markerContents := []byte("setopt prompt_subst\n")
	if err := os.WriteFile(markerPath, markerContents, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(first.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}

	second, err := Initialize(root)
	if err != nil {
		t.Fatalf("second Initialize() error = %v", err)
	}
	if second.Root != first.Root {
		t.Fatalf("second Initialize().Root = %q, want %q", second.Root, first.Root)
	}
	manifestAfter, err := os.ReadFile(second.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestAfter, manifestBefore) {
		t.Fatalf("second Initialize() changed susu.json:\nbefore: %s\nafter: %s", manifestBefore, manifestAfter)
	}
	gotManifest, err := second.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotManifest, wantManifest) {
		t.Fatalf("manifest after second Initialize() = %#v, want %#v", gotManifest, wantManifest)
	}
	gotMarker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotMarker, markerContents) {
		t.Fatalf("stored source after second Initialize() = %q, want %q", gotMarker, markerContents)
	}
}

func TestOpenReportsMissingConfiguredRepository(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "configured-repository")

	repository, err := Open(missing)
	if !errors.Is(err, ErrRepositoryMissing) {
		t.Fatalf("Open() error = %v, want ErrRepositoryMissing", err)
	}
	if repository != nil {
		t.Fatalf("Open() repository = %#v after error, want nil", repository)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("Open() error = %q, want missing path context", err)
	}
}

func TestOpenReportsMissingManifest(t *testing.T) {
	root := initGitRepository(t)
	repository := mustInitializeRepository(t, root)
	if err := os.Remove(repository.ManifestPath()); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(root)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Open() error = %v, want ErrNotInitialized", err)
	}
	if opened != nil {
		t.Fatalf("Open() repository = %#v after error, want nil", opened)
	}
	if !strings.Contains(err.Error(), manifest.Filename) || !strings.Contains(err.Error(), "susu init") {
		t.Fatalf("Open() error is not actionable: %v", err)
	}
}

func TestOpenReportsMissingStorageDirectories(t *testing.T) {
	for _, storage := range []string{"public", "encrypted"} {
		t.Run(storage, func(t *testing.T) {
			root := initGitRepository(t)
			repository := mustInitializeRepository(t, root)
			if err := os.Remove(filepath.Join(repository.Root, storage)); err != nil {
				t.Fatal(err)
			}

			opened, err := Open(root)
			if err == nil {
				t.Fatalf("Open() succeeded with missing %s storage", storage)
			}
			if opened != nil {
				t.Fatalf("Open() repository = %#v after error, want nil", opened)
			}
			for _, detail := range []string{"storage directory", storage, "missing", "susu init"} {
				if !strings.Contains(err.Error(), detail) {
					t.Fatalf("Open() error = %q, want %q context", err, detail)
				}
			}
		})
	}
}

func TestSourcePathRejectsTraversal(t *testing.T) {
	repository := mustInitializeRepository(t, initGitRepository(t))
	invalid := []struct {
		name   string
		source string
	}{
		{"empty", ""},
		{"storage root", "public"},
		{"outside root", "../outside"},
		{"parent traversal", "public/../outside"},
		{"nested traversal", "public/nested/../../outside"},
		{"absolute", "/public/file"},
		{"wrong storage", "private/file"},
		{"prefix confusion", "publicity/file"},
		{"duplicate separator", "public//file"},
		{"dot component", "public/./file"},
		{"encrypted traversal", "encrypted/../file"},
		{"NUL byte", "public/nul\x00file"},
	}

	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			got, err := repository.SourcePath(test.source)
			if !errors.Is(err, ErrUnsafeSource) {
				t.Fatalf("SourcePath(%q) error = %v, want ErrUnsafeSource", test.source, err)
			}
			if got != "" {
				t.Fatalf("SourcePath(%q) = %q after error, want empty path", test.source, got)
			}
		})
	}

	got, err := repository.SourcePath("encrypted/nested/file.enc")
	if err != nil {
		t.Fatalf("SourcePath(valid source) error = %v", err)
	}
	want := filepath.Join(repository.Root, "encrypted", "nested", "file.enc")
	if got != want {
		t.Fatalf("SourcePath(valid source) = %q, want %q", got, want)
	}
}

func TestSourcesRejectSymlinks(t *testing.T) {
	repository := mustInitializeRepository(t, initGitRepository(t))
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	outsideSecret := filepath.Join(outside, "secret")
	if err := os.WriteFile(outsideSecret, []byte("do not follow\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	parentLink := filepath.Join(repository.Root, "public", "linked-directory")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	leafLink := filepath.Join(repository.Root, "public", "linked-file")
	if err := os.Symlink(outsideSecret, leafLink); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	t.Run("existing source through symlink parent", func(t *testing.T) {
		got, err := repository.ExistingSource("public/linked-directory/secret")
		if !errors.Is(err, ErrUnsafeSource) {
			t.Fatalf("ExistingSource() error = %v, want ErrUnsafeSource", err)
		}
		if got != "" {
			t.Fatalf("ExistingSource() = %q after error, want empty path", got)
		}
	})

	t.Run("new source through symlink parent", func(t *testing.T) {
		got, err := repository.NewSource("public/linked-directory/new", 0o700)
		if !errors.Is(err, ErrUnsafeSource) {
			t.Fatalf("NewSource() error = %v, want ErrUnsafeSource", err)
		}
		if got != "" {
			t.Fatalf("NewSource() = %q after error, want empty path", got)
		}
		if _, statErr := os.Lstat(filepath.Join(outside, "new")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("NewSource() escaped through a symlink: stat error = %v", statErr)
		}
	})

	t.Run("existing symlink leaf", func(t *testing.T) {
		got, err := repository.ExistingSource("public/linked-file")
		if !errors.Is(err, ErrUnsafeSource) {
			t.Fatalf("ExistingSource() error = %v, want ErrUnsafeSource", err)
		}
		if got != "" {
			t.Fatalf("ExistingSource() = %q after error, want empty path", got)
		}
	})

	t.Run("new symlink leaf", func(t *testing.T) {
		got, err := repository.NewSource("public/linked-file", 0o700)
		if !errors.Is(err, ErrSourceExists) {
			t.Fatalf("NewSource() error = %v, want ErrSourceExists", err)
		}
		if got != "" {
			t.Fatalf("NewSource() = %q after error, want empty path", got)
		}
	})
}

func requireGit(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git executable not found")
	}
	return git
}

func initGitRepository(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repository with spaces")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(requireGit(t), "init", "--quiet", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init %q: %v\n%s", root, err, output)
	}
	return root
}

func mustInitializeRepository(t *testing.T, root string) *Repository {
	t.Helper()
	repository, err := Initialize(root)
	if err != nil {
		t.Fatalf("Initialize(%q) error = %v", root, err)
	}
	return repository
}

func canonicalPath(t *testing.T, input string) string {
	t.Helper()
	absolute, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(canonical)
}
