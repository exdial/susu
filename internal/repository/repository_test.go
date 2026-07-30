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

func TestGitCommonDirectoryForNormalRepository(t *testing.T) {
	root := initGitRepository(t)
	repository := mustInitializeRepository(t, root)
	want := canonicalPath(t, filepath.Join(root, ".git"))
	if got := repository.GitCommonDirectory(); got != want {
		t.Fatalf("Initialize().GitCommonDirectory() = %q, want %q", got, want)
	}
	assertRegularFile(t, filepath.Join(want, "susu.lock"))

	opened, err := Open(repository.Root)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", repository.Root, err)
	}
	if got := opened.GitCommonDirectory(); got != want {
		t.Fatalf("Open().GitCommonDirectory() = %q, want %q", got, want)
	}
}

func TestGitRootEndingInSpace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repository ending in space ")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, "init", "--quiet", root)

	repository := mustInitializeRepository(t, root)
	wantRoot := canonicalPath(t, root)
	if !strings.HasSuffix(wantRoot, " ") {
		t.Fatalf("canonical fixture root %q does not end in a space", wantRoot)
	}
	if repository.Root != wantRoot {
		t.Fatalf("Initialize().Root = %q, want trailing-space root %q", repository.Root, wantRoot)
	}
	wantCommonDirectory := canonicalPath(t, filepath.Join(root, ".git"))
	if got := repository.GitCommonDirectory(); got != wantCommonDirectory {
		t.Fatalf("Initialize().GitCommonDirectory() = %q, want %q", got, wantCommonDirectory)
	}
	assertRegularFile(t, filepath.Join(wantCommonDirectory, "susu.lock"))

	opened, err := Open(repository.Root)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", repository.Root, err)
	}
	if opened.Root != wantRoot {
		t.Fatalf("Open().Root = %q, want trailing-space root %q", opened.Root, wantRoot)
	}
	if got := opened.GitCommonDirectory(); got != wantCommonDirectory {
		t.Fatalf("Open().GitCommonDirectory() = %q, want %q", got, wantCommonDirectory)
	}
}

func TestGitCommonDirectoryEndingInSpace(t *testing.T) {
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	commonDirectory := filepath.Join(root, "separate Git directory ")
	runGit(t, "init", "--quiet", "--separate-git-dir", commonDirectory, worktree)
	assertRegularFile(t, filepath.Join(worktree, ".git"))

	repository := mustInitializeRepository(t, worktree)
	want := canonicalPath(t, commonDirectory)
	if !strings.HasSuffix(want, " ") {
		t.Fatalf("canonical fixture common directory %q does not end in a space", want)
	}
	if got := repository.GitCommonDirectory(); got != want {
		t.Fatalf("Initialize().GitCommonDirectory() = %q, want trailing-space directory %q", got, want)
	}
	assertRegularFile(t, filepath.Join(want, "susu.lock"))

	opened, err := Open(repository.Root)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", repository.Root, err)
	}
	if got := opened.GitCommonDirectory(); got != want {
		t.Fatalf("Open().GitCommonDirectory() = %q, want trailing-space directory %q", got, want)
	}
}

func TestParseGitPathRecord(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{name: "newline preserves trailing space", output: "/tmp/repository \n", want: "/tmp/repository "},
		{name: "carriage return is preserved as path data", output: "/tmp/repository \r\n", want: "/tmp/repository \r"},
		{name: "empty output", output: "", wantErr: true},
		{name: "empty record", output: "\n", wantErr: true},
		{name: "carriage-return-only path", output: "\r\n", want: "\r"},
		{name: "missing terminator", output: "/tmp/repository ", wantErr: true},
		{name: "multiple records", output: "/tmp/one\n/tmp/two\n", wantErr: true},
		{name: "embedded carriage return is preserved", output: "/tmp/one\r/tmp/two\n", want: "/tmp/one\r/tmp/two"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseGitPathRecord(test.output)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseGitPathRecord(%q) = %q, want error", test.output, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGitPathRecord(%q) error = %v", test.output, err)
			}
			if got != test.want {
				t.Fatalf("parseGitPathRecord(%q) = %q, want %q", test.output, got, test.want)
			}
		})
	}
}

func TestGitCommonDirectoryForLinkedWorktree(t *testing.T) {
	primaryRoot, linkedRoot := initLinkedGitWorktree(t)
	linkedGitFile := filepath.Join(linkedRoot, ".git")
	assertRegularFile(t, linkedGitFile)

	primaryRepository := mustInitializeRepository(t, primaryRoot)
	linkedRepository := mustInitializeRepository(t, linkedRoot)
	openedLinked, err := Open(linkedRepository.Root)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", linkedRepository.Root, err)
	}

	want := canonicalPath(t, filepath.Join(primaryRoot, ".git"))
	for name, repository := range map[string]*Repository{
		"primary Initialize": primaryRepository,
		"linked Initialize":  linkedRepository,
		"linked Open":        openedLinked,
	} {
		if got := repository.GitCommonDirectory(); got != want {
			t.Fatalf("%s GitCommonDirectory() = %q, want shared directory %q", name, got, want)
		}
	}
	assertRegularFile(t, filepath.Join(want, "susu.lock"))

	linkedGitDirectory, err := parseGitPathRecord(string(runGit(t, "-C", linkedRoot, "rev-parse", "--git-dir")))
	if err != nil {
		t.Fatalf("parse linked worktree Git directory: %v", err)
	}
	if !filepath.IsAbs(linkedGitDirectory) {
		linkedGitDirectory = filepath.Join(linkedRoot, linkedGitDirectory)
	}
	linkedGitDirectory = canonicalPath(t, linkedGitDirectory)
	if linkedGitDirectory == want {
		t.Fatalf("linked worktree Git directory = common directory %q; fixture is not linked", want)
	}
	if _, err := os.Lstat(filepath.Join(linkedGitDirectory, "susu.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("linked per-worktree Git directory contains susu.lock: %v", err)
	}
}

func TestLockReusesRetainedGitCommonDirectory(t *testing.T) {
	initialized := mustInitializeRepository(t, initGitRepository(t))
	repository, err := Open(initialized.Root)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", initialized.Root, err)
	}
	commonDirectory := repository.GitCommonDirectory()
	lockPath := filepath.Join(commonDirectory, "susu.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove existing repository lock: %v", err)
	}

	emptyPath := filepath.Join(t.TempDir(), "empty-path")
	if err := os.Mkdir(emptyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", emptyPath)
	if git, err := exec.LookPath("git"); err == nil {
		t.Fatalf("git remains available at %q after isolating PATH", git)
	}

	release, err := repository.Lock()
	if err != nil {
		t.Fatalf("Lock() with git unavailable error = %v", err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Errorf("release repository lock: %v", err)
		}
	})
	assertRegularFile(t, lockPath)
	if got := repository.GitCommonDirectory(); got != commonDirectory {
		t.Fatalf("GitCommonDirectory() after Lock() = %q, want retained %q", got, commonDirectory)
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

func TestOpenRejectsNoncanonicalConfiguredRepositoryPath(t *testing.T) {
	repository := mustInitializeRepository(t, initGitRepository(t))
	link := filepath.Join(t.TempDir(), "repository-link")
	if err := os.Symlink(repository.Root, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	opened, err := Open(link)
	if !errors.Is(err, ErrRepositoryMissing) {
		t.Fatalf("Open(symlink) error = %v, want ErrRepositoryMissing", err)
	}
	if opened != nil {
		t.Fatalf("Open(symlink) repository = %#v after error, want nil", opened)
	}
	if !strings.Contains(err.Error(), "now resolves") {
		t.Fatalf("Open(symlink) error is not actionable: %v", err)
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

	opened, err := Open(repository.Root)
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

			opened, err := Open(repository.Root)
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
	runGit(t, "init", "--quiet", root)
	return root
}

func initLinkedGitWorktree(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "global-gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	primary := filepath.Join(root, "primary repository with spaces")
	linked := filepath.Join(root, "linked worktree with spaces")
	runGit(t, "init", "--quiet", primary)
	runGit(
		t,
		"-C", primary,
		"-c", "user.name=susu-tests",
		"-c", "user.email=susu-tests@example.invalid",
		"-c", "commit.gpgSign=false",
		"commit", "--quiet", "--allow-empty", "-m", "linked worktree fixture",
	)
	runGit(t, "-C", primary, "worktree", "add", "--detach", linked, "HEAD")
	return primary, linked
}

func runGit(t *testing.T, arguments ...string) []byte {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(requireGit(t), arguments...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		t.Fatalf("git %s: %s", strings.Join(arguments, " "), detail)
	}
	return stdout.Bytes()
}

func assertRegularFile(t *testing.T, filename string) {
	t.Helper()
	info, err := os.Lstat(filename)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", filename, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%q mode = %v, want a regular file", filename, info.Mode())
	}
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
