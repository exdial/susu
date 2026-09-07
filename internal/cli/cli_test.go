package cli_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"susu/internal/app"
	"susu/internal/cli"
	"susu/internal/paths"
	"susu/internal/state"
)

func TestHelp(t *testing.T) {
	tests := []struct {
		name       string
		arguments  []string
		fromStdout bool
		want       []string
		notWant    []string
	}{
		{
			name:       "root",
			arguments:  []string{"--help"},
			fromStdout: true,
			want: []string{
				"susu manages portable public and encrypted dotfiles.",
				"Usage:\n  susu <command> [arguments]",
				"Commands:\n  init        initialize susu in an existing Git repository\n  add         start managing files or directories\n  rm          stop managing files\n  ls          list managed files\n  show        print a stored file\n  apply       apply managed files to this machine\n  completion  generate shell completion script",
				"Run `susu <command> --help` for command-specific help.",
				"Git synchronization stays explicit.",
				"Use Git normally to commit, pull, and push changes.",
			},
			notWant: []string{
				"init <repository>",
				"add [options] <path...>",
				"rm <path...>",
				"show <path>",
				"alias: list",
			},
		},
		{
			name:      "init",
			arguments: []string{"init", "--help"},
			want: []string{
				"Initialize susu in an existing Git repository.",
				"Usage:\n  susu init <repository>",
				"Examples:",
				"susu init ~/src/dotfiles",
			},
		},
		{
			name:      "add",
			arguments: []string{"add", "--help"},
			want: []string{
				"Add files or directories to susu.",
				"Usage:\n  susu add [options] <path...>",
				"--sensitive",
				"Examples:",
				"susu add ~/.config/nvim",
			},
		},
		{
			name:      "rm",
			arguments: []string{"rm", "--help"},
			want: []string{
				"Stop managing files.",
				"Files are removed from susu management but remain on the filesystem.",
				"Usage:\n  susu rm <path...>",
				"Examples:",
			},
		},
		{
			name:      "ls",
			arguments: []string{"ls", "--help"},
			want: []string{
				"List managed files.",
				"Usage:\n  susu ls",
				"annotations",
				"Alias: susu list",
			},
		},
		{
			name:      "list alias",
			arguments: []string{"list", "--help"},
			want: []string{
				"List managed files.",
				"Usage:\n  susu ls",
				"Alias: susu list",
			},
		},
		{
			name:      "show",
			arguments: []string{"show", "--help"},
			want: []string{
				"Print a stored file.",
				"Usage:\n  susu show <path>",
				"No destination file is modified.",
				"Examples:",
			},
		},
		{
			name:      "apply",
			arguments: []string{"apply", "--help"},
			want: []string{
				"Apply managed files to this machine.",
				"Usage:\n  susu apply",
				"replace their destinations atomically",
				"local state and repository destinations are rejected",
			},
		},
		{
			name:      "completion",
			arguments: []string{"completion", "--help"},
			want: []string{
				"Generate a shell completion script.",
				"Usage:\n  susu completion <shell>",
				"bash",
				"zsh",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCLIFixture(t)
			stdout, stderr, err := fixture.run(test.arguments...)
			if err != nil {
				t.Fatalf("Run(%q): %v", test.arguments, err)
			}

			got, unexpected := stderr, stdout
			if test.fromStdout {
				got, unexpected = stdout, stderr
			}
			if unexpected != "" {
				t.Fatalf("Run(%q) wrote to the unexpected output stream: %q", test.arguments, unexpected)
			}
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("Run(%q) help does not contain %q:\n%s", test.arguments, want, got)
				}
			}
			for _, notWant := range test.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("Run(%q) help unexpectedly contains %q:\n%s", test.arguments, notWant, got)
				}
			}
			if fixture.passwordCalls != 0 {
				t.Fatalf("Run(%q) called the password provider %d times", test.arguments, fixture.passwordCalls)
			}
		})
	}
}

func TestEarlyHelpDoesNotRequireHome(t *testing.T) {
	t.Setenv("HOME", "")
	for _, arguments := range [][]string{{"--help"}, {"add", "--help"}, {"ls", "--help"}, {"list", "--help"}, {"completion", "--help"}} {
		var output bytes.Buffer
		if !cli.PrintHelpIfRequested(arguments, &output) {
			t.Fatalf("PrintHelpIfRequested(%q) = false", arguments)
		}
		if !strings.Contains(output.String(), "Usage:") {
			t.Fatalf("PrintHelpIfRequested(%q) output = %q", arguments, output.String())
		}
	}
}

func TestDefaultOverviewBeforeInitialization(t *testing.T) {
	fixture := newCLIFixture(t)
	stdout, stderr, err := fixture.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := `susu manages portable public and encrypted dotfiles.

Get started:
  susu init <repository>
  susu add <path...>
  susu apply

Run ` + "`susu --help`" + ` to see all commands.
`
	if stdout != want {
		t.Fatalf("Run() stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("Run() stderr = %q, want empty output", stderr)
	}
	if strings.Contains(stdout, "command is required") || strings.Contains(stdout, "Commands:") {
		t.Fatalf("Run() displayed error or full help instead of onboarding:\n%s", stdout)
	}
}

func TestDefaultOverviewForInitializedRepository(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is unavailable")
	}

	fixture := newCLIFixture(t)
	isolateEnvironment(t, fixture)
	repositoryPath := filepath.Join(fixture.home, ".dotfiles")
	command := exec.Command(gitPath, "init", "--quiet", repositoryPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	_ = runSuccessfully(t, fixture, "init", repositoryPath)

	if got := runSuccessfully(t, fixture); !strings.Contains(got, "Repository: ~/.dotfiles\nManaged: 0 files") {
		t.Fatalf("empty initialized overview = %q", got)
	}

	first := filepath.Join(fixture.home, ".first")
	second := filepath.Join(fixture.home, ".second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("managed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = runSuccessfully(t, fixture, "add", first, second)

	stdout, stderr, err := fixture.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, want := range []string{
		"susu manages portable public and encrypted dotfiles.",
		"Repository: ~/.dotfiles",
		"Managed: 2 files",
		"Common commands:",
		"  susu add <path...>",
		"  susu ls",
		"  susu apply",
		"Run `susu --help` to see all commands.",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("Run() overview does not contain %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Get started:") {
		t.Errorf("initialized overview contains onboarding:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("Run() stderr = %q, want empty output", stderr)
	}
}

func TestUnknownCommandRemainsAnError(t *testing.T) {
	fixture := newCLIFixture(t)
	stdout, stderr, err := fixture.run("does-not-exist")
	if err == nil {
		t.Fatal("Run(unknown command) succeeded, want an error")
	}
	wantError := `unknown command "does-not-exist"; run 'susu --help'`
	if err.Error() != wantError {
		t.Fatalf("Run(unknown command) error = %q, want %q", err, wantError)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("Run(unknown command) output = stdout %q, stderr %q; want both empty", stdout, stderr)
	}
}

func TestArgumentCardinality(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		arguments []string
		wantError string
	}{
		{
			name:      "init requires a repository",
			command:   "init",
			arguments: []string{"init"},
			wantError: "init requires exactly one repository path",
		},
		{
			name:      "init rejects multiple repositories",
			command:   "init",
			arguments: []string{"init", "one", "two"},
			wantError: "init requires exactly one repository path",
		},
		{
			name:      "add requires a path",
			command:   "add",
			arguments: []string{"add"},
			wantError: "add requires at least one path",
		},
		{
			name:      "rm requires a path",
			command:   "rm",
			arguments: []string{"rm"},
			wantError: "rm requires at least one path",
		},
		{
			name:      "ls rejects arguments",
			command:   "ls",
			arguments: []string{"ls", "extra"},
			wantError: "ls does not accept arguments",
		},
		{
			name:      "list alias rejects arguments",
			command:   "ls",
			arguments: []string{"list", "extra"},
			wantError: "ls does not accept arguments",
		},
		{
			name:      "show requires a path",
			command:   "show",
			arguments: []string{"show"},
			wantError: "show requires exactly one managed path",
		},
		{
			name:      "show rejects multiple paths",
			command:   "show",
			arguments: []string{"show", "one", "two"},
			wantError: "show requires exactly one managed path",
		},
		{
			name:      "apply rejects arguments",
			command:   "apply",
			arguments: []string{"apply", "extra"},
			wantError: "apply does not accept arguments",
		},
		{
			name:      "completion requires a shell",
			command:   "completion",
			arguments: []string{"completion"},
			wantError: "completion requires exactly one shell",
		},
		{
			name:      "completion rejects multiple shells",
			command:   "completion",
			arguments: []string{"completion", "bash", "zsh"},
			wantError: "completion requires exactly one shell",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCLIFixture(t)
			stdout, stderr, err := fixture.run(test.arguments...)
			if err == nil {
				t.Fatalf("Run(%q) succeeded, want error %q", test.arguments, test.wantError)
			}
			if err.Error() != test.wantError {
				t.Fatalf("Run(%q) error = %q, want %q", test.arguments, err, test.wantError)
			}
			if stdout != "" {
				t.Fatalf("Run(%q) stdout = %q, want empty output", test.arguments, stdout)
			}
			wantUsage := "Usage:\n  susu " + test.command
			if !strings.Contains(stderr, wantUsage) {
				t.Fatalf("Run(%q) stderr does not contain %q:\n%s", test.arguments, wantUsage, stderr)
			}
			if fixture.passwordCalls != 0 {
				t.Fatalf("Run(%q) called the password provider %d times", test.arguments, fixture.passwordCalls)
			}
		})
	}
}

func TestPublicCLIWorkflow(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is unavailable")
	}

	fixture := newCLIFixture(t)
	isolateEnvironment(t, fixture)

	repositoryPath := filepath.Join(fixture.root, "Git repository with spaces")
	command := exec.Command(gitPath, "init", "--quiet", repositoryPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}

	stdout := runSuccessfully(t, fixture, "init", repositoryPath)
	boundRepository, err := fixture.store.Load()
	if err != nil {
		t.Fatalf("load repository binding after init: %v", err)
	}
	if want := "initialized " + boundRepository + "\n"; stdout != want {
		t.Fatalf("init stdout = %q, want %q", stdout, want)
	}

	destination := filepath.Join(fixture.home, "dot files with spaces", "editor config.txt")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte("public CLI workflow contents\n")
	if err := os.WriteFile(destination, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	logical := "~/dot files with spaces/editor config.txt"

	if got := runSuccessfully(t, fixture, "add", destination); got != "added "+logical+"\n" {
		t.Fatalf("add stdout = %q, want %q", got, "added "+logical+"\n")
	}
	if got := runSuccessfully(t, fixture, "ls"); got != logical+"\n" {
		t.Fatalf("ls stdout = %q, want %q", got, logical+"\n")
	}
	if got := runSuccessfully(t, fixture, "list"); got != logical+"\n" {
		t.Fatalf("list alias stdout = %q, want %q", got, logical+"\n")
	}
	if got := runSuccessfully(t, fixture, "show", logical); got != string(contents) {
		t.Fatalf("show stdout = %q, want %q", got, contents)
	}
	if got := runSuccessfully(t, fixture, "rm", destination); got != "removed "+logical+"\n" {
		t.Fatalf("rm stdout = %q, want %q", got, "removed "+logical+"\n")
	}
	if got := runSuccessfully(t, fixture, "ls"); got != "" {
		t.Fatalf("ls after rm stdout = %q, want empty output", got)
	}

	remaining, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read destination after rm: %v", err)
	}
	if !bytes.Equal(remaining, contents) {
		t.Fatalf("destination after rm = %q, want %q", remaining, contents)
	}

	xdgDestination := filepath.Join(fixture.xdgConfigHome, "argocd", "config.yaml")
	xdgSettingsDestination := filepath.Join(fixture.xdgConfigHome, "argocd", "settings.yaml")
	for path, contents := range map[string][]byte{
		xdgDestination:         []byte("current-context: production\n"),
		xdgSettingsDestination: []byte("theme: dark\n"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := runSuccessfully(t, fixture, "add", xdgDestination); got != "added ~/.config/argocd/config.yaml\n" {
		t.Fatalf("XDG add stdout = %q", got)
	}
	if got := runSuccessfully(t, fixture, "add", xdgDestination); got != "already managed ~/.config/argocd/config.yaml\n" {
		t.Fatalf("duplicate XDG add stdout = %q", got)
	}
	if got := runSuccessfully(t, fixture, "add", xdgSettingsDestination); got != "added ~/.config/argocd/settings.yaml\n" {
		t.Fatalf("XDG settings add stdout = %q", got)
	}
	wantList := "~/.config/argocd/config.yaml\n~/.config/argocd/settings.yaml\n"
	if got := runSuccessfully(t, fixture, "ls"); got != wantList {
		t.Fatalf("XDG ls stdout = %q, want %q", got, wantList)
	}
	if got := runSuccessfully(t, fixture, "apply"); got != "applied ~/.config/argocd/config.yaml\napplied ~/.config/argocd/settings.yaml\n" {
		t.Fatalf("XDG apply stdout = %q", got)
	}

	manifestContents, err := os.ReadFile(filepath.Join(boundRepository, "susu.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestContents, []byte(`${XDG_CONFIG_HOME}/argocd/config.yaml`)) {
		t.Fatalf("susu.json does not retain the XDG logical path:\n%s", manifestContents)
	}

	if got := runSuccessfully(t, fixture, "rm", xdgDestination, xdgSettingsDestination); got != "removed ~/.config/argocd/config.yaml\nremoved ~/.config/argocd/settings.yaml\n" {
		t.Fatalf("XDG rm stdout = %q", got)
	}
	stdout, stderr, err := fixture.run("rm", xdgDestination)
	if !errors.Is(err, app.ErrNotManaged) {
		t.Fatalf("rm missing XDG path error = %v, want app.ErrNotManaged", err)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("rm missing XDG path output = stdout %q, stderr %q; want both empty", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "~/.config/argocd/config.yaml") || strings.Contains(err.Error(), paths.XDGConfigHomePrefix) {
		t.Fatalf("rm missing XDG path error is not user-facing: %v", err)
	}

	if fixture.passwordCalls != 0 {
		t.Fatalf("public workflow called the password provider %d times", fixture.passwordCalls)
	}
}

type cliFixture struct {
	runner        *cli.CLI
	stdout        *bytes.Buffer
	stderr        *bytes.Buffer
	store         *state.Store
	root          string
	home          string
	xdgConfigHome string
	xdgStateHome  string
	passwordCalls int
}

func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home with spaces")
	xdgConfigHome := filepath.Join(root, "XDG config with spaces")
	xdgStateHome := filepath.Join(root, "XDG state with spaces")
	for _, directory := range []string{home, xdgConfigHome, xdgStateHome} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	resolver, err := paths.NewResolverAt(home, xdgConfigHome, home)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(home, xdgStateHome)
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.New(store, resolver, "linux")
	if err != nil {
		t.Fatal(err)
	}

	fixture := &cliFixture{
		stdout:        new(bytes.Buffer),
		stderr:        new(bytes.Buffer),
		store:         store,
		root:          root,
		home:          home,
		xdgConfigHome: xdgConfigHome,
		xdgStateHome:  xdgStateHome,
	}
	fixture.runner, err = cli.New(service, resolver, fixture.stdout, fixture.stderr, func(bool) ([]byte, error) {
		fixture.passwordCalls++
		return []byte("test-only password"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *cliFixture) run(arguments ...string) (stdout, stderr string, err error) {
	fixture.stdout.Reset()
	fixture.stderr.Reset()
	err = fixture.runner.Run(arguments)
	return fixture.stdout.String(), fixture.stderr.String(), err
}

func runSuccessfully(t *testing.T, fixture *cliFixture, arguments ...string) string {
	t.Helper()
	stdout, stderr, err := fixture.run(arguments...)
	if err != nil {
		t.Fatalf("Run(%q): %v", arguments, err)
	}
	if stderr != "" {
		t.Fatalf("Run(%q) stderr = %q, want empty output", arguments, stderr)
	}
	return stdout
}

func isolateEnvironment(t *testing.T, fixture *cliFixture) {
	t.Helper()
	t.Setenv("HOME", fixture.home)
	t.Setenv("XDG_CONFIG_HOME", fixture.xdgConfigHome)
	t.Setenv("XDG_STATE_HOME", fixture.xdgStateHome)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(fixture.root, "XDG cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(fixture.root, "XDG data"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(fixture.root, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}
