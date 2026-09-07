package cli_test

import (
	"strings"
	"testing"
)

func TestCompletionScripts(t *testing.T) {
	tests := []struct {
		shell string
		want  []string
	}{
		{
			shell: "bash",
			want: []string{
				"complete -F _susu_completion susu",
				"init add rm ls list show apply completion help",
				"--sensitive --help -h",
			},
		},
		{
			shell: "zsh",
			want: []string{
				"#compdef susu",
				"'list:alias for ls'",
				"'--sensitive[encrypt new files with the repository master key]'",
				"'1:shell:(bash zsh)'",
				"compdef _susu susu",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.shell, func(t *testing.T) {
			fixture := newCLIFixture(t)
			stdout, stderr, err := fixture.run("completion", test.shell)
			if err != nil {
				t.Fatalf("Run(completion %s) error = %v", test.shell, err)
			}
			if stderr != "" {
				t.Fatalf("Run(completion %s) stderr = %q, want empty output", test.shell, stderr)
			}
			for _, want := range test.want {
				if !strings.Contains(stdout, want) {
					t.Errorf("completion %s does not contain %q:\n%s", test.shell, want, stdout)
				}
			}
			if fixture.passwordCalls != 0 {
				t.Fatalf("Run(completion %s) called the password provider %d times", test.shell, fixture.passwordCalls)
			}
		})
	}
}

func TestCompletionRejectsUnsupportedShell(t *testing.T) {
	fixture := newCLIFixture(t)
	stdout, stderr, err := fixture.run("completion", "powershell")
	if err == nil {
		t.Fatal("Run(completion powershell) succeeded, want an error")
	}
	want := `unsupported completion shell "powershell" (supported: bash, zsh)`
	if err.Error() != want {
		t.Fatalf("Run(completion powershell) error = %q, want %q", err, want)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("Run(completion powershell) output = stdout %q, stderr %q; want both empty", stdout, stderr)
	}
}
