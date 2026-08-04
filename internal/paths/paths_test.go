package paths

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePrefersXDGConfigHomeBeforeHome(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home with spaces")
	xdg := filepath.Join(home, "settings")
	resolver := mustResolverAt(t, home, xdg, home)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"home root", home, "~"},
		{"home child", filepath.Join(home, ".zshrc"), "~/.zshrc"},
		{"xdg root", xdg, "${XDG_CONFIG_HOME}"},
		{"xdg child", filepath.Join(xdg, "tool name", "config.toml"), "${XDG_CONFIG_HOME}/tool name/config.toml"},
		{"expanded home", "~/notes/file.txt", "~/notes/file.txt"},
		{"expanded xdg", "${XDG_CONFIG_HOME}/app/config.json", "${XDG_CONFIG_HOME}/app/config.json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolver.Normalize(test.input)
			if err != nil {
				t.Fatalf("Normalize(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("Normalize(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeUsesXDGConfigFallback(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	resolver := mustResolverAt(t, home, "", temp)

	logical, err := resolver.Normalize(filepath.Join(home, ".config", "starship.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if logical != "${XDG_CONFIG_HOME}/starship.toml" {
		t.Fatalf("Normalize() = %q", logical)
	}

	resolved, err := resolver.Resolve(logical)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "starship.toml")
	if resolved != want {
		t.Fatalf("Resolve() = %q, want %q", resolved, want)
	}
}

func TestNormalizeSupportsRelativeNonexistentPaths(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	workingDirectory := filepath.Join(home, "work area")
	resolver := mustResolverAt(t, home, "", workingDirectory)

	logical, err := resolver.Normalize(filepath.Join("..", "future files", "a file.txt"))
	if err != nil {
		t.Fatalf("Normalize() required a nonexistent path to exist: %v", err)
	}
	if logical != "~/future files/a file.txt" {
		t.Fatalf("Normalize() = %q", logical)
	}
}

func TestNormalizeRejectsPathsOutsideRootsWithoutPrefixConfusion(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	resolver := mustResolverAt(t, home, "", home)

	for _, input := range []string{
		filepath.Join(temp, "home-other", "file"),
		filepath.Join(temp, "outside", "file"),
		"~/../../outside",
	} {
		_, err := resolver.Normalize(input)
		if !errors.Is(err, ErrUnrepresentable) {
			t.Errorf("Normalize(%q) error = %v, want ErrUnrepresentable", input, err)
		}
	}
}

func TestNormalizeRejectsMalformedExpansionPrefixes(t *testing.T) {
	temp := t.TempDir()
	resolver := mustResolverAt(t, filepath.Join(temp, "home"), "", temp)

	for _, input := range []string{"~someone/file", "${XDG_CONFIG_HOME}file"} {
		_, err := resolver.Normalize(input)
		if !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Normalize(%q) error = %v, want ErrInvalidPath", input, err)
		}
	}
}

func TestResolveLogicalPaths(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home with spaces")
	xdg := filepath.Join(temp, "config with spaces")
	resolver := mustResolverAt(t, home, xdg, temp)

	tests := []struct {
		logical string
		want    string
	}{
		{"~", home},
		{"~/file name", filepath.Join(home, "file name")},
		{"~/one/two", filepath.Join(home, "one", "two")},
		{"${XDG_CONFIG_HOME}", xdg},
		{"${XDG_CONFIG_HOME}/app name/config", filepath.Join(xdg, "app name", "config")},
	}

	for _, test := range tests {
		got, err := resolver.Resolve(test.logical)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", test.logical, err)
		}
		if got != test.want {
			t.Errorf("Resolve(%q) = %q, want %q", test.logical, got, test.want)
		}
	}
}

func TestResolveRejectsMalformedLogicalPaths(t *testing.T) {
	temp := t.TempDir()
	resolver := mustResolverAt(t, filepath.Join(temp, "home"), filepath.Join(temp, "config"), temp)

	invalid := []string{
		"",
		"relative/path",
		filepath.Join(temp, "absolute"),
		"~someone/file",
		"~/",
		"~/../outside",
		"~/./file",
		"~/one//two",
		"~/one/",
		"~\\file",
		"${XDG_CONFIG_HOME}/",
		"${XDG_CONFIG_HOME}/../outside",
		"${XDG_CONFIG_HOME}/./file",
		"${XDG_CONFIG_HOME}//file",
		"${XDG_CONFIG_HOME}file",
		"${XDG_CONFIG_HOME_VAR}/file",
		"~/nul\x00file",
	}

	for _, logical := range invalid {
		t.Run(logical, func(t *testing.T) {
			_, err := resolver.Resolve(logical)
			if !errors.Is(err, ErrInvalidLogicalPath) {
				t.Fatalf("Resolve(%q) error = %v, want ErrInvalidLogicalPath", logical, err)
			}
		})
	}
}

func TestResolverRejectsInvalidRoots(t *testing.T) {
	temp := t.TempDir()

	tests := []struct {
		home string
		xdg  string
		cwd  string
	}{
		{"", "", temp},
		{"relative-home", "", temp},
		{temp, "relative-config", temp},
		{temp, "", "relative-working-directory"},
	}

	for _, test := range tests {
		if _, err := NewResolverAt(test.home, test.xdg, test.cwd); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewResolverAt(%q, %q, %q) error = %v, want ErrInvalidPath", test.home, test.xdg, test.cwd, err)
		}
	}
}

func TestNewResolverFromEnv(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	xdg := filepath.Join(temp, "xdg config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	resolver, err := NewResolverFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolver.Normalize(filepath.Join(xdg, "app", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "${XDG_CONFIG_HOME}/app/config" {
		t.Fatalf("Normalize() = %q", got)
	}
}

func TestNewResolverFromEnvRequiresHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	_, err := NewResolverFromEnv()
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("NewResolverFromEnv() error = %v, want ErrInvalidPath", err)
	}
}

func TestNormalizeAndResolveRoundTrip(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	xdg := filepath.Join(temp, "xdg")
	resolver := mustResolverAt(t, home, xdg, temp)

	for _, filesystemPath := range []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, "directory with spaces", "file"),
		filepath.Join(xdg, "nested", "config.toml"),
	} {
		logical, err := resolver.Normalize(filesystemPath)
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := resolver.Resolve(logical)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != filepath.Clean(filesystemPath) {
			t.Errorf("round trip for %q returned %q through %q", filesystemPath, resolved, logical)
		}
	}
}

func TestComparisonKeyDarwinAliases(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{"ASCII case", "/Users/Alice/Library/Preferences", "/users/alice/library/preferences"},
		{"NFC and NFD", "/Users/example/caf\u00e9", "/Users/example/cafe\u0301"},
		{"case and normalization", "/Users/example/\u00c9COLE", "/users/EXAMPLE/e\u0301cole"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := ComparisonKey(test.first, "darwin")
			if err != nil {
				t.Fatalf("ComparisonKey(%q, darwin): %v", test.first, err)
			}
			second, err := ComparisonKey(test.second, "darwin")
			if err != nil {
				t.Fatalf("ComparisonKey(%q, darwin): %v", test.second, err)
			}
			if first != second {
				t.Fatalf("ComparisonKey() returned distinct Darwin aliases %q and %q", first, second)
			}
		})
	}
}

func TestComparisonKeyLinuxPreservesComponentSpelling(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{"ASCII case", "/home/example/Config", "/home/example/config"},
		{"NFC and NFD", "/home/example/caf\u00e9", "/home/example/cafe\u0301"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := ComparisonKey(test.first, "linux")
			if err != nil {
				t.Fatalf("ComparisonKey(%q, linux): %v", test.first, err)
			}
			second, err := ComparisonKey(test.second, "linux")
			if err != nil {
				t.Fatalf("ComparisonKey(%q, linux): %v", test.second, err)
			}
			if first != test.first || second != test.second {
				t.Fatalf("ComparisonKey() changed Linux spelling: got %q and %q", first, second)
			}
			if first == second {
				t.Fatalf("ComparisonKey() conflated distinct Linux paths %q and %q", first, second)
			}
		})
	}
}

func TestComparisonKeyCleansAbsolutePaths(t *testing.T) {
	tests := []struct {
		platform string
		want     string
	}{
		{"darwin", "/users/example/config/file"},
		{"linux", "/Users/example/Config/file"},
	}

	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			got, err := ComparisonKey("/Users/example/one/../Config/./file", test.platform)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ComparisonKey() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestComparisonKeyPreservesComponentBoundaries(t *testing.T) {
	first, err := ComparisonKey("/A/BC", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ComparisonKey("/AB/C", "darwin")
	if err != nil {
		t.Fatal(err)
	}

	if first != "/a/bc" || second != "/ab/c" {
		t.Fatalf("ComparisonKey() returned %q and %q", first, second)
	}
	if first == second {
		t.Fatalf("ComparisonKey() did not preserve component boundaries")
	}
}

func TestComparisonKeyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		platform string
	}{
		{"empty path", "", "linux"},
		{"relative path", "relative/path", "linux"},
		{"NUL", "/tmp/nul\x00path", "darwin"},
		{"malformed UTF-8 on Darwin", "/tmp/invalid-\xff", "darwin"},
		{"empty platform", "/tmp/file", ""},
		{"unsupported platform", "/tmp/file", "windows"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ComparisonKey(test.filename, test.platform)
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("ComparisonKey(%q, %q) error = %v, want ErrInvalidPath", test.filename, test.platform, err)
			}
			if got != "" {
				t.Fatalf("ComparisonKey(%q, %q) = %q on error, want empty key", test.filename, test.platform, got)
			}
		})
	}
}

func TestComparisonKeyLinuxPreservesNonUTF8Bytes(t *testing.T) {
	filename := "/tmp/invalid-\xff"
	got, err := ComparisonKey(filename, "linux")
	if err != nil {
		t.Fatalf("ComparisonKey(non-UTF-8 Linux path): %v", err)
	}
	if got != filename {
		t.Fatalf("ComparisonKey(non-UTF-8 Linux path) = %q, want %q", got, filename)
	}
}

func mustResolverAt(t *testing.T, home, xdgConfigHome, workingDirectory string) *Resolver {
	t.Helper()
	resolver, err := NewResolverAt(home, xdgConfigHome, workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestMain(m *testing.M) {
	// Tests inject every HOME/XDG value and never use these as filesystem roots.
	os.Exit(m.Run())
}
