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

type internalApplyEnvironment struct {
	service    *Service
	home       string
	xdg        string
	repository string
}

func TestApplyRechecksAliasesAfterSourcePreflight(t *testing.T) {
	environment := newInternalApplyEnvironment(t)
	entries := writeInternalApplyAliasFixture(t, environment)
	homeDestination := filepath.Join(environment.home, "shared")
	if err := os.WriteFile(homeDestination, []byte("local value must remain\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hooks := applyHooks{afterSourcePreflight: func() error {
		if err := os.RemoveAll(environment.xdg); err != nil {
			return err
		}
		return os.Symlink(environment.home, environment.xdg)
	}}
	result, err := environment.service.applyWithHooks(nil, hooks)
	if !errors.Is(err, ErrDestinationConflict) {
		t.Fatalf("applyWithHooks() error = %v, want ErrDestinationConflict", err)
	}
	if len(result.Applied) != 0 || len(result.Skipped) != 0 {
		t.Fatalf("applyWithHooks() result = %+v, want no applied or skipped entries", result)
	}
	contents, err := os.ReadFile(homeDestination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "local value must remain\n" {
		t.Fatalf("home destination contents = %q", contents)
	}
	for _, entry := range entries {
		if _, err := os.Stat(filepath.Join(environment.repository, filepath.FromSlash(entry.Source))); err != nil {
			t.Fatalf("repository source %q changed: %v", entry.Source, err)
		}
	}
}

func TestApplyRechecksAliasesBeforeEachReplacement(t *testing.T) {
	environment := newInternalApplyEnvironment(t)
	entries := writeInternalApplyAliasFixture(t, environment)
	homeDestination := filepath.Join(environment.home, "shared")
	if err := os.WriteFile(homeDestination, []byte("local value must remain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	xdgBackup := environment.xdg + "-before-alias"

	hooks := applyHooks{beforeDestinationReplace: func(logical string) error {
		if logical != "~/shared" {
			return nil
		}
		if err := os.Rename(environment.xdg, xdgBackup); err != nil {
			return err
		}
		return os.Symlink(environment.home, environment.xdg)
	}}
	result, err := environment.service.applyWithHooks(nil, hooks)
	if !errors.Is(err, ErrDestinationConflict) {
		t.Fatalf("applyWithHooks() error = %v, want ErrDestinationConflict", err)
	}
	if len(result.Applied) != 1 || result.Applied[0] != entries[0].Path || len(result.Skipped) != 0 {
		t.Fatalf("applyWithHooks() result = %+v, want only %q applied", result, entries[0].Path)
	}
	firstContents, err := os.ReadFile(filepath.Join(xdgBackup, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstContents) != "XDG snapshot\n" {
		t.Fatalf("first applied destination contents = %q", firstContents)
	}
	homeContents, err := os.ReadFile(homeDestination)
	if err != nil {
		t.Fatal(err)
	}
	if string(homeContents) != "local value must remain\n" {
		t.Fatalf("home destination contents = %q", homeContents)
	}
}

func newInternalApplyEnvironment(t *testing.T) internalApplyEnvironment {
	t.Helper()
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}

	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdg")
	repositoryPath := filepath.Join(root, "repository")
	stateHome := filepath.Join(root, "state")
	for _, directory := range []string{home, xdg, repositoryPath, stateHome} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(gitExecutable, "init", "--quiet", repositoryPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}

	resolver, err := paths.NewResolverAt(home, xdg, home)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(home, stateHome)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, resolver, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := service.Init(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	return internalApplyEnvironment{service: service, home: home, xdg: xdg, repository: repositoryRoot}
}

func writeInternalApplyAliasFixture(t *testing.T, environment internalApplyEnvironment) []manifest.Entry {
	t.Helper()
	entries := []manifest.Entry{
		{Path: "${XDG_CONFIG_HOME}/shared", Source: "public/.config/shared"},
		{Path: "~/shared", Source: "public/shared"},
	}
	current := manifest.New()
	current.Entries = entries
	if err := manifest.Save(filepath.Join(environment.repository, manifest.Filename), current); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{
		entries[0].Source: []byte("XDG snapshot\n"),
		entries[1].Source: []byte("HOME snapshot\n"),
	}
	for source, value := range contents {
		filename := filepath.Join(environment.repository, filepath.FromSlash(source))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, value, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return entries
}
