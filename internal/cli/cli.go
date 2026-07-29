// Package cli parses commands and connects them to the testable app service.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"

	"susu/internal/app"
	"susu/internal/cryptox"
	"susu/internal/paths"
	"susu/internal/state"
)

// CLI is one command runner with explicit output and password dependencies.
type CLI struct {
	service  *app.Service
	stdout   io.Writer
	stderr   io.Writer
	password app.PasswordProvider
}

// New constructs a command runner. A nil password provider is valid for
// commands that never touch sensitive entries.
func New(service *app.Service, stdout, stderr io.Writer, password app.PasswordProvider) (*CLI, error) {
	if service == nil {
		return nil, errors.New("app service is nil")
	}
	if stdout == nil || stderr == nil {
		return nil, errors.New("CLI output writer is nil")
	}
	return &CLI{service: service, stdout: stdout, stderr: stderr, password: password}, nil
}

// NewFromEnv builds the production command runner from HOME/XDG state and the
// current Go platform.
func NewFromEnv(stdout, stderr io.Writer) (*CLI, error) {
	resolver, err := paths.NewResolverFromEnv()
	if err != nil {
		return nil, fmt.Errorf("configure paths: %w", err)
	}
	store, err := state.NewStoreFromEnv()
	if err != nil {
		return nil, fmt.Errorf("configure local state: %w", err)
	}
	service, err := app.New(store, resolver, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	return New(service, stdout, stderr, readTTYPassword)
}

// PrintHelpIfRequested writes help without constructing environment-dependent
// repository services. This keeps --help available even when HOME is unset or
// local state is malformed.
func PrintHelpIfRequested(arguments []string, output io.Writer) bool {
	if output == nil {
		return false
	}
	rootHelp := len(arguments) == 1 && (arguments[0] == "help" || arguments[0] == "-h" || arguments[0] == "--help")
	commandHelp := len(arguments) == 2 && (arguments[1] == "-h" || arguments[1] == "--help")
	if !rootHelp && !commandHelp {
		return false
	}
	helper := &CLI{stdout: output, stderr: output}
	if rootHelp {
		helper.printRootHelp(output)
		return true
	}
	switch arguments[0] {
	case "init", "add", "rm", "list", "show", "apply":
		_ = helper.Run(arguments)
		return true
	default:
		return false
	}
}

// Run executes one argv slice without terminating the process.
func (c *CLI) Run(arguments []string) error {
	if len(arguments) == 0 {
		c.printRootHelp(c.stderr)
		return errors.New("command is required")
	}
	switch arguments[0] {
	case "help", "-h", "--help":
		c.printRootHelp(c.stdout)
		return nil
	case "init":
		return c.runInit(arguments[1:])
	case "add":
		return c.runAdd(arguments[1:])
	case "rm":
		return c.runRemove(arguments[1:])
	case "list":
		return c.runList(arguments[1:])
	case "show":
		return c.runShow(arguments[1:])
	case "apply":
		return c.runApply(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q; run 'susu --help'", arguments[0])
	}
}

func (c *CLI) runInit(arguments []string) error {
	flags := c.flagSet("init", `Usage: susu init <repository>

Validate an existing Git repository root, initialize susu.json and storage
folders if needed, and bind this machine to the repository.

Example:
  susu init ~/src/dotfiles
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return errors.New("init requires exactly one repository path")
	}
	root, err := c.service.Init(flags.Arg(0))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.stdout, "initialized %s\n", root)
	return err
}

func (c *CLI) runAdd(arguments []string) error {
	flags := c.flagSet("add", `Usage: susu add [options] <path...>

Start managing one or more files. Real directories are traversed recursively
and stored as individual file entries; symlinks are never followed. Existing
entries are skipped and never silently synchronized or overwritten.

Options:
  --sensitive                 encrypt new files with the repository master key
  --exclude-platform <value>  skip on apply for darwin or linux; repeatable

Examples:
  susu add ~/.zshrc ~/.gitconfig
  susu add --exclude-platform linux ~/.hammerspoon/init.lua
  susu add --sensitive ~/.kube/config ~/.ssh/config
`)
	var sensitive bool
	var exclusions stringListFlag
	flags.BoolVar(&sensitive, "sensitive", false, "encrypt new files as sensitive repository entries")
	flags.Var(&exclusions, "exclude-platform", "platform to exclude during apply: darwin or linux (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return errors.New("add requires at least one path")
	}
	result, err := c.service.Add(flags.Args(), app.AddOptions{
		Sensitive:        sensitive,
		ExcludePlatforms: exclusions,
		Password:         c.password,
	})
	for _, logical := range result.Added {
		if _, err := fmt.Fprintf(c.stdout, "added %s\n", logical); err != nil {
			return err
		}
	}
	for _, logical := range result.AlreadyManaged {
		if _, writeErr := fmt.Fprintf(c.stdout, "already managed %s\n", logical); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (c *CLI) runRemove(arguments []string) error {
	flags := c.flagSet("rm", `Usage: susu rm <path...>

Stop managing one or more exact file paths. This removes susu.json entries and
repository copies, but never removes destination files from HOME.

Example:
  susu rm ~/.zshrc ~/.gitconfig
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return errors.New("rm requires at least one path")
	}
	result, err := c.service.Remove(flags.Args())
	for _, logical := range result.Removed {
		if _, writeErr := fmt.Fprintf(c.stdout, "removed %s\n", logical); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (c *CLI) runList(arguments []string) error {
	flags := c.flagSet("list", `Usage: susu list

List portable destination paths currently managed by the active repository.
Sensitive and platform-excluded entries receive concise annotations.
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return errors.New("list does not accept arguments")
	}
	entries, err := c.service.List()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintln(c.stdout, app.FormatEntry(entry)); err != nil {
			return err
		}
	}
	return nil
}

func (c *CLI) runShow(arguments []string) error {
	flags := c.flagSet("show", `Usage: susu show <path>

Write one stored repository version to stdout. Sensitive content is decrypted
in memory after one no-echo TTY password prompt; no destination is modified.

Examples:
  susu show ~/.gitconfig
  susu show ~/.kube/config
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return errors.New("show requires exactly one managed path")
	}
	return c.service.Show(flags.Arg(0), c.stdout, c.password)
}

func (c *CLI) runApply(arguments []string) error {
	flags := c.flagSet("apply", `Usage: susu apply

Restore repository versions to confined local filesystem destinations. Sources
are preflighted, each file is replaced atomically, current-platform exclusions
are skipped, and sensitive entries share one password prompt per invocation.
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return errors.New("apply does not accept arguments")
	}
	result, err := c.service.Apply(c.password)
	for _, logical := range result.Applied {
		if _, err := fmt.Fprintf(c.stdout, "applied %s\n", logical); err != nil {
			return err
		}
	}
	for _, logical := range result.Skipped {
		if _, writeErr := fmt.Fprintf(c.stdout, "skipped %s [excluded on current platform]\n", logical); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (c *CLI) flagSet(command, usage string) *flag.FlagSet {
	flags := flag.NewFlagSet("susu "+command, flag.ContinueOnError)
	flags.SetOutput(c.stderr)
	flags.Usage = func() { _, _ = io.WriteString(c.stderr, usage) }
	return flags
}

func (c *CLI) printRootHelp(output io.Writer) {
	_, _ = io.WriteString(output, `susu manages portable public and encrypted dotfiles in a Git repository.

Usage:
  susu <command> [arguments]

Commands:
  init <repository>       initialize and bind an existing Git repository root
  add [options] <path...> start managing files or recursive directories
  rm <path...>            stop managing exact files; leave destinations intact
  list                    list managed portable destination paths
  show <path>             write one stored version to stdout
  apply                   restore applicable repository versions locally

Global help:
  susu --help
  susu <command> --help

Git commit, push, pull, and repository synchronization remain explicit Git
operations; susu does not run them for you.
`)
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }
func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func helpError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func readTTYPassword(create bool) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty for password input: %w", err)
	}
	defer tty.Close()

	password, err := readOnePassword(tty, "Password: ")
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if !create {
		return password, nil
	}

	confirmation, err := readOnePassword(tty, "Confirm password: ")
	if err != nil {
		cryptox.ZeroBytes(password)
		return nil, err
	}
	defer cryptox.ZeroBytes(confirmation)
	if !bytes.Equal(password, confirmation) {
		cryptox.ZeroBytes(password)
		return nil, errors.New("password confirmation does not match")
	}
	return password, nil
}

func readOnePassword(tty *os.File, prompt string) ([]byte, error) {
	if _, err := io.WriteString(tty, prompt); err != nil {
		return nil, err
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	_, newlineErr := io.WriteString(tty, "\n")
	if err != nil {
		return nil, fmt.Errorf("read password from TTY: %w", err)
	}
	if newlineErr != nil {
		cryptox.ZeroBytes(password)
		return nil, newlineErr
	}
	return password, nil
}
