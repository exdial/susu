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

	"github.com/exdial/susu/internal/app"
	"github.com/exdial/susu/internal/cryptox"
	"github.com/exdial/susu/internal/paths"
	"github.com/exdial/susu/internal/state"
)

// CLI is one command runner with explicit output and password dependencies.
type CLI struct {
	service  *app.Service
	paths    *paths.Resolver
	stdout   io.Writer
	stderr   io.Writer
	password app.PasswordProvider
}

// New constructs a command runner with domain and path-presentation dependencies.
// A nil password provider is valid for commands that never touch sensitive entries.
func New(service *app.Service, resolver *paths.Resolver, stdout, stderr io.Writer, password app.PasswordProvider) (*CLI, error) {
	if service == nil {
		return nil, errors.New("app service is nil")
	}
	if resolver == nil {
		return nil, errors.New("path resolver is nil")
	}
	if stdout == nil || stderr == nil {
		return nil, errors.New("CLI output writer is nil")
	}
	return &CLI{service: service, paths: resolver, stdout: stdout, stderr: stderr, password: password}, nil
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
	return New(service, resolver, stdout, stderr, readTTYPassword)
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
	case "init", "add", "rm", "ls", "list", "show", "apply", "completion":
		_ = helper.Run(arguments)
		return true
	default:
		return false
	}
}

// Run executes one argv slice without terminating the process.
func (c *CLI) Run(arguments []string) error {
	return userFacingError(c.run(arguments))
}

func (c *CLI) run(arguments []string) error {
	if len(arguments) == 0 {
		return c.runOverview()
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
	case "ls", "list":
		return c.runList(arguments[1:])
	case "show":
		return c.runShow(arguments[1:])
	case "apply":
		return c.runApply(arguments[1:])
	case "completion":
		return c.runCompletion(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q; run 'susu --help'", arguments[0])
	}
}

func (c *CLI) runOverview() error {
	overview, err := c.service.Overview()
	if errors.Is(err, state.ErrNotInitialized) {
		return c.printOnboarding()
	}
	if err != nil {
		return err
	}
	return c.printOverview(overview)
}

func (c *CLI) runInit(arguments []string) error {
	flags := c.flagSet("init", `Initialize susu in an existing Git repository.

Usage:
  susu init <repository>

Examples:
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
	flags := c.flagSet("add", `Add or update file snapshots in susu.

Usage:
  susu add [options] <path...>

Options:
  --sensitive  encrypt new files with the repository master key

Existing entries keep their public or sensitive classification.
Directories add new files and update managed files without removing missing ones.
Updates are atomic per file; earlier updates remain if a later operation fails.

Examples:
  susu add ~/.gitconfig
  susu add ~/.config/nvim
  susu add ~/.ssh/config
`)
	var sensitive bool
	flags.BoolVar(&sensitive, "sensitive", false, "encrypt new files as sensitive repository entries")
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return errors.New("add requires at least one path")
	}
	result, err := c.service.Add(flags.Args(), app.AddOptions{
		Sensitive: sensitive,
		Password:  c.password,
	})
	for _, logical := range result.Added {
		if _, err := fmt.Fprintf(c.stdout, "added %s\n", userFacingText(logical)); err != nil {
			return err
		}
	}
	for _, logical := range result.Updated {
		if _, writeErr := fmt.Fprintf(c.stdout, "updated %s\n", userFacingText(logical)); writeErr != nil {
			return writeErr
		}
	}
	for _, logical := range result.AlreadyManaged {
		if _, writeErr := fmt.Fprintf(c.stdout, "already managed %s\n", userFacingText(logical)); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (c *CLI) runRemove(arguments []string) error {
	flags := c.flagSet("rm", `Stop managing files.

Usage:
  susu rm <path...>

Files are removed from susu management but remain on the filesystem.

Examples:
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
		if _, writeErr := fmt.Fprintf(c.stdout, "removed %s\n", userFacingText(logical)); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (c *CLI) runList(arguments []string) error {
	flags := c.flagSet("ls", `List managed files.

Usage:
  susu ls

Sensitive entries receive concise annotations.

Alias: susu list
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return errors.New("ls does not accept arguments")
	}
	entries, err := c.service.List()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintln(c.stdout, userFacingText(app.FormatEntry(entry))); err != nil {
			return err
		}
	}
	return nil
}

func (c *CLI) runShow(arguments []string) error {
	flags := c.flagSet("show", `Print a stored file.

Usage:
  susu show <path>

Sensitive content is decrypted in memory after one no-echo TTY password prompt.
No destination file is modified.

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
	flags := c.flagSet("apply", `Apply managed files to this machine.

Usage:
  susu apply

Managed files replace their destinations atomically.
Sensitive files share one password prompt per invocation. Protected
local state and repository destinations are rejected before any file is applied.
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
		if _, err := fmt.Fprintf(c.stdout, "applied %s\n", userFacingText(logical)); err != nil {
			return err
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

func (c *CLI) printOnboarding() error {
	_, err := io.WriteString(c.stdout, `susu manages portable public and encrypted dotfiles.

Get started:
  susu init <repository>
  susu add <path...>
  susu apply

Run `+"`susu --help`"+` to see all commands.
`)
	return err
}

func (c *CLI) printOverview(overview app.Overview) error {
	_, err := fmt.Fprintf(c.stdout, `susu manages portable public and encrypted dotfiles.

Repository: %s
Managed: %d files

Common commands:
  susu add <path...>
  susu ls
  susu apply

Run `+"`susu --help`"+` to see all commands.
`, c.paths.AbbreviateHome(overview.Repository), overview.ManagedFiles)
	return err
}

func (c *CLI) printRootHelp(output io.Writer) {
	_, _ = io.WriteString(output, `susu manages portable public and encrypted dotfiles.

Usage:
  susu <command> [arguments]

Commands:
  init        initialize susu in an existing Git repository
  add         add or update file snapshots
  rm          stop managing files
  ls          list managed files
  show        print a stored file
  apply       apply managed files to this machine
  completion  generate shell completion script

Run `+"`susu <command> --help`"+` for command-specific help.

Git synchronization stays explicit.
Use Git normally to commit, pull, and push changes.
`)
}

func helpError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

// FormatError renders an error for the command-line interface.
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	return userFacingText(err.Error())
}

type formattedError struct {
	err error
}

func (err formattedError) Error() string { return FormatError(err.err) }
func (err formattedError) Unwrap() error { return err.err }

func userFacingError(err error) error {
	if err == nil || !strings.Contains(err.Error(), paths.XDGConfigHomePrefix) {
		return err
	}
	return formattedError{err: err}
}

func userFacingText(value string) string {
	return strings.ReplaceAll(value, paths.XDGConfigHomePrefix, "~/.config")
}

type ttyOpener func(string, int, os.FileMode) (*os.File, error)
type terminalPasswordReader func(int) ([]byte, error)

func readTTYPassword(create bool) ([]byte, error) {
	return readTTYPasswordWith(create, os.OpenFile, term.ReadPassword)
}

func readTTYPasswordWith(create bool, openTTY ttyOpener, readPassword terminalPasswordReader) ([]byte, error) {
	tty, err := openTTY("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty for password input: %w", err)
	}
	defer tty.Close()

	password, err := readOnePasswordWith(tty, "Password: ", readPassword)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if !create {
		return password, nil
	}

	confirmation, err := readOnePasswordWith(tty, "Confirm password: ", readPassword)
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

func readOnePasswordWith(tty *os.File, prompt string, readPassword terminalPasswordReader) ([]byte, error) {
	if _, err := io.WriteString(tty, prompt); err != nil {
		return nil, err
	}
	password, err := readPassword(int(tty.Fd()))
	if err != nil {
		cryptox.ZeroBytes(password)
	}
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
