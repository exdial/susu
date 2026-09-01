package cli

import (
	"errors"
	"fmt"
	"io"
)

const bashCompletion = `# bash completion for susu
_susu_completion() {
  local cur prev command
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev=""
  if (( COMP_CWORD > 0 )); then
    prev="${COMP_WORDS[COMP_CWORD-1]}"
  fi

  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( $(compgen -W "init add rm ls list show apply completion help" -- "$cur") )
    return
  fi

  command="${COMP_WORDS[1]}"
  case "$command" in
    add)
      if [[ "$prev" == "--exclude-platform" ]]; then
        COMPREPLY=( $(compgen -W "darwin linux" -- "$cur") )
      elif [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--sensitive --exclude-platform --help -h" -- "$cur") )
      else
        compopt -o filenames
        COMPREPLY=( $(compgen -f -- "$cur") )
      fi
      ;;
    init|rm|show)
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--help -h" -- "$cur") )
      else
        compopt -o filenames
        COMPREPLY=( $(compgen -f -- "$cur") )
      fi
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh --help -h" -- "$cur") )
      ;;
    ls|list|apply)
      COMPREPLY=( $(compgen -W "--help -h" -- "$cur") )
      ;;
  esac
}

complete -F _susu_completion susu
`

const zshCompletion = `#compdef susu

_susu() {
  local -a commands
  commands=(
    'init:initialize susu in an existing Git repository'
    'add:start managing files or directories'
    'rm:stop managing files'
    'ls:list managed files'
    'list:alias for ls'
    'show:print a stored file'
    'apply:apply managed files to this machine'
    'completion:generate shell completion script'
    'help:show help'
  )

  if (( CURRENT == 2 )); then
    _describe 'command' commands
    return
  fi

  case "${words[2]}" in
    init|rm|show)
      _arguments '-h[show help]' '--help[show help]' '*:path:_files'
      ;;
    add)
      _arguments \
        '-h[show help]' \
        '--help[show help]' \
        '--sensitive[encrypt new files with the repository master key]' \
        '*--exclude-platform[skip on apply for a platform]:platform:(darwin linux)' \
        '*:path:_files'
      ;;
    ls|list|apply)
      _arguments '-h[show help]' '--help[show help]'
      ;;
    completion)
      _arguments '-h[show help]' '--help[show help]' '1:shell:(bash zsh)'
      ;;
  esac
}

compdef _susu susu
`

func (c *CLI) runCompletion(arguments []string) error {
	flags := c.flagSet("completion", `Generate a shell completion script.

Usage:
  susu completion <shell>

Supported shells:
  bash
  zsh

Examples:
  source <(susu completion bash)
  susu completion zsh > ~/.zfunc/_susu
`)
	if err := flags.Parse(arguments); err != nil {
		return helpError(err)
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return errors.New("completion requires exactly one shell")
	}

	var script string
	switch shell := flags.Arg(0); shell {
	case "bash":
		script = bashCompletion
	case "zsh":
		script = zshCompletion
	default:
		return fmt.Errorf("unsupported completion shell %q (supported: bash, zsh)", shell)
	}
	_, err := io.WriteString(c.stdout, script)
	return err
}
