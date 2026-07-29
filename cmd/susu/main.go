package main

import (
	"fmt"
	"os"

	"susu/internal/cli"
)

func main() {
	if cli.PrintHelpIfRequested(os.Args[1:], os.Stdout) {
		return
	}
	runner, err := cli.NewFromEnv(os.Stdout, os.Stderr)
	if err == nil {
		err = runner.Run(os.Args[1:])
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "susu:", err)
		os.Exit(1)
	}
}
