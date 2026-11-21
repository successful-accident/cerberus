// Command cerberus keeps a library of Linux ISOs current.
package main

import (
	"fmt"
	"os"

	// The forms and the status table arrive in build phase 2.
	_ "github.com/charmbracelet/huh"
	_ "github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:          "cerberus",
		Short:        "Keep a library of Linux ISOs current",
		Version:      version,
		SilenceUsage: true,
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
