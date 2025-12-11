package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbomdelta",
	Short: "sbomdelta evaluates vulnerability deltas between upstream and hardened images",
	Long: `sbomdelta evaluates vulnerability deltas between upstream and hardened images.

It compares:
  - package differences
  - CVE differences
  - optional backport/exception CVEs`,
	// If user runs just `sbomdelta`, show help
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// Execute is called from main.go
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(evalCmd)
}
