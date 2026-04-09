package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	// rootCmd represents the base command when called without any subcommands.
	rootCmd = &cobra.Command{
		Use:   "axon",
		Short: "axon is a high-performance security evidence normalization engine",
		Long: `A robust tool for normalizing, deduplicating, and correlating findings from 
disparate security sources (SAST, DAST, SCA, Cloud) into a canonical Internal Evidence Model.
Built with performance and zero-copy processing as primary goals.`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().StringP("format", "f", "json", "Output format (json, csv, table)")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug logging")

	// Standard Twelve-Factor app patterns: stdout/stderr configuration
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}
