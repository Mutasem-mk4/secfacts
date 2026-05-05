package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/axon/axon/internal/adapters/exporters"
	"github.com/axon/axon/internal/adapters/ingestion"
	"github.com/axon/axon/internal/core/services"
	"github.com/spf13/cobra"
)

var (
	inputFile  string
	outputFile string
	parserName string
	failOn     string
	failScore  float32
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a security report and generate a normalized report",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// 1. Auto-Discovery Logic
		if inputFile == "" {
			fmt.Println("🔍 No file specified. Searching for security reports...")
			files, _ := filepath.Glob("*.sarif")
			if len(files) == 0 {
				files, _ = filepath.Glob("reports/*.sarif")
			}
			if len(files) > 0 {
				inputFile = files[0]
				fmt.Printf("✨ Found report: %s\n", inputFile)
			} else {
				return fmt.Errorf("could not find any .sarif files. Please specify one with -i")
			}
		}

		// 2. Setup Parser
		p, err := ingestion.GetParser(parserName)
		if err != nil {
			return err
		}

		// 2. Setup Input/Output
		in, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer in.Close()

		var out io.Writer = os.Stdout
		if outputFile != "" {
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		// 3. Resolve threshold score
		threshold := resolveThreshold(failOn, failScore)

		// 4. Setup Pipeline Components
		norm := services.NewShardedNormalizer(4) // 4 workers
		cor := services.NewCorrelatorService()
		exp := exporters.NewMarkdownExporter()

		// 5. Orchestrate
		pipeline := services.NewPipeline(
			services.WithParser(p),
			services.WithNormalizer(norm),
			services.WithCorrelator(cor),
			services.WithExporter(exp),
			services.WithFailScore(threshold),
		)

		return pipeline.Run(ctx, in, out)
	},
}

func resolveThreshold(label string, score float32) float32 {
	if score > 0 {
		return score
	}

	switch label {
	case "critical":
		return 9.0
	case "high":
		return 7.0
	case "medium":
		return 4.0
	case "low":
		return 1.0
	default:
		return 0
	}
}

func init() {
	scanCmd.Flags().StringVarP(&inputFile, "file", "i", "", "Input security report file (required)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output report file (default: stdout)")
	scanCmd.Flags().StringVarP(&parserName, "parser", "p", "sarif", "Parser to use (default: sarif)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Fail on severity level (low, medium, high, critical)")
	scanCmd.Flags().Float32Var(&failScore, "fail-score", 0, "Fail on specific severity score (e.g., 7.5)")

	rootCmd.AddCommand(scanCmd)

	// Register default parsers
	ingestion.Register(ingestion.NewSarifParser())
}
