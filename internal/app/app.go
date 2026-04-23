package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/axon/axon/internal/adapters/baseline"
	"github.com/axon/axon/internal/adapters/exporter/asff"
	iemexporter "github.com/axon/axon/internal/adapters/exporter/iemjson"
	"github.com/axon/axon/internal/adapters/exporter/sarif"
	"github.com/axon/axon/internal/adapters/parser/checkov"
	"github.com/axon/axon/internal/adapters/parser/gitleaks"
	"github.com/axon/axon/internal/adapters/parser/iemjson"
	"github.com/axon/axon/internal/adapters/parser/snyk"
	"github.com/axon/axon/internal/adapters/parser/trivy"
	policyyaml "github.com/axon/axon/internal/adapters/policy"
	"github.com/axon/axon/internal/adapters/registry"
	"github.com/axon/axon/internal/bootstrap"
	"github.com/axon/axon/internal/domain/correlation"
	"github.com/axon/axon/internal/domain/dedup"
	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	domainpolicy "github.com/axon/axon/internal/domain/policy"
	"github.com/axon/axon/internal/ports"
	"github.com/axon/axon/internal/usecase/evaluate"
	"github.com/axon/axon/internal/usecase/ingest"
	"github.com/axon/axon/internal/usecase/normalize"
	"github.com/axon/axon/pkg/version"
)

func Run() int {
	cfg := bootstrap.LoadConfig()
	logger := bootstrap.NewLogger(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, err := newRootCommand(ctx, cfg, logger)
	if err != nil {
		logger.Error().
			Str("code", string(sferr.CodeOf(err))).
			Err(err).
			Msg("initialize command")
		return 1
	}

	if err := cmd.ExecuteContext(ctx); err != nil {
		logger.Error().
			Str("code", string(sferr.CodeOf(err))).
			Err(err).
			Msg("command failed")
		if sferr.IsCode(err, sferr.CodePolicyViolation) {
			return 2
		}
		return 1
	}

	return 0
}

func newRootCommand(ctx context.Context, cfg bootstrap.Config, logger zerolog.Logger) (*cobra.Command, error) {
	parserRegistry, exporterRegistry, err := newRegistries()
	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:           "axon",
		Short:         "Normalize security evidence into a canonical internal model.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.SetContext(ctx)
	cmd.PersistentFlags().String("log-level", cfg.LogLevel, "Log level: debug, info, warn, error")
	cmd.PersistentFlags().String("log-format", cfg.LogFormat, "Log format: console or json")
	cmd.PersistentFlags().Int("workers", cfg.Workers, "Maximum concurrent workers for ingestion")

	cmd.AddCommand(newIngestCommand(cfg, logger, parserRegistry, exporterRegistry))
	cmd.AddCommand(newCompletionCommand(cmd))
	cmd.AddCommand(newServeCommand(cfg, logger))
	cmd.AddCommand(newWorkerCommand(cfg, logger))

	return cmd, nil
}

func newIngestCommand(
	cfg bootstrap.Config,
	logger zerolog.Logger,
	parserRegistry *registry.ParserRegistry,
	exporterRegistry *registry.ExporterRegistry,
) *cobra.Command {
	var outputPath string
	var format string
	var pretty bool
	var provider string
	var toolName string
	var toolVersion string
	var failOnSeverity string
	var baselinePath string
	var policyPath string
	var awsAccountID string
	var awsRegion string
	var awsProductARN string
	var awsGeneratorID string
	var quiet bool
	var concurrency int

	cmd := &cobra.Command{
		Use:     "ingest <input> [input...]",
		Aliases: []string{"normalize"},
		Short:   "Ingest and normalize security reports (files or directories) into the internal model.",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if concurrency <= 0 {
				return sferr.New(sferr.CodeInvalidArgument, "ingest", "concurrency must be greater than zero")
			}

			exporter, err := exporterRegistry.ByFormat(format)
			if err != nil {
				return err
			}

			writer, closeWriter, err := outputWriter(outputPath)
			if err != nil {
				return err
			}
			defer closeWriter()

			source := evidence.SourceDescriptor{
				Provider:    provider,
				ToolName:    toolName,
				ToolVersion: toolVersion,
				Format:      "auto",
			}

			inputs := make([]ingest.Input, 0, len(args))
			cleanupInputs := make([]func(), 0, len(args))
			defer func() {
				for _, cleanup := range cleanupInputs {
					cleanup()
				}
			}()
			usesStdin := false
			for _, arg := range args {
				if arg == "-" {
					if usesStdin {
						return sferr.New(sferr.CodeInvalidArgument, "ingest", "stdin can only be specified once")
					}
					usesStdin = true
					input, cleanup, err := materializeStdinInput(source)
					if err != nil {
						return err
					}
					cleanupInputs = append(cleanupInputs, cleanup)
					inputs = append(inputs, input)
					continue
				}
				inputs = append(inputs, ingest.Input{
					Path:   arg,
					Source: sourceForInput(source, arg),
				})
			}

			progress := progressObserver{logger: logger, quiet: quiet}
			identityBuilder := evidence.DefaultIdentityBuilder{}
			normalizer := normalize.Service{
				IdentityBuilder: identityBuilder,
				Interner:        evidence.NewInterner(),
			}
			deduplicator := dedup.Service{Builder: identityBuilder}
			correlator := correlation.Service{}

			service := ingest.Service{
				Parsers:      parserRegistry.All(),
				Normalizer:   normalizer,
				Deduplicator: deduplicator,
				Correlator:   correlator,
				Exporter:     exporter,
				Observer:     progress,
				Config: ingest.Config{
					DiscoveryWorkers: 1,
					ParseWorkers:     concurrency,
					NormalizeWorkers: concurrency,
					DiscoveryBuffer:  64,
					FindingBuffer:    512,
				},
			}

			if !quiet {
				logger.Info().
					Str("format", format).
					Str("output", defaultOutputLabel(outputPath)).
					Int("concurrency", concurrency).
					Strs("inputs", args).
					Msg("starting ingestion")
			}

			policy, err := loadPolicy(policyPath)
			if err != nil {
				return err
			}
			mergePolicyFlags(&policy, failOnSeverity)
			retainFindings := shouldEvaluate(policy, baselinePath)

			result, err := service.Run(cmd.Context(), ingest.Request{
				Inputs: inputs,
				Output: ports.ExportRequest{
					Writer: writer,
					Options: ports.ExportOptions{
						Pretty:       pretty,
						AWSAccountID: awsAccountID,
						AWSRegion:    awsRegion,
						ProductARN:   awsProductARN,
						GeneratorID:  awsGeneratorID,
					},
				},
				RetainFindings: retainFindings,
			})
			if err != nil {
				return err
			}

			if shouldEvaluate(policy, baselinePath) {
				baselineDocument, err := loadBaseline(cmd.Context(), baselinePath)
				if err != nil {
					return err
				}

				decision, err := evaluate.Service{
					Engine: domainpolicy.Service{},
				}.Run(cmd.Context(), evaluate.Request{
					Document: evidence.Document{Findings: result.Findings},
					Baseline: baselineDocument,
					Policy:   policy,
				})
				if err != nil {
					return err
				}

				logger.Info().
					Int("new_findings", len(decision.NewFindings)).
					Int("existing_findings", len(decision.ExistingFindings)).
					Int("fixed_findings", len(decision.FixedFindings)).
					Bool("passed", decision.Passed).
					Msg("policy evaluation completed")

				if !decision.Passed {
					renderSummaryTable(cmd.ErrOrStderr(), result)
					return sferr.New(sferr.CodePolicyViolation, "ingest", summarizeViolations(decision.Violations))
				}
			}

			renderSummaryTable(cmd.ErrOrStderr(), result)
			if !quiet {
				logger.Info().Msg("ingestion completed")
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", runtime.NumCPU(), "Concurrent workers for parsing/normalization")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format: json, sarif, or asff")
	cmd.Flags().BoolVarP(&pretty, "pretty", "p", true, "Pretty-print exported output")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress logs (only emit summary)")
	cmd.Flags().StringVar(&provider, "provider", "axon", "Logical source provider for findings")
	cmd.Flags().StringVar(&toolName, "tool-name", "axon", "Scanner or producer name")
	cmd.Flags().StringVar(&toolVersion, "tool-version", version.Version, "Scanner or producer version")
	cmd.Flags().StringVarP(&failOnSeverity, "fail-on-severity", "s", "", "Fail if findings meet threshold: low, medium, high, critical")
	cmd.Flags().StringVarP(&baselinePath, "baseline", "b", "", "Incremental comparison baseline (axon JSON)")
	cmd.Flags().StringVarP(&policyPath, "policy", "P", "", "Path to YAML policy file")
	cmd.Flags().StringVar(&awsAccountID, "aws-account-id", "", "AWS account ID for ASFF exports; falls back to AXON_AWS_ACCOUNT_ID")
	cmd.Flags().StringVar(&awsRegion, "aws-region", "", "AWS region for ASFF exports; falls back to AXON_AWS_REGION")
	cmd.Flags().StringVar(&awsProductARN, "aws-product-arn", "", "AWS Security Hub product ARN for ASFF exports; falls back to AXON_AWS_PRODUCT_ARN")
	cmd.Flags().StringVar(&awsGeneratorID, "aws-generator-id", "", "Generator ID for ASFF exports; falls back to AXON_AWS_GENERATOR_ID")

	return cmd
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Generate shell completion scripts",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return sferr.New(sferr.CodeInvalidArgument, "completion", "unsupported shell: "+args[0])
			}
		},
	}
}

func newRegistries() (*registry.ParserRegistry, *registry.ExporterRegistry, error) {
	parserRegistry, err := registry.NewParserRegistry(
		trivy.Parser{},
		iemjson.Parser{},
		gitleaks.Parser{},
		snyk.Parser{},
		checkov.Parser{},
	)
	if err != nil {
		return nil, nil, err
	}

	exporterRegistry, err := registry.NewExporterRegistry(
		iemexporter.Exporter{},
		asff.Exporter{},
		sarif.Exporter{},
	)
	if err != nil {
		return nil, nil, err
	}

	return parserRegistry, exporterRegistry, nil
}

func outputWriter(path string) (*os.File, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, nil, sferr.Wrap(sferr.CodeIO, "normalize.outputWriter", err, "create output file")
	}

	return file, func() {
		_ = file.Close()
	}, nil
}

func defaultOutputLabel(path string) string {
	if path == "" {
		return "stdout"
	}

	return path
}

func sourceForInput(source evidence.SourceDescriptor, path string) evidence.SourceDescriptor {
	source.URI = path
	return source
}

func materializeStdinInput(source evidence.SourceDescriptor) (ingest.Input, func(), error) {
	return ingest.Input{
		Path:   "stdin",
		Source: sourceForInput(source, "stdin"),
		Reader: io.NopCloser(os.Stdin),
	}, func() {}, nil
}

func loadPolicy(path string) (domainpolicy.Policy, error) {
	if path == "" {
		return domainpolicy.Policy{}, nil
	}

	return policyyaml.LoadFile(path)
}

func mergePolicyFlags(policy *domainpolicy.Policy, failOnSeverity string) {
	if strings.TrimSpace(failOnSeverity) != "" {
		policy.FailOnSeverity = evidence.SeverityLabel(strings.ToLower(strings.TrimSpace(failOnSeverity)))
	}
}

func shouldEvaluate(policy domainpolicy.Policy, baselinePath string) bool {
	if strings.TrimSpace(baselinePath) != "" {
		return true
	}

	return strings.TrimSpace(string(policy.FailOnSeverity)) != "" ||
		len(policy.MaxCountThresholds) > 0 ||
		len(policy.Allowlist) > 0 ||
		policy.FailOnNewOnly
}

func loadBaseline(ctx context.Context, path string) (evidence.Document, error) {
	if strings.TrimSpace(path) == "" {
		return evidence.Document{}, nil
	}

	return baseline.LoadIEMJSON(ctx, path, iemjson.Parser{})
}

func summarizeViolations(violations []domainpolicy.Violation) string {
	if len(violations) == 0 {
		return "policy violation"
	}

	messages := make([]string, 0, len(violations))
	for _, violation := range violations {
		messages = append(messages, violation.Message)
	}

	return strings.Join(messages, "; ")
}

type progressObserver struct {
	logger zerolog.Logger
	quiet  bool
}

func (o progressObserver) OnFilesDiscovered(_ context.Context, count int) {
	if o.quiet {
		return
	}
	o.logger.Info().Int("files", count).Msg("discovered files")
}

func (o progressObserver) OnFindingsParsed(_ context.Context, count int) {
	if o.quiet {
		return
	}
	o.logger.Info().Int("findings", count).Msg("parsed findings")
}

func (o progressObserver) OnFindingsDeduplicated(_ context.Context, total int, unique int) {
	if o.quiet {
		return
	}
	o.logger.Info().
		Int("total_findings", total).
		Int("unique_findings", unique).
		Msg("deduplicated findings")
}

func (o progressObserver) OnExportCompleted(_ context.Context, format string, findings int) {
	if o.quiet {
		return
	}
	o.logger.Info().
		Str("format", format).
		Int("findings", findings).
		Msg("export completed")
}

func (o progressObserver) OnPartialExport(_ context.Context, format string, findings int, reason string) {
	o.logger.Warn().
		Str("format", format).
		Int("findings", findings).
		Str("reason", reason).
		Msg("partial export")
}

func renderSummaryTable(out io.Writer, result ingest.Result) {
	if out == nil {
		return
	}
	bySeverity := result.Counts

	kinds := []evidence.Kind{
		evidence.KindSCA,
		evidence.KindSAST,
		evidence.KindDAST,
		evidence.KindCloud,
		evidence.KindSecrets,
	}
	labels := []evidence.SeverityLabel{
		evidence.SeverityCritical,
		evidence.SeverityHigh,
		evidence.SeverityMedium,
		evidence.SeverityLow,
		evidence.SeverityInfo,
	}

	isTerminal := false
	if f, ok := out.(*os.File); ok {
		isTerminal = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Summary")
	_, _ = fmt.Fprintf(tw, "Severity\tTotal\tSCA\tSAST\tDAST\tCloud\tSecrets\n")

	for _, label := range labels {
		counts := bySeverity[label]
		total := 0
		row := make([]int, 0, len(kinds))
		for _, kind := range kinds {
			value := counts[kind]
			row = append(row, value)
			total += value
		}

		severityText := strings.ToUpper(string(label))
		if isTerminal {
			severityText = colorizeSeverity(label, severityText)
		}

		_, _ = fmt.Fprintf(
			tw,
			"%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			severityText,
			total,
			row[0],
			row[1],
			row[2],
			row[3],
			row[4],
		)
	}

	totalLabel := "TOTAL"
	if isTerminal {
		totalLabel = "\x1b[1mTOTAL\x1b[0m"
	}

	_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
		totalLabel,
		result.Document.Summary.UniqueFindings,
		totalByKindCounts(result.Counts, evidence.KindSCA),
		totalByKindCounts(result.Counts, evidence.KindSAST),
		totalByKindCounts(result.Counts, evidence.KindDAST),
		totalByKindCounts(result.Counts, evidence.KindCloud),
		totalByKindCounts(result.Counts, evidence.KindSecrets),
	)
	_ = tw.Flush()
}

func colorizeSeverity(label evidence.SeverityLabel, text string) string {
	const (
		reset     = "\x1b[0m"
		bold      = "\x1b[1m"
		red       = "\x1b[31m"
		yellow    = "\x1b[33m"
		cyan      = "\x1b[36m"
		blue      = "\x1b[34m"
		boldRed   = bold + red
	)

	switch label {
	case evidence.SeverityCritical, evidence.SeverityHigh:
		return boldRed + text + reset
	case evidence.SeverityMedium:
		return yellow + text + reset
	case evidence.SeverityLow:
		return cyan + text + reset
	case evidence.SeverityInfo:
		return blue + text + reset
	default:
		return text
	}
}

func totalByKindCounts(counts map[evidence.SeverityLabel]map[evidence.Kind]int, kind evidence.Kind) int {
	total := 0
	for _, byKind := range counts {
		total += byKind[kind]
	}
	return total
}

func ExitWithError(err error) {
	if err == nil {
		return
	}

	_, _ = fmt.Fprintln(os.Stderr, sferr.Format(err))
}
