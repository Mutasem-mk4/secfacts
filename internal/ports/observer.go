package ports

import "context"

type Observer interface {
	OnFilesDiscovered(ctx context.Context, count int)
	OnFindingsParsed(ctx context.Context, count int)
	OnFindingsDeduplicated(ctx context.Context, total int, unique int)
	OnExportCompleted(ctx context.Context, format string, findings int)
	OnPartialExport(ctx context.Context, format string, findings int, reason string)
}
