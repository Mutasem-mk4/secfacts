package iemjson

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const (
	format   = "json"
	opExport = "iemjson.Exporter.Export"
)

type Exporter struct{}

func (Exporter) Format() string {
	return format
}

func (Exporter) Export(ctx context.Context, req ports.ExportRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Writer == nil {
		return sferr.New(sferr.CodeInvalidArgument, opExport, "writer is required")
	}

	iterator := req.Findings
	if iterator == nil {
		iterator = ports.NewSliceFindingIterator(req.Document.Findings)
	}
	defer iterator.Close()

	writer := bufio.NewWriter(req.Writer)
	defer writer.Flush()

	if err := writeDocumentPrefix(writer, req.Document); err != nil {
		return err
	}

	first := true
	for {
		finding, err := iterator.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "iterate findings")
		}
		if !first {
			if _, err := writer.WriteString(","); err != nil {
				return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write findings delimiter")
			}
		}
		first = false

		payload, err := json.Marshal(finding)
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal finding")
		}
		if _, err := writer.Write(payload); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write finding")
		}
	}

	correlations, err := json.Marshal(req.Document.Correlations)
	if err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal correlations")
	}
	if _, err := writer.WriteString(`],"Correlations":`); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write correlations key")
	}
	if _, err := writer.Write(correlations); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write correlations")
	}
	if _, err := writer.WriteString("}\n"); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "finalize document")
	}

	return nil
}

func writeDocumentPrefix(writer *bufio.Writer, document evidence.Document) error {
	writeField := func(name string, value any, suffix string) error {
		payload, err := json.Marshal(value)
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal "+name)
		}
		if _, err := writer.WriteString(`"` + name + `":`); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write "+name+" key")
		}
		if _, err := writer.Write(payload); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write "+name)
		}
		if _, err := writer.WriteString(suffix); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write "+name+" suffix")
		}
		return nil
	}

	if _, err := writer.WriteString("{"); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "start document")
	}
	if err := writeField("SchemaVersion", document.SchemaVersion, ","); err != nil {
		return err
	}
	if err := writeField("GeneratedAt", document.GeneratedAt, ","); err != nil {
		return err
	}
	if err := writeField("Source", document.Source, ","); err != nil {
		return err
	}
	if err := writeField("Summary", document.Summary, `,"Findings":[`); err != nil {
		return err
	}

	return nil
}
