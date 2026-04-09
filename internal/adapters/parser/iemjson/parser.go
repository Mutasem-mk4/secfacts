package iemjson

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const opParse = "iemjson.Parser.Parse"
const opHydrate = "iemjson.Parser.Hydrate"

type Parser struct{}

func (Parser) Provider() string {
	return "iemjson"
}

func (Parser) Supports(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".json" || ext == ".jsonl" || ext == ".ndjson"
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	switch strings.ToLower(filepath.Ext(req.Filename)) {
	case ".jsonl", ".ndjson":
		return parseLineDelimited(ctx, req, sink)
	default:
		return parseStructuredJSON(ctx, req, sink)
	}
}

func (Parser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	if err := ctx.Err(); err != nil {
		return evidence.Finding{}, err
	}
	if req.Meta.Range.Len() <= 0 {
		return evidence.Finding{}, sferr.New(sferr.CodeParseFailed, opHydrate, "finding range is empty")
	}

	section := io.NewSectionReader(req.Reader, req.Meta.Range.Start, req.Meta.Range.Len())
	raw, err := io.ReadAll(section)
	if err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeIO, opHydrate, err, "read finding section")
	}

	trimmed := trimHydratedJSON(raw)
	if len(trimmed) == 0 {
		return evidence.Finding{}, sferr.New(sferr.CodeParseFailed, opHydrate, "finding section is empty")
	}

	var finding evidence.Finding
	if err := json.Unmarshal(trimmed, &finding); err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeParseFailed, opHydrate, err, "decode finding section")
	}

	applySourceDefaults(&finding, req.Source)
	return finding, nil
}

func parseStructuredJSON(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read opening token")
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "expected JSON array or object input")
	}

	switch delim {
	case '[':
		return parseFindingArray(ctx, decoder, req, sink)
	case '{':
		return parseDocumentObject(ctx, decoder, req, sink)
	default:
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "expected top-level array or object")
	}
}

func parseFindingArray(ctx context.Context, decoder *json.Decoder, req ports.ParseRequest, sink ports.FindingSink) error {
	for index := 0; decoder.More(); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := decoder.InputOffset()
		var finding evidence.Finding
		if err := decoder.Decode(&finding); err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode finding")
		}

		if err := writeFinding(ctx, req, sink, finding, ports.ParseMetadata{
			Range: evidence.ByteOffsetRange{Start: start, End: decoder.InputOffset()},
			Index: index,
		}); err != nil {
			return err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read closing token")
	}

	return nil
}

func parseDocumentObject(ctx context.Context, decoder *json.Decoder, req ports.ParseRequest, sink ports.FindingSink) error {
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode document key")
		}

		key, ok := keyToken.(string)
		if !ok {
			return sferr.New(sferr.CodeParseFailed, opParse, "document key is not a string")
		}

		if !strings.EqualFold(key, "findings") {
			var discard json.RawMessage
			if err := decoder.Decode(&discard); err != nil {
				return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "discard document field")
			}
			continue
		}

		token, err := decoder.Token()
		if err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read findings token")
		}

		delim, ok := token.(json.Delim)
		if !ok || delim != '[' {
			return sferr.New(sferr.CodeParseFailed, opParse, "document findings field must be an array")
		}

		if err := parseFindingArray(ctx, decoder, req, sink); err != nil {
			return err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read document closing token")
	}

	return nil
}

func parseLineDelimited(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	var (
		reader io.Reader = req.Reader
		offset int64
		index  int
	)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		line, err := readLine(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "scan line-delimited input")
		}

		start, end, ok := trimmedLineRange(line, offset)
		offset += int64(len(line))
		if !ok {
			continue
		}

		var finding evidence.Finding
		if err := json.Unmarshal(bytes.TrimSpace(line), &finding); err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode line-delimited finding")
		}

		if err := writeFinding(ctx, req, sink, finding, ports.ParseMetadata{
			Range: evidence.ByteOffsetRange{Start: start, End: end},
			Index: index,
		}); err != nil {
			return err
		}
		index++
	}
}

func writeFinding(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink, finding evidence.Finding, meta ports.ParseMetadata) error {
	applySourceDefaults(&finding, req.Source)
	return sink.WriteFinding(ctx, finding, meta)
}

func applySourceDefaults(finding *evidence.Finding, source evidence.SourceDescriptor) {
	finding.SchemaVersion = evidence.SchemaVersion
	if finding.Source.Provider == "" {
		finding.Source.Provider = source.Provider
	}
	if finding.Source.Scanner == "" {
		finding.Source.Scanner = source.ToolName
	}
	if finding.Source.ScannerVersion == "" {
		finding.Source.ScannerVersion = source.ToolVersion
	}
}

func trimHydratedJSON(raw []byte) []byte {
	trimmed := bytes.TrimLeft(raw, " \t\r\n,")
	return bytes.TrimSpace(trimmed)
}

func readLine(reader io.Reader) ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			line = append(line, buf[0])
			if buf[0] == '\n' {
				return line, nil
			}
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

func trimmedLineRange(line []byte, base int64) (int64, int64, bool) {
	start := 0
	for start < len(line) && isJSONSpace(line[start]) {
		start++
	}
	end := len(line)
	for end > start && isJSONSpace(line[end-1]) {
		end--
	}
	if start == end {
		return 0, 0, false
	}
	return base + int64(start), base + int64(end), true
}

func isJSONSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}
