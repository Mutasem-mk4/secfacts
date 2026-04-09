package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Code string

const (
	CodeUnknown          Code = "unknown"
	CodeInvalidArgument  Code = "invalid_argument"
	CodeInvalidConfig    Code = "invalid_config"
	CodeUnsupportedInput Code = "unsupported_input"
	CodeDiscoveryFailed  Code = "discovery_failed"
	CodeBaselineFailed   Code = "baseline_failed"
	CodeParseFailed      Code = "parse_failed"
	CodeNormalizeFailed  Code = "normalize_failed"
	CodeDedupFailed      Code = "dedup_failed"
	CodeCorrelateFailed  Code = "correlate_failed"
	CodeExportFailed     Code = "export_failed"
	CodePolicyFailed     Code = "policy_failed"
	CodePolicyViolation  Code = "policy_violation"
	CodeIO               Code = "io"
	CodeInternal         Code = "internal"
	CodeUnimplemented    Code = "unimplemented"
)

type Error struct {
	Code    Code
	Op      string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}

	parts := make([]string, 0, 4)
	if e.Op != "" {
		parts = append(parts, e.Op)
	}
	if e.Code != "" {
		parts = append(parts, string(e.Code))
	}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}

	message := strings.Join(parts, ": ")
	if e.Err == nil {
		return message
	}
	if message == "" {
		return e.Err.Error()
	}

	return message + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

func New(code Code, op string, message string) error {
	return &Error{
		Code:    normalizeCode(code),
		Op:      op,
		Message: strings.TrimSpace(message),
	}
}

func Wrap(code Code, op string, err error, message string) error {
	if err == nil {
		return nil
	}

	return &Error{
		Code:    normalizeCode(code),
		Op:      op,
		Message: strings.TrimSpace(message),
		Err:     err,
	}
}

func WrapJSON(code Code, op string, err error, r io.ReaderAt, message string) error {
	if err == nil {
		return nil
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		snippet := getErrorSnippet(r, syntaxErr.Offset)
		message = fmt.Sprintf("%s (at offset %d: %s)", message, syntaxErr.Offset, snippet)
	}

	return Wrap(code, op, err, message)
}

func getErrorSnippet(r io.ReaderAt, offset int64) string {
	if r == nil {
		return ""
	}

	const snippetLen = 50
	start := offset - snippetLen/2
	if start < 0 {
		start = 0
	}

	buf := make([]byte, snippetLen)
	n, err := r.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return ""
	}

	snippet := string(buf[:n])
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	return "..." + strings.TrimSpace(snippet) + "..."
}

func CodeOf(err error) Code {
	if err == nil {
		return CodeUnknown
	}

	var target *Error
	if errors.As(err, &target) && target.Code != "" {
		return target.Code
	}

	return CodeUnknown
}

func IsCode(err error, code Code) bool {
	return CodeOf(err) == normalizeCode(code)
}

func Format(err error) string {
	if err == nil {
		return ""
	}

	return fmt.Sprintf("code=%s err=%s", CodeOf(err), err)
}

func normalizeCode(code Code) Code {
	if code == "" {
		return CodeUnknown
	}

	return code
}
