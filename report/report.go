package report

import (
	"io"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE              = "CWE-798"
	CWE_DESCRIPTION  = "Use of Hard-coded Credentials"
	StdoutReportPath = "-"
)

// Reporter writes one artifact for one batch of findings.
//
// # Report write contract
//
// The json, csv, junit and sarif reporters all consume the same batch of
// findings and must agree on a single shape per artifact:
//
//  1. The artifact shape is resolved over the whole finding batch, never from
//     the first finding alone. In particular, the CSV column set includes the
//     Link column whenever any finding in the batch carries a link, and every
//     row then carries a Link cell (empty for findings without one).
//  2. Zero findings keep the historical per-format empty shapes: csv is a
//     zero-byte file (no header), json is "[]", junit is an empty testsuites
//     document, and sarif declares the rule catalog with an empty results
//     array. These shapes are part of the contract, not incidental output.
//  3. The sarif rule catalog declares exactly the rules that took part in the
//     scan. The catalog is assembled by the caller (cmd) from the effective
//     config, so downstream integrations never see rules that were not
//     evaluated.
//  4. A write error is returned to the caller and no cleanup is attempted:
//     whatever bytes the sink already accepted remain in place. Callers must
//     treat the artifact as failed instead of trusting a partial file.
//
// Non-empty artifacts are byte-compatible with the golden files in
// testdata/expected/report.
type Reporter interface {
	Write(w io.WriteCloser, findings []Finding) error
}
