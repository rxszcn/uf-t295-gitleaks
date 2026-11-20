package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
)

// The regression matrix below is derived from the report write contract in
// report.go. Each case pins one contract clause:
//
//  1. zero findings keep the per-format empty shapes
//  2. the csv column set is resolved over the batch: a link anywhere means the
//     Link column is present and carries data for every row
//  3. the same holds when the first finding carries the link and later ones
//     do not (the column set is not derived from the first row)
//  4. the sarif rule catalog declares exactly the rules that took part in the
//     scan, so catalog entries and results come from the same source
//
// Non-empty golden artifacts are covered by the existing per-format tests.

func writeToBuffer(t *testing.T, reporter Reporter, findings []Finding) []byte {
	t.Helper()

	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, findings))
	return buf.Bytes()
}

// group 1: zero findings, four artifact shapes.
func TestWriteContractZeroFindings(t *testing.T) {
	t.Run("csv is a zero-byte artifact without header", func(t *testing.T) {
		got := writeToBuffer(t, &CsvReporter{}, []Finding{})
		assert.Empty(t, got)
	})

	t.Run("json is an empty array", func(t *testing.T) {
		got := writeToBuffer(t, &JsonReporter{}, []Finding{})
		want, err := os.ReadFile(filepath.Join(expectPath, "report", "empty.json"))
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got))
	})

	t.Run("junit is an empty testsuites document", func(t *testing.T) {
		got := writeToBuffer(t, &JunitReporter{}, []Finding{})
		want, err := os.ReadFile(filepath.Join(expectPath, "report", "junit_empty.xml"))
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got))
	})

	t.Run("sarif declares the scan catalog with an empty results array", func(t *testing.T) {
		reporter := &SarifReporter{
			OrderedRules: []config.Rule{
				{RuleID: "aws-access-key", Description: "AWS Access Key"},
			},
		}
		got := writeToBuffer(t, reporter, []Finding{})

		var sarif Sarif
		require.NoError(t, json.Unmarshal(got, &sarif))
		require.Len(t, sarif.Runs, 1)
		assert.NotNil(t, sarif.Runs[0].Results)
		assert.Empty(t, sarif.Runs[0].Results)
		require.Len(t, sarif.Runs[0].Tool.Driver.Rules, 1)
		assert.Equal(t, "aws-access-key", sarif.Runs[0].Tool.Driver.Rules[0].ID)
	})
}

// group 2: first finding has no link, later finding does.
func TestWriteContractLinkColumnFromLaterFinding(t *testing.T) {
	findings := []Finding{
		{
			RuleID:    "no-link-rule",
			File:      "a.py",
			StartLine: 1,
			Tags:      []string{},
		},
		{
			RuleID:    "link-rule",
			File:      "b.py",
			StartLine: 2,
			Link:      "https://example.com/b.py",
			Tags:      []string{},
		},
	}

	got := writeToBuffer(t, &CsvReporter{}, findings)

	reader := csv.NewReader(bytes.NewReader(got))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3)

	header := records[0]
	linkIndex := -1
	for i, column := range header {
		if column == "Link" {
			linkIndex = i
		}
	}
	require.NotEqual(t, -1, linkIndex, "header must contain Link: %v", header)

	require.Len(t, records[1], len(header))
	require.Len(t, records[2], len(header))
	assert.Equal(t, "", records[1][linkIndex])
	assert.Equal(t, "https://example.com/b.py", records[2][linkIndex])
}

// group 3: first finding has the link, later findings do not.
func TestWriteContractLinkColumnFromFirstFinding(t *testing.T) {
	findings := []Finding{
		{
			RuleID:    "link-rule",
			File:      "a.py",
			StartLine: 1,
			Link:      "https://example.com/a.py",
			Tags:      []string{},
		},
		{
			RuleID:    "no-link-rule",
			File:      "b.py",
			StartLine: 2,
			Tags:      []string{},
		},
	}

	got := writeToBuffer(t, &CsvReporter{}, findings)

	reader := csv.NewReader(bytes.NewReader(got))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3)

	header := records[0]
	linkIndex := -1
	for i, column := range header {
		if column == "Link" {
			linkIndex = i
		}
	}
	require.NotEqual(t, -1, linkIndex, "header must contain Link: %v", header)

	require.Len(t, records[1], len(header))
	require.Len(t, records[2], len(header))
	assert.Equal(t, "https://example.com/a.py", records[1][linkIndex])
	assert.Equal(t, "", records[2][linkIndex])
}

// group 4: after the rule set is narrowed, the sarif catalog and the results
// are assembled from the same rule set.
func TestWriteContractSarifCatalogMatchesExecutedRuleSet(t *testing.T) {
	// A narrowed scan: only one rule was enabled, so only one rule could take
	// part in the scan and produce a result.
	narrowedRules := []config.Rule{
		{RuleID: "generic-api-key", Description: "Generic API Key"},
	}
	findings := []Finding{
		{
			RuleID:      "generic-api-key",
			Description: "Generic API Key",
			File:        "config.py",
			StartLine:   3,
			Tags:        []string{},
		},
	}

	reporter := &SarifReporter{OrderedRules: narrowedRules}
	got := writeToBuffer(t, reporter, findings)

	var sarif Sarif
	require.NoError(t, json.Unmarshal(got, &sarif))
	require.Len(t, sarif.Runs, 1)

	declared := sarif.Runs[0].Tool.Driver.Rules
	results := sarif.Runs[0].Results
	require.Len(t, declared, 1)
	require.Len(t, results, 1)
	assert.Equal(t, len(declared), len(results),
		"declared catalog entries must match executed results")
	assert.Equal(t, declared[0].ID, results[0].RuleId)

	// Every result must be attributable to a declared rule, and every declared
	// rule must have taken part in the scan. With a narrowed rule set of one
	// executed rule the two views are the same set.
	declaredIDs := make(map[string]struct{}, len(declared))
	for _, r := range declared {
		declaredIDs[r.ID] = struct{}{}
	}
	for _, result := range results {
		_, ok := declaredIDs[result.RuleId]
		assert.True(t, ok, "result rule %q is missing from the declared catalog", result.RuleId)
	}
}

// writeFailureWriter accepts up to |limit| bytes and then fails. It keeps the
// buffer as a field rather than embedding it so that io.WriteString cannot
// bypass Write via the embedded WriteString method.
type writeFailureWriter struct {
	buf      bytes.Buffer
	limit    int
	failures int
}

var errWriteFailure = errors.New("injected write failure")

func (w *writeFailureWriter) Close() error { return nil }

func (w *writeFailureWriter) Bytes() []byte { return w.buf.Bytes() }

func (w *writeFailureWriter) Len() int { return w.buf.Len() }

func (w *writeFailureWriter) Write(p []byte) (int, error) {
	allowed := w.limit - w.buf.Len()
	if allowed <= 0 {
		w.failures++
		return 0, errWriteFailure
	}
	if len(p) > allowed {
		n, _ := w.buf.Write(p[:allowed])
		w.failures++
		return n, errWriteFailure
	}
	return w.buf.Write(p)
}

// Write failures are surfaced to the caller and leave already-written bytes in
// place; the reporters do not truncate or delete a partially written artifact.
func TestWriteContractWriteFailureLeavesBytesInPlace(t *testing.T) {
	tests := []struct {
		name     string
		reporter Reporter
		findings []Finding
	}{
		{
			name:     "csv",
			reporter: &CsvReporter{},
			findings: []Finding{{RuleID: "test-rule", File: "auth.py", StartLine: 1}},
		},
		{
			name:     "json",
			reporter: &JsonReporter{},
			findings: []Finding{{RuleID: "test-rule", File: "auth.py", StartLine: 1}},
		},
		{
			name:     "junit",
			reporter: &JunitReporter{},
			findings: []Finding{{RuleID: "test-rule", File: "auth.py", StartLine: 1}},
		},
		{
			name:     "sarif",
			reporter: &SarifReporter{},
			findings: []Finding{{RuleID: "test-rule", File: "auth.py", StartLine: 1}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &writeFailureWriter{limit: 16}

			err := test.reporter.Write(w, test.findings)
			require.Error(t, err)
			assert.ErrorIs(t, err, errWriteFailure)

			// The bytes accepted before the failure stay in the artifact.
			assert.NotEmpty(t, w.Bytes())
			assert.LessOrEqual(t, w.Len(), 16)
		})
	}
}

// The empty csv artifact deliberately keeps its historical shape: no header is
// written, so the weekly-report script still sees a zero-byte file.
func TestWriteContractCSVHeaderReading(t *testing.T) {
	findings := []Finding{
		{RuleID: "rule-a", File: "a.py", StartLine: 1},
		{RuleID: "rule-b", File: "b.py", StartLine: 2, Link: "https://example.com/b.py"},
	}

	got := writeToBuffer(t, &CsvReporter{}, findings)
	header := strings.SplitN(string(got), "\n", 2)[0]

	assert.Equal(t,
		"RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags,Link",
		header)
}
