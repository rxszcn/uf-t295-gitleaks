package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

type CsvReporter struct {
}

var _ Reporter = (*CsvReporter)(nil)

// csvBaseColumns is the column set every non-empty csv artifact starts from.
// The Link column is appended when the batch contains link data.
var csvBaseColumns = []string{
	"RuleID",
	"Commit",
	"File",
	"SymlinkFile",
	"Secret",
	"Match",
	"StartLine",
	"EndLine",
	"StartColumn",
	"EndColumn",
	"Author",
	"Message",
	"Date",
	"Email",
	"Fingerprint",
	"Tags",
}

// csvColumns resolves the column set over the whole finding batch. Link is a
// batch-level property: as soon as any finding carries a link, the column is
// present for every row. The column set is never derived from a single row.
func csvColumns(findings []Finding) []string {
	withLink := false
	for _, f := range findings {
		if f.Link != "" {
			withLink = true
			break
		}
	}

	columns := make([]string, 0, len(csvBaseColumns)+1)
	columns = append(columns, csvBaseColumns...)
	if withLink {
		columns = append(columns, "Link")
	}
	return columns
}

func (r *CsvReporter) Write(w io.WriteCloser, findings []Finding) error {
	if len(findings) == 0 {
		// Contract: zero findings yield a zero-byte csv artifact (no header).
		return nil
	}

	var (
		cw      = csv.NewWriter(w)
		err     error
		columns = csvColumns(findings)
	)
	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := make([]string, 0, len(columns))
		row = append(row,
			f.RuleID,
			f.Commit,
			f.File,
			f.SymlinkFile,
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		)
		if len(columns) > len(csvBaseColumns) {
			row = append(row, f.Link)
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
