package report

import (
	"encoding/json"
	"io"
)

type JsonReporter struct {
}

var _ Reporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	if findings == nil {
		// Contract: zero findings encode as [], never as null.
		findings = []Finding{}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}
