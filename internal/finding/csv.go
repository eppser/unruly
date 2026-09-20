package finding

import (
	"encoding/csv"
	"io"
	"strconv"
)

// CSV rendering: one row per finding, for a spreadsheet or a ticket queue.
//
// It carries the verdict and the address, and deliberately NOT the sampled
// rows. Every other rendering can quote real data because the operator asked
// for proof; a CSV is the shape most likely to be forwarded, pasted into a
// sheet and mailed around, and the sampled rows are the session tokens and
// password hashes the finding is warning about. -redact exists for the other
// formats. Here it is the default and there is no flag to turn it off, because
// a spreadsheet of somebody's credentials is not a report.
//
// The columns are outcome-first: what is wrong and how bad, before where and
// why.
var csvColumns = []string{
	"severity", "id", "resource", "protocol", "rows", "matched", "reason",
}

// CSVHeader writes the column names. Called once, before any row.
func CSVHeader(out io.Writer) error {
	w := csv.NewWriter(out)
	if err := w.Write(csvColumns); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

// csvRow renders one finding. Field order matches csvColumns, and the two are
// kept adjacent so a column added to one is obvious in the other.
func (f Finding) csvRow() []string {
	rows := ""
	if f.Evidence.Rows > 0 {
		rows = strconv.Itoa(f.Evidence.Rows)
	}
	return []string{
		f.Severity.String(),
		f.ID,
		f.Resource,
		f.Protocol,
		rows,
		f.Matched,
		f.Evidence.Reason,
	}
}

func (w Writer) writeCSV(f Finding) error {
	c := csv.NewWriter(w.Out)
	if err := c.Write(f.csvRow()); err != nil {
		return err
	}
	c.Flush()
	return c.Error()
}
