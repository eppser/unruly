package main

import (
	"github.com/projectdiscovery/gologger"

	"github.com/eppser/unruly/scan"
)

// renderNotes is the command's rendering adapter. Stages own what a
// measurement means; the command owns how progress is displayed.
func renderNotes(n scan.Note) {
	switch n.Level {
	case scan.Error:
		gologger.Error().Msg(n.Text)
	case scan.Warn:
		gologger.Warning().Msg(n.Text)
	default:
		gologger.Info().Msg(n.Text)
	}
}
