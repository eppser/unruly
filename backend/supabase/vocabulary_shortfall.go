package supabase

import (
	"fmt"

	"github.com/eppser/unruly/internal/finding"
)

// What the operator is told, and what the report records, when the vocabulary
// going into enumeration is thin.
//
// Enumeration against a Supabase project is only as good as the names it tries.
// Falling back to the pinned wordlist is not a failure -- it still finds
// plenty -- but it silently lowers recall, so a report produced that way must
// say so or a reader will take "no relations found" as evidence of a clean
// project when it is evidence of a short wordlist.
//
// The two exhausted-vocabulary branches look alike and are not: "no response
// from the application" means the site was unreachable, while "N source(s)
// read, no usable vocabulary in them" means it answered and had nothing in it.
// The first is an outage, the second is a genuine measurement, and collapsing
// them would tell an operator to go fix a network problem they do not have.
type vocabNote struct {
	Warn   bool
	Msg    string
	Report *finding.Finding // nil when there is nothing to record
}

func vocabularyShortfall(site string, supplied, harvested, sources int) vocabNote {
	switch {
	case site == "" && supplied > 0:
		// Not a fallback: the vocabulary came from somewhere, it just did not
		// come from here.
		return vocabNote{Msg: fmt.Sprintf("no -site supplied; enumeration runs on the "+
			"pinned wordlist plus %d supplied name(s)", supplied)}
	case site == "":
		return vocabNote{Warn: true, Msg: "no -site supplied: enumeration falls back to " +
			"the pinned wordlist, which cannot reach domain-specific relation names"}
	case harvested == 0 && sources == 0:
		f := finding.NotAssessedApplication(site, "no response from the application")
		return vocabNote{Warn: true, Report: &f, Msg: fmt.Sprintf("the application at %s "+
			"could not be read: enumeration falls back to the pinned wordlist, so "+
			"relation recall is a lower bound", site)}
	case harvested == 0:
		f := finding.NotAssessedApplication(site,
			fmt.Sprintf("%d source(s) read, no usable vocabulary in them", sources))
		return vocabNote{Warn: true, Report: &f, Msg: fmt.Sprintf("read %d source(s) from "+
			"%s but harvested no usable vocabulary: enumeration falls back to the "+
			"pinned wordlist", sources, site)}
	}
	return vocabNote{}
}
