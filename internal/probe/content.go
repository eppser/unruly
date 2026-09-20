package probe

import (
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/postgrest"
)

// Telling a leak from a page.
//
// A relation readable by anonymous callers is not automatically a problem. Some
// of them are the site's own content: the copy, the navigation, the product
// blurbs, the FAQ. Those are meant to be world-readable, they are rendered into
// the page anyway, and reporting them at the same severity as a table of
// password hashes is how a report stops being read.
//
// The discrimination has to be asymmetric, because the two errors are not
// equal. Under-reporting a leak is worse than over-reporting a page, so the
// rule is NOT "downgrade anything we do not recognise as sensitive" -- that
// would quietly demote every table whose columns happen to be named in a way
// the classifier has never seen, which is most real schemas. It demotes only on
// POSITIVE evidence that a relation is content: several columns that name
// presentation rather than people.
//
// Three further conditions keep it honest. A single content-ish column is not
// enough, because id+title describes a lookup table as easily as an article. A
// relation carrying anything the sensitive classifier recognises is never
// demoted, whatever else it holds. And a relation anyone can WRITE is never
// demoted, because the ability to change what a site displays is a finding
// regardless of whether the words were public already.
var contentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(title|subtitle|headline|heading)$`),
	regexp.MustCompile(`(?i)^(slug|permalink|url_key)$`),
	regexp.MustCompile(`(?i)^(body|content|excerpt|summary|description|blurb|caption)$`),
	regexp.MustCompile(`(?i)^(image|image_url|thumbnail|thumbnail_url|banner|icon|cover)$`),
	regexp.MustCompile(`(?i)^(locale|language|lang|translation)$`),
	regexp.MustCompile(`(?i)^(sort_order|position|rank|weight|display_order)$`),
	regexp.MustCompile(`(?i)^(published|published_at|is_published|visible|is_visible|draft)$`),
	regexp.MustCompile(`(?i)^(seo_title|seo_description|meta_title|meta_description)$`),
	regexp.MustCompile(`(?i)^(category|tag|tags|section|label_text)$`),
}

// structural columns say nothing either way and are excluded from the ratio, so
// a two-column content table is not dragged under the threshold by its own
// primary key.
var structuralColumn = regexp.MustCompile(
	`(?i)^(id|uuid|pk|created_at|updated_at|inserted_at|deleted_at|created_by|updated_by)$`)

// ContentColumns returns the columns that name presentation rather than people.
func ContentColumns(cols []string) []string {
	var out []string
	for _, c := range cols {
		leaf := c
		if i := strings.LastIndex(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		for _, re := range contentPatterns {
			if re.MatchString(leaf) {
				out = append(out, c)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// looksLikePublishedContent reports whether a relation is probably the site's
// own copy. See the file comment for why every condition is required.
func looksLikePublishedContent(rel Relation) bool {
	if len(rel.Sensitive) > 0 {
		return false
	}
	// Write access must have been TESTED and refused. Without -write nothing
	// was asked, and demoting then is demoting on ignorance -- the mistake this
	// whole file is written to avoid, made one level up.
	//
	// Found by reading the tool's own CSV: content_but_writable, which the
	// eval pins at high because anyone can rewrite it, printed medium in a scan
	// without -write. The eval could not see it, because the eval passes
	// -write. A world-writable page demoted to medium is precisely the
	// under-report that matters.
	if !writeProbeAnswered(rel) {
		return false
	}
	content := ContentColumns(rel.Columns)
	if len(content) < 2 {
		return false
	}
	var meaningful int
	for _, c := range rel.Columns {
		leaf := c
		if i := strings.LastIndex(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		if !structuralColumn.MatchString(leaf) {
			meaningful++
		}
	}
	if meaningful == 0 {
		return false
	}
	// A clear majority, not a plurality: a table with two content columns and
	// three of something else is not a page.
	return float64(len(content))/float64(meaningful) >= 0.6
}

// writeProbeAnswered reports whether write probing ran and produced a verdict.
// Inconclusive does not count: a probe that declined tells us nothing about
// whether the relation is writable.
func writeProbeAnswered(rel Relation) bool {
	for _, v := range []postgrest.WriteState{rel.Write, rel.Update, rel.Delete} {
		if v == postgrest.WriteBlockedRLS || v == postgrest.WriteReached {
			return true
		}
	}
	return false
}
