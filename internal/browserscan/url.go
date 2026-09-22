package browserscan

import (
	"regexp"
	"strings"
)

// reHost is a hostname with at least one dot and a plausible TLD, or
// localhost with an optional port.
var reHost = regexp.MustCompile(`^(?:localhost(?::\d{1,5})?|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,63})(?::\d{1,5})?$`)

// NormaliseSite turns what a person types into an address, or returns "" when
// it is not one.
//
// People type what they read off a business card. The form used to reject
// "myapp.lovable.app" for having no scheme, which is a correct observation and
// a useless one: they typed their own address and were told it was not a web
// address.
//
// http is NOT upgraded to https. Someone who typed http meant it, and quietly
// scanning a different origin than the one they named would make the report
// about a system they did not ask about.
func NormaliseSite(in string) string {
	s := strings.TrimSpace(in)
	if s == "" {
		return ""
	}
	// A scheme typed with one slash is still an intent, and a common slip.
	if m := regexp.MustCompile(`^(https?):/([^/])`).FindStringSubmatch(s); m != nil {
		s = m[1] + "://" + s[len(m[1])+2:]
	}
	scheme := ""
	switch {
	case strings.HasPrefix(strings.ToLower(s), "https://"):
		scheme, s = "https://", s[8:]
	case strings.HasPrefix(strings.ToLower(s), "http://"):
		scheme, s = "http://", s[7:]
	case strings.Contains(s, "://"):
		// Some other scheme entirely. Not something this scans.
		return ""
	case strings.Contains(s, ":") && !strings.Contains(s, "."):
		// javascript:, mailto: and friends.
		return ""
	default:
		scheme = "https://"
	}
	host, path := s, ""
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		host, path = s[:i], s[i:]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if !reHost.MatchString(host) {
		return ""
	}
	// A trailing bare slash carries nothing and makes two spellings of one
	// address, which would show up as two different scans.
	if path == "/" {
		path = ""
	}
	return scheme + host + path
}
