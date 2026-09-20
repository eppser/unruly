package routes

import "testing"

// The rule is disagreement within a family, not "a route answered 200".
// These cases encode the difference.
func TestFamilyInconsistency(t *testing.T) {
	cases := []struct {
		name string
		f    Family
		want bool
	}{
		{
			// The real shape on the reference target: four /api/admin/* routes
			// require a token, /api/admin/logs returns internal pipeline data.
			name: "one open sibling among several protected",
			f: Family{Prefix: "/api/admin",
				Protected: []string{"/api/admin/review", "/api/admin/submissions", "/api/admin/reorder"},
				Open:      []string{"/api/admin/logs"}},
			want: true,
		},
		{
			name: "entirely public family is a design choice",
			f:    Family{Prefix: "/api", Open: []string{"/api/health", "/api/stats"}},
			want: false,
		},
		{
			name: "entirely protected family is correct",
			f: Family{Prefix: "/api/admin",
				Protected: []string{"/api/admin/a", "/api/admin/b"}},
			want: false,
		},
		{
			// A single protected sibling is too weak to call a convention.
			name: "one protected, one open proves nothing",
			f: Family{Prefix: "/api/x",
				Protected: []string{"/api/x/a"}, Open: []string{"/api/x/b"}},
			want: false,
		},
	}
	for _, tc := range cases {
		if got := tc.f.Inconsistent(); got != tc.want {
			t.Errorf("%s: Inconsistent() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRouteClassification(t *testing.T) {
	if !(Route{GET: 401}).RequiresAuth("GET") {
		t.Error("401 must count as requiring auth")
	}
	if !(Route{POST: 403}).RequiresAuth("POST") {
		t.Error("403 must count as requiring auth")
	}
	if (Route{GET: 405, POST: 400}).RequiresAuth("GET") ||
		(Route{GET: 405, POST: 400}).RequiresAuth("POST") {
		t.Error("405/400 are not auth decisions")
	}
	if !(Route{GET: 200}).AnonymouslyOpen("GET") {
		t.Error("200 must count as open")
	}
	// A route that only accepts POST answers 405 to GET; that is not an
	// anonymous success and must not be grouped as open.
	if (Route{GET: 405, POST: 401}).AnonymouslyOpen("GET") {
		t.Error("405 is not an anonymous success")
	}
}

func TestGroupIntoFamilies(t *testing.T) {
	fs := groupIntoFamilies([]Route{
		// POST being protected must not hide that GET is open.
		{Path: "/api/admin/logs", GET: 200, POST: 401},
		{Path: "/api/admin/review", GET: 401, POST: 401},
		{Path: "/api/admin/submissions", GET: 403, POST: 401},
		{Path: "/api/dashboard", GET: 200},
	})
	var admin *Family
	for i := range fs {
		if fs[i].Prefix == "/api/admin" && fs[i].Method == "GET" {
			admin = &fs[i]
		}
	}
	if admin == nil {
		t.Fatal("expected an /api/admin family")
	}
	if len(admin.Protected) != 2 || len(admin.Open) != 1 {
		t.Fatalf("grouping wrong: protected=%v open=%v", admin.Protected, admin.Open)
	}
	if !admin.Inconsistent() {
		t.Error("this family must be flagged")
	}
}

func TestFamiliesNeverCombineMethods(t *testing.T) {
	fs := groupIntoFamilies([]Route{
		{Path: "/api/admin/open", GET: 200, POST: 405},
		{Path: "/api/admin/a", GET: 405, POST: 401},
		{Path: "/api/admin/b", GET: 405, POST: 403},
	})
	for _, f := range fs {
		if f.Inconsistent() {
			t.Fatalf("GET success was combined with POST refusals: %+v", f)
		}
	}
}

func TestConventionalPublicLeavesDoNotManufactureAnInconsistency(t *testing.T) {
	fs := groupIntoFamilies([]Route{
		{Path: "/crm/customers", GET: 401},
		{Path: "/crm/accounts", GET: 403},
		{Path: "/crm/health", GET: 200},
		{Path: "/crm/guide", GET: 200},
	})
	for _, f := range fs {
		if f.Inconsistent() {
			t.Fatalf("intentional operational/docs route became an auth bug: %+v", f)
		}
	}
	if !conventionalPublicPath("/crm/health") || !conventionalPublicPath("/crm/guide") ||
		conventionalPublicPath("/crm/customers") {
		t.Fatal("public-leaf discriminator does not match its narrow contract")
	}
}

func TestDynamicSegmentsAreNotProbed(t *testing.T) {
	for _, p := range []string{"/api/user/[id]", "/api/item/{slug}", "/api/post/:id"} {
		if !reDynamic.MatchString(p) {
			t.Errorf("%q should be recognised as dynamic and skipped", p)
		}
	}
	if reDynamic.MatchString("/api/admin/logs") {
		t.Error("static paths must not be treated as dynamic")
	}
}

func TestPrivilegedPrefixRaisesSeverity(t *testing.T) {
	if !looksPrivileged("/api/admin") {
		t.Error("admin prefix should raise severity")
	}
	if looksPrivileged("/api/posts") {
		t.Error("ordinary prefix should not")
	}
}
