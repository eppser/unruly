package finding

// FixKind says WHERE a remediation is applied.
//
// Every remediation in this report begins with `--`, because the output is
// piped into psql -- by the remediation eval on every audit, and by operators
// for real. That convention is correct for a database and misleading
// everywhere else: Firestore rules live in a file that is edited and deployed,
// a signup requirement is a toggle in a console, and a leaked key is fixed by
// rotating it. Rendered identically to SQL, all three invite an operator to
// paste them into a SQL prompt, where they do nothing.
//
// Empty means unstated, and unstated must never be read as SQL. Most findings
// predate this field, and a default that guessed "database" would put console
// instructions into a script somebody executes.
type FixKind string

const (
	// FixSQL runs against the project's database.
	FixSQL FixKind = "sql"
	// FixRulesFile is edited in the repository and deployed.
	FixRulesFile FixKind = "rules-file"
	// FixConsole is a setting in the provider's dashboard.
	FixConsole FixKind = "console"
	// FixRotate is a credential that must be replaced, not reconfigured.
	FixRotate FixKind = "rotate-credential"
	// FixNone is for findings that describe the scan rather than the target.
	FixNone FixKind = "none"
)

// Where renders the destination for a reader.
//
// Phrased as a place rather than a mechanism, because the question it answers
// is "where do I go to fix this" and the answer is a console, a file, or a
// database prompt.
func (f Finding) Where() string {
	switch f.FixKind {
	case FixSQL:
		return "in the database"
	case FixRulesFile:
		return "in the rules file, then deploy"
	case FixConsole:
		return "in the provider's console"
	case FixRotate:
		return "by rotating the credential"
	case FixNone:
		return "nothing to fix on the target"
	}
	return "unstated"
}
