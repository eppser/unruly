package finding

import (
	"html/template"
	"io"
	"sort"
	"strings"
)

// HTML packages a report so it can be handed to somebody else.
//
// The SQL this tool emits is the part worth sharing -- it closes the findings
// it reports, and the remediation eval executes every statement of it against a
// real database on every audit. Until now it was only reachable by reading
// -fix output out of a terminal. This puts it behind one button.
//
// One self-contained file, no network: a report that fetches a stylesheet
// leaks the fact that it was opened, and a report that needs the internet is
// useless in the room where it usually gets read.
//
// Sampled rows are NOT included, for the same reason the CSV omits them: this
// is the artefact most likely to be forwarded, and the samples are the
// credentials the findings are about. The evidence that survives is the
// replayable request, which proves the finding without carrying the data.

type htmlFinding struct {
	Severity, ID, Resource, Protocol string
	Matched, Description, Reason     string
	Request                          string
	Rows                             int
	Fix                              string
	Plain                            string
}

type htmlReport struct {
	Target    string
	Generated string
	Counts    []htmlCount
	Findings  []htmlFinding
	AllSQL    string
	Plain     string
}

type htmlCount struct {
	Label string
	N     int
}

// WriteHTML renders the whole report. target and generated are passed in
// rather than discovered so the output is a pure function of its inputs, which
// is what lets the determinism eval diff two runs.
func WriteHTML(out io.Writer, target, generated string, fs []Finding) error {
	sorted := append([]Finding{}, fs...)
	Sort(sorted)

	counts := map[Severity]int{}
	var rows []htmlFinding
	for _, f := range sorted {
		counts[f.Severity]++
		fix := strings.TrimSpace(f.Remediation)
		rows = append(rows, htmlFinding{
			Severity: f.Severity.String(), ID: f.ID, Resource: f.Resource,
			Protocol: f.Protocol, Matched: f.Matched, Description: f.Description,
			Reason: f.Evidence.Reason, Request: f.Evidence.Request,
			Rows: f.Evidence.Rows, Fix: fix,
		})
	}

	var order []htmlCount
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if n := counts[s]; n > 0 {
			order = append(order, htmlCount{s.String(), n})
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return false }) // already worst-first

	return htmlTemplate.Execute(out, htmlReport{
		Target: target, Generated: generated, Counts: order, Findings: rows,
		// One consolidated plan rather than every finding's block concatenated.
		// A relation that is readable and insertable and updatable and
		// deletable produced four blocks repeating the same ALTER TABLE, and a
		// fix nobody reads is a fix nobody applies.
		AllSQL: FixPlan(sorted), Plain: Plain(sorted),
	})
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>unruly — {{.Target}}</title>
<style>
 :root{--bg:#fff;--fg:#14161a;--mut:#5b6470;--line:#e3e6ea;--card:#f7f8fa;
   --critical:#b3001b;--high:#c2410c;--medium:#a16207;--low:#3f6212;--info:#475569}
 @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--mut:#9aa4b2;
   --line:#252a31;--card:#161a20;--critical:#ff6b6b;--high:#ffa04d;--medium:#ffd166;
   --low:#a3e635;--info:#94a3b8}}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
   font:15px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}
 .wrap{max-width:1040px;margin:0 auto;padding:32px 20px 72px}
 h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px}
 .sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .counts{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
 .pill{border:1px solid var(--line);border-radius:999px;padding:3px 11px;font-size:13px}
 .f{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:10px;
   background:var(--card)}
 .fh{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
 .sev{font-weight:650;text-transform:uppercase;font-size:11px;letter-spacing:.06em}
 .res{font-weight:600} .id{color:var(--mut);font-size:12px}
 .desc{margin:8px 0 0;color:var(--fg)}
 .why{color:var(--mut);font-size:13px;margin-top:6px}
 pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;
   overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:10px 0 0}
 button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);
   border-radius:8px;padding:7px 14px;cursor:pointer}
 button:hover{border-color:var(--mut)}
 .critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}
 .low{color:var(--low)}.info{color:var(--info)}
</style></head><body><div class="wrap">
<h1>unruly</h1>
<div class="sub">{{.Target}} — {{.Generated}}</div>
<div class="counts">{{range .Counts}}<span class="pill {{.Label}}">{{.Label}} {{.N}}</span>{{end}}</div>
{{if .Plain}}<h2>In plain words</h2><pre>{{.Plain}}</pre>{{end}}
{{if .AllSQL}}<h2>Fix it</h2>
<p class="sub">Every statement below is executed against a live database by this
project's own remediation test, on every audit. Read it before you run it.</p>
<button id="copy">Copy all SQL</button>
<pre id="sql">{{.AllSQL}}</pre>{{end}}
<h2>Findings</h2>
{{range .Findings}}<div class="f">
 <div class="fh"><span class="sev {{.Severity}}">{{.Severity}}</span>
  <span class="res">{{.Resource}}</span><span class="id">{{.ID}}</span>
  {{if .Rows}}<span class="id">{{.Rows}} rows</span>{{end}}</div>
 <p class="desc">{{.Description}}</p>
 {{if .Reason}}<div class="why">{{.Reason}}</div>{{end}}
 {{if .Request}}<pre>{{.Request}}</pre>{{end}}
</div>{{end}}
</div>
<script>
 var b=document.getElementById('copy');
 if(b){b.addEventListener('click',function(){
   var t=document.getElementById('sql').textContent;
   navigator.clipboard.writeText(t).then(function(){
     b.textContent='Copied';setTimeout(function(){b.textContent='Copy all SQL'},1600);
   },function(){
     // Clipboard access is refused on file:// in some browsers. Selecting the
     // text is worse than copying it and much better than a button that
     // silently does nothing.
     var r=document.createRange();r.selectNodeContents(document.getElementById('sql'));
     var s=getSelection();s.removeAllRanges();s.addRange(r);
     b.textContent='Selected — press Cmd/Ctrl+C';
   });
 });}
</script></body></html>
`))
