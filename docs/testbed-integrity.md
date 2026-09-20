# Verifying the testbed was not damaged

The reference testbed is a LIVE site with its own scheduled jobs. Its documented
row counts are a snapshot, not an invariant, and using them as a damage detector
gives the wrong answer in both directions.

## What happened

The counts recorded in this project's standing constraints are

    agent_runs 465, survival_series 171, signatory_submissions 124,
    daily_snapshot 104, sessions 17, exploit_rate_series 9, zero_day_series 9

Checked mid-session, `agent_runs` read 468 and `daily_snapshot` read 105. Three
rows and one row appeared that the constraints do not account for.

They were not ours. The newest rows are

    2026-08-17T06:31 graph_recomputer completed
    2026-08-17T06:28 news_researcher  completed
    2026-08-17T06:25 cve_updater      completed

a scheduled batch, after a gap since 2026-08-14. Every one of the 468 rows
belongs to one of the application's own three agents, and a count of rows with
a null `agent_name` -- the shape an empty INSERT probe leaves -- returns zero.

## Why absolute counts are the wrong check

A count that moved tells you something changed. It does not tell you WHO changed
it, and on a live target the answer is usually "the target". That makes the
check wrong twice:

- **False alarm.** A future run sees 468 against a documented 465 and concludes
  the scanner wrote rows. The likely response -- disabling a write probe, or
  distrusting a whole class of finding -- is a real cost paid for the site
  doing its job.
- **False assurance, which is worse.** A probe row lands in a table the
  application also writes to, and the count moves by an amount nobody can
  attribute. "The app must have done it" is available as an explanation every
  single time.

## What to check instead

Look for rows this scanner would have created, not for a number:

    -- rows with no value in a column the application always fills
    GET /rest/v1/<relation>?select=*&<required_column>=is.null&limit=0
        Prefer: count=exact

    -- anything carrying the probe marker
    GET /storage/v1/object/list/<bucket>   -> objects named unruly_write_probe_*

The empty INSERT is the probe most likely to land, and it lands with every
optional column unset -- which is exactly what an application row never looks
like. That asymmetry is the signal, and it survives the target writing to
itself.

Where a probe row DID land and could not be removed, the scanner already says
so: `unruly-probe-row-left-behind` and `unruly-probe-object-left-behind` are
emitted at high severity for that reason, and the threat model gives them their
own row -- residue is the scanner's doing, not the project's, and hiding it
would be the least defensible silence in the tool.

## Standing result

Every check so far shows no residue on the testbed from this project's scans,
including the two `-write -no-residue` runs which were verified against the
counts immediately before and after, while the counts were still a valid check.
