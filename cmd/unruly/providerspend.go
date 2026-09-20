package main

import "github.com/eppser/unruly/scan"

// addProviderSpend records a non-Supabase backend's traffic in the ledger.
//
// Two numbers arrive and they overlap. total is everything the backend sent,
// which is what the scan summary needs; per is the breakdown a STAGED backend
// reported through scan.State, and every request in it is already inside total.
//
// Adding both is how "collections 893, providers 893" appeared in a ledger for
// a run that sent 893 requests once. A ledger that double-counts sends whoever
// reads it looking for a bottleneck that is not there, which is the same
// failure as labelling a stage wrongly -- the number is plausible and untrue.
//
// So the staged part is attributed to the stage that reported it, and only the
// remainder stays under "providers": the detection and assessment traffic that
// belongs to no stage.
func addProviderSpend(spend *ledger, total int, per []scan.StageSpend) {
	staged := 0
	for _, e := range per {
		staged += e.Requests
	}
	if rest := total - staged; rest > 0 {
		spend.add("providers", rest)
	}
	for _, e := range per {
		spend.add(e.Stage, e.Requests)
	}
}
