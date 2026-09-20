package client

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter is the scan-wide request budget.
//
// -rl used to bind only this package, while discovery, vocabulary harvesting,
// route probing and archive fetching each built their own http.Client and were
// governed by nothing. An operator setting -rl 10 to be careful with somebody
// else's project still had route discovery firing over a hundred page fetches
// at full concurrency.
//
// A courtesy control that covers part of the traffic is not a courtesy
// control. One limiter is shared by every stage, so the number the operator
// typed is the number of requests per second the target actually receives.
type Limiter struct{ l *rate.Limiter }

// NewLimiter returns a limiter for n requests per second, or nil when n <= 0,
// which means unlimited. A nil *Limiter is safe to use.
func NewLimiter(n int) *Limiter {
	if n <= 0 {
		return nil
	}
	return &Limiter{l: rate.NewLimiter(rate.Limit(n), n)}
}

// Wait blocks until the budget allows another request. Safe on a nil receiver.
func (lim *Limiter) Wait(ctx context.Context) {
	if lim == nil || lim.l == nil {
		return
	}
	_ = lim.l.Wait(ctx)
}
