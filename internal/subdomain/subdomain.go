// Package subdomain widens discovery to other deployments of the same
// application.
//
// The finding this exists for is the forgotten one: a staging or preview host
// that shipped the same backend, was never decommissioned, and nobody has
// looked at since. Production is what gets audited; the second deployment is
// where an anon key with looser policies is still live.
//
// It DISCOVERS and REPORTS. It does not scan what it finds, and that is a
// deliberate limit rather than an unfinished edge. A subdomain of a domain an
// operator nominated is not automatically theirs to scan -- status pages,
// documentation and support portals are routinely somebody else's
// infrastructure behind a CNAME -- and this tool's rule is that it scans what
// it was pointed at. What it produces is a list and the command to scan it,
// which leaves the decision with the person who can actually make it.
//
// Deterministic, as the scan path must be: a pinned wordlist and DNS, no
// third-party service. Certificate Transparency would find more and would make
// two runs of an unchanged domain disagree, because what CT knows changes
// underneath you.
package subdomain

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Host is a name that resolves.
type Host struct {
	Name string
	// Addrs is what it resolved to: evidence that it exists, rather than an
	// assertion that it does.
	Addrs []string
}

// Options configures enumeration.
type Options struct {
	// Domain is the registrable domain to enumerate under.
	Domain string
	// Labels are the names to try. Empty means nothing is tried.
	Labels []string
	// Concurrency bounds simultaneous lookups.
	Concurrency int
	// Resolver is exposed so tests need no network.
	Resolver func(ctx context.Context, host string) ([]string, error)
	Timeout  time.Duration
}

// Result is what enumeration established.
type Result struct {
	Hosts []Host
	// Tried is how many names were looked up, so a report can say what the
	// list covered rather than implying it covered everything.
	Tried int
}

// Enumerate resolves each candidate host under the domain.
//
// DNS only. A name that resolves exists; one that does not is not reported,
// because NXDOMAIN is the one answer here that means something definite.
func Enumerate(ctx context.Context, o Options) Result {
	if o.Domain == "" || len(o.Labels) == 0 {
		return Result{}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	resolve := o.Resolver
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]string, error) {
			var r net.Resolver
			return r.LookupHost(ctx, host)
		}
	}

	var (
		mu    sync.Mutex
		hosts []Host
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, o.Concurrency)
	for _, label := range o.Labels {
		host := label + "." + o.Domain
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			addrs, err := resolve(lookupCtx, host)
			if err != nil || len(addrs) == 0 {
				return
			}
			sort.Strings(addrs)
			mu.Lock()
			hosts = append(hosts, Host{Name: host, Addrs: addrs})
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// Sorted, because a scan of an unchanged domain must produce an unchanged
	// report, and neither goroutine completion order nor map iteration is.
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	return Result{Hosts: hosts, Tried: len(o.Labels)}
}

// RegistrableDomain reduces a host to the domain worth enumerating under.
//
// Deliberately simple: the last two labels. A public-suffix list would handle
// co.uk and its kin correctly, and pulling one in adds a dependency that has to
// be kept current to stay correct. Where this guess is wrong the effect is
// bounded -- names under a domain that is not the operator's simply fail to
// resolve -- and the operator can pass the domain directly.
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
