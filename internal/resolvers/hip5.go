package resolvers

import (
	"context"
	"errors"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"time"
)

var errHIP5NotSupported = errors.New("no supported hip-5 record found")
var errNotSynced = fmt.Errorf("error: handshake resolver not fully synced")
var errBadCNAMETarget = errors.New("bad cname target")
var errMaxDepthReached = errors.New("max depth reached")

type hip5Handler func(ctx context.Context, qname string, qtype uint16, ns *dns.NS) ([]dns.RR, error)

type HIP5Resolver struct {
	handlers map[string]hip5Handler

	rootAddr   string
	rootClient *dns.Client
	queryFunc  func(ctx context.Context, name string, qtype uint16) *resolver.DNSResult
	*resolver.Stub
	syncCheck func() bool

	// for testing
	queryExtension func(ctx context.Context, tld string) ([]*dns.NS, error)
}

func NewHIP5Resolver(recursive *resolver.Stub, rootAddr string, syncCheck func() bool) *HIP5Resolver {
	h := &HIP5Resolver{}
	h.Stub = recursive
	h.queryFunc = recursive.DefaultResolver.Query
	h.Stub.DefaultResolver.Query = h.query
	h.rootAddr = rootAddr
	h.syncCheck = syncCheck
	h.rootClient = &dns.Client{
		Net:            "udp",
		Timeout:        5 * time.Second,
		SingleInflight: true,
	}

	h.handlers = make(map[string]hip5Handler)
	h.queryExtension = h.findSupportedExtensions
	return h
}

func (h *HIP5Resolver) RegisterHandler(extension string, handler hip5Handler) {
	h.handlers[extension] = handler
}

func (h *HIP5Resolver) query(ctx context.Context, name string, qtype uint16) *resolver.DNSResult {
	return h.queryInternal(ctx, name, qtype, 0)
}

func (h *HIP5Resolver) queryInternal(ctx context.Context, name string, qtype uint16, depth int) *resolver.DNSResult {
	if synced := h.syncCheck(); !synced {
		return &resolver.DNSResult{
			Records: nil,
			Secure:  false,
			Err:     errNotSynced,
		}
	}

	name = dns.CanonicalName(name)
	tld := LastNLabels(name, 1)
	var res *resolver.DNSResult

	if tld != "eth" {
		res = h.queryFunc(ctx, name, qtype)
		if res.Err == nil || !errors.Is(res.Err, resolver.ErrServFail) {
			return res
		}
	}

	// .eth or SERVFAIL could be a HIP-5 record
	rrs, secure, errHip5 := h.attemptHIP5Resolution(ctx, tld, name, qtype, depth)
	if errHip5 == nil {
		return &resolver.DNSResult{
			Records: rrs,
			Secure:  secure,
			Err:     nil,
		}
	}

	if res != nil && errHip5 == errHIP5NotSupported {
		return res
	}

	// name uses a hip5 ns but failed to resolve
	return &resolver.DNSResult{
		Records: nil,
		Secure:  false,
		Err:     errHip5,
	}
}

func (h *HIP5Resolver) attemptHIP5Resolution(ctx context.Context, tld, qname string, qtype uint16, depth int) ([]dns.RR, bool, error) {
	if tld == "" {
		return nil, false, fmt.Errorf("no hip-5 records in root zone apex")
	}

	hip5Res, err := h.queryExtension(ctx, tld)
	if err != nil {
		return nil, false, fmt.Errorf("checking for hip-5 records failed: %w", err)
	}

	if len(hip5Res) > 0 {
		rrs, err := h.runHandlers(ctx, hip5Res, qname, qtype)
		if err != nil {
			return nil, false, fmt.Errorf("hip-5 resolution failed: %w", err)
		}

		secure := true
		if depth < 3 {
			if rrs, secure, err = h.flatten(ctx, rrs, qname, qtype, depth); err != nil {
				return nil, false, err
			}

			return filterType(rrs, qtype), secure, nil
		}

		return nil, false, fmt.Errorf("hip-5 resolution failed: %w", errMaxDepthReached)
	}

	return nil, false, errHIP5NotSupported
}

func filterType(rrs []dns.RR, qtype uint16) []dns.RR {
	var other []dns.RR

	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			other = append(other, rr)
		}
	}

	return other
}

func (h *HIP5Resolver) flatten(ctx context.Context, rrs []dns.RR, qname string, qtype uint16, depth int) ([]dns.RR, bool, error) {
	var cnames []*dns.CNAME

	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.CNAME:
			cnames = append(cnames, rr.(*dns.CNAME))
		}
	}

	if len(cnames) > 0 {
		return h.resolveCNAME(ctx, cnames, qname, qtype, depth)
	}

	return rrs, true, nil
}

func (h *HIP5Resolver) resolveCNAME(ctx context.Context, rrs []*dns.CNAME, qname string, qtype uint16, depth int) ([]dns.RR, bool, error) {
	var lastErr error
	for _, rr := range rrs {
		target := dns.CanonicalName(rr.Target)
		if target == qname {
			return nil, false, errBadCNAMETarget
		}

		res := h.queryInternal(ctx, rr.Target, qtype, depth+1)
		if res.Err != nil {
			lastErr = res.Err
			continue
		}

		return res.Records, res.Secure, nil
	}

	return nil, false, lastErr
}

func (h *HIP5Resolver) runHandlers(ctx context.Context, extensions []*dns.NS, qname string, qtype uint16) ([]dns.RR, error) {
	var lastErr error
	var res []dns.RR

	for _, rr := range extensions {
		tld := LastNLabels(rr.Ns, 1)
		if handler, ok := h.handlers[tld]; ok {
			res, lastErr = handler(ctx, qname, qtype, rr)

			if lastErr == nil {
				return res, nil
			}
		}
	}

	return nil, lastErr
}

func (h *HIP5Resolver) findSupportedExtensions(ctx context.Context, tld string) ([]*dns.NS, error) {
	tld = dns.Fqdn(tld)
	if tld == "eth." {
		return ethNS, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(tld, dns.TypeNS)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	r, _, err := h.rootClient.ExchangeContext(ctx, m, h.rootAddr)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("hip-5 lookup failed with rcode %d", r.Rcode)
	}

	var answer []*dns.NS
	for _, rr := range r.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			ending := LastNLabels(ns.Ns, 1)

			// include supported HIP-5 extensions only
			if _, ok := h.handlers[ending]; ok {
				answer = append(answer, ns)
			}
		}
	}

	return answer, nil
}
