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
	if synced := h.syncCheck(); !synced {
		return &resolver.DNSResult{
			Records: nil,
			Secure:  false,
			Err:     errNotSynced,
		}
	}

	tld := LastNLabels(name, 1)
	var res *resolver.DNSResult

	if tld != "eth" {
		res = h.queryFunc(ctx, name, qtype)
		if res.Err == nil || !errors.Is(res.Err, resolver.ErrServFail) {
			return res
		}
	}

	// .eth or SERVFAIL could be a HIP-5 record
	rrs, errHip5 := h.attemptHIP5Resolution(ctx, tld, name, qtype)
	if errHip5 == nil {
		return &resolver.DNSResult{
			Records: rrs,
			Secure:  true,
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

func (h *HIP5Resolver) attemptHIP5Resolution(ctx context.Context, tld, qname string, qtype uint16) ([]dns.RR, error) {
	if tld == "" {
		return nil, fmt.Errorf("no hip-5 records in root zone apex")
	}

	hip5Res, err := h.queryExtension(ctx, tld)
	if err != nil {
		return nil, fmt.Errorf("checking for hip-5 records failed: %w", err)
	}

	if len(hip5Res) > 0 {
		rrs, err := h.runHandlers(ctx, hip5Res, qname, qtype)
		if err != nil {
			return nil, fmt.Errorf("hip-5 resolution failed: %w", err)
		}

		return rrs, nil
	}

	return nil, errHIP5NotSupported
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
