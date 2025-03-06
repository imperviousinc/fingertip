package resolvers

import (
	"context"
	"errors"
	"fingertip/internal/resolvers/dnssec"
	"fmt"
	"github.com/randomlogin/sane/resolver"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

var errNotSynced = fmt.Errorf("error: handshake resolver not fully synced")
var errHIP5NotSupported = errors.New("no supported hip-5 record found")
var errBadCNAMETarget = errors.New("bad cname target")
var errMaxDepthReached = errors.New("max depth reached")

type hip5Handler func(ctx context.Context, qname string, qtype uint16, ns *dns.NS) ([]dns.RR, error)
type QueryMiddlewareFunc func(qname string, qtype uint16) (bool, *resolver.DNSResult)

type HIP5Resolver struct {
	handlers      map[string]hip5Handler
	onBeforeQuery QueryMiddlewareFunc

	// for sending queries to a trusted root
	// to get hip-5 addresses
	rootAddr   string
	rootClient *dns.Client
	syncCheck  func() bool
	tldCache   *cache
	keyCache   *cache

	// stub resolver with no hip-5 support
	stubQuery func(ctx context.Context, name string, qtype uint16) *resolver.DNSResult
	*resolver.Stub

	// hip-5 NS recursion
	nsClient *dns.Client

	// needed for tests
	exchangeRoot func(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
	exchange     func(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
}

func NewHIP5Resolver(stub *resolver.Stub, rootAddr string, syncCheck func() bool) *HIP5Resolver {
	h := &HIP5Resolver{}
	h.Stub = stub
	h.syncCheck = syncCheck
	h.handlers = make(map[string]hip5Handler)
	h.tldCache = newCache(30)
	h.keyCache = newCache(200)

	// using the same query function used by stub
	// to benefit from caching
	h.stubQuery = stub.DefaultResolver.Query
	h.Stub.DefaultResolver.Query = h.query

	h.rootAddr = rootAddr
	h.rootClient = &dns.Client{
		Net:            "udp",
		Timeout:        2 * time.Second,
		SingleInflight: true,
	}
	h.exchangeRoot = h.rootClient.ExchangeContext

	h.nsClient = &dns.Client{
		Net:            "udp",
		Timeout:        4 * time.Second,
		SingleInflight: true,
	}
	h.exchange = h.nsClient.ExchangeContext

	return h
}

func (h *HIP5Resolver) RegisterHandler(extension string, handler hip5Handler) {
	h.handlers[extension] = handler
}

func (h *HIP5Resolver) SetQueryMiddleware(m QueryMiddlewareFunc) {
	h.onBeforeQuery = m
}

func (h *HIP5Resolver) query(ctx context.Context, name string, qtype uint16) *resolver.DNSResult {
	if h.onBeforeQuery != nil {
		if ok, res := h.onBeforeQuery(name, qtype); ok {
			return res
		}
	}

	return h.queryInternal(ctx, name, qtype, 0)
}

func (h *HIP5Resolver) checkTLDCache(tld string) ([]*dns.NS, bool) {
	e, ok := h.tldCache.get(tld)
	if !ok {
		return nil, false
	}

	if time.Now().After(e.ttl) {
		h.tldCache.remove(tld)
		return nil, false
	}

	return e.msg.([]*dns.NS), true
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
	tld := dns.Fqdn(LastNLabels(name, 1))
	var res *resolver.DNSResult

	known := false
	if tld == "eth." {
		known = true
	} else {
		rrs, ok := h.checkTLDCache(tld)
		known = ok && len(rrs) > 0
	}

	if !known {
		res = h.stubQuery(ctx, name, qtype)
		if res.Err == nil || !errors.Is(res.Err, resolver.ErrServFail) {
			return res
		}
	}

	// Either its a known HIP-5 tld
	// or stub couldn't resolve it
	rrs, secure, errHip5 := h.attemptHIP5Resolution(ctx, tld, name, qtype, depth)
	if errHip5 == nil {
		return &resolver.DNSResult{
			Records: rrs,
			Secure:  secure,
			Err:     nil,
		}
	}

	// return the original failed response
	// from the stub unmodified
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
	if tld == "." {
		return nil, false, fmt.Errorf("no hip-5 records in root zone apex")
	}

	hip5Res, err := h.lookupExtensions(ctx, tld)
	if err != nil {
		return nil, false, fmt.Errorf("checking for hip-5 records failed: %w", err)
	}

	if len(hip5Res) > 0 {
		rrs, err := h.runHandlers(ctx, hip5Res, qname, qtype)
		if err != nil {
			return nil, false, fmt.Errorf("hip-5 resolution failed: %w", err)
		}

		secure := true
		if rrs, secure, err = h.flatten(ctx, rrs, nil, true, qname, qtype, depth); err != nil {
			return nil, false, err
		}

		return filterType(rrs, qtype), secure, nil
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

func (h *HIP5Resolver) flatten(ctx context.Context, rrs []dns.RR, extra []dns.RR, secure bool, qname string, qtype uint16, depth int) ([]dns.RR, bool, error) {
	if depth > 10 {
		return nil, false, fmt.Errorf("hip-5 resolution failed: %w", errMaxDepthReached)
	}

	var cnames []*dns.CNAME
	var ns []*dns.NS
	var ds []dns.RR

	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.CNAME:
			cnames = append(cnames, rr.(*dns.CNAME))
		case *dns.NS:
			ns = append(ns, rr.(*dns.NS))
		case *dns.DS:
			ds = append(ds, rr)
		}
	}

	// response isn't secure
	// remove any DS records
	if !secure {
		ds = nil
	}

	if len(cnames) > 0 {
		return h.resolveCNAME(ctx, cnames, qname, qtype, depth)
	}

	if len(ns) > 0 {
		return h.resolveNS(ctx, ns, ds, extra, qname, qtype, depth)
	}

	if len(ds) > 0 {
		return nil, false, errors.New("error DS with no delegations")
	}

	return rrs, secure, nil
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

func getDelegatedName(rrs []*dns.NS, ds []dns.RR, qname string) (string, error) {
	var zone string
	// verify that all delegations have
	// the same owner name
	for _, rr := range rrs {
		if zone == "" {
			zone = dns.CanonicalName(rr.Header().Name)
			continue
		}

		if !strings.EqualFold(zone, rr.Header().Name) {
			return "", fmt.Errorf("got NS owner name = %s, want = %s", rr.Header().Name, zone)
		}
	}

	// qname must be a child of the zone
	if !dns.IsSubDomain(zone, qname) {
		return "", fmt.Errorf("qname %s isn't a child of %s", qname, zone)
	}

	// DS owner name
	// must match as well
	for _, rr := range ds {
		if !strings.EqualFold(zone, rr.Header().Name) {
			return "", fmt.Errorf("got DS owner name = %s, want %s", rr.Header().Name, zone)
		}
	}

	return zone, nil
}

func (h *HIP5Resolver) lookupNSAddr(ctx context.Context, rr *dns.NS, extra []dns.RR) ([]net.IP, error) {
	if rr == nil {
		return nil, fmt.Errorf("nil rr")
	}

	var ips []net.IP

	for _, glue := range extra {
		if !strings.EqualFold(glue.Header().Name, rr.Ns) {
			continue
		}

		switch t := glue.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}

	if len(ips) != 0 {
		return ips, nil
	}

	var err error
	if ips, _, err = h.LookupIP(ctx, "ip", rr.Ns); err != nil {
		return nil, err
	}

	return ips, nil
}

func (h *HIP5Resolver) resolveNS(ctx context.Context, rrs []*dns.NS, ds []dns.RR, extra []dns.RR, qname string, qtype uint16, depth int) ([]dns.RR, bool, error) {
	delegatedName, err := getDelegatedName(rrs, ds, qname)
	if err != nil {
		return nil, false, err
	}

	var msg *dns.Msg
	var nsIPs []net.IP

	for _, rr := range rrs {
		if nsIPs, err = h.lookupNSAddr(ctx, rr, extra); err != nil {
			continue
		}
		if msg, err = h.exchangeNS(ctx, nsIPs, qname, qtype); err == nil {
			break
		}
	}

	if msg == nil {
		return nil, false, fmt.Errorf("failed to read message")
	}

	var keys map[uint16]*dns.DNSKEY

	if len(ds) > 0 {
		if keys, err = h.queryDNSKeys(ctx, nsIPs, ds, delegatedName); err != nil {
			return nil, false, fmt.Errorf("dnskey error: %v", err)
		}
	}

	signed := len(keys) > 0
	var secure bool

	if signed {
		if secure, err = dnssec.Verify(msg, delegatedName, qname, qtype, keys, time.Now(), 2048); err != nil {
			return nil, false, fmt.Errorf("dnssec verify error: %v", err)
		}
	}

	// limit recursion depth
	depth++

	if len(msg.Answer) > 0 {
		return h.flatten(ctx, msg.Answer, nil, secure, qname, qtype, depth)
	}

	return h.flatten(ctx, msg.Ns, msg.Extra, secure, qname, qtype, depth)
}

func (h *HIP5Resolver) queryDNSKeys(ctx context.Context, ips []net.IP, ds []dns.RR, delegatedName string) (map[uint16]*dns.DNSKEY, error) {
	if entry, ok := h.keyCache.get(delegatedName); ok {
		if time.Now().Before(entry.ttl) {
			msg := new(dns.Msg)
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = entry.msg.([]dns.RR)

			keys, err := dnssec.VerifyDNSKeys(delegatedName, msg, ds, time.Now(), 2048)
			if err == nil {
				return keys, nil
			}
		}
		h.keyCache.remove(delegatedName)
	}

	msg, err := h.exchangeNS(ctx, ips, delegatedName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	keys, err := dnssec.VerifyDNSKeys(delegatedName, msg, ds, time.Now(), 2048)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}

	h.keyCache.set(delegatedName, &entry{
		msg: msg.Answer,
		ttl: time.Now().Add(getTTL(msg.Answer)),
	})

	return keys, nil
}

func (h *HIP5Resolver) exchangeNS(ctx context.Context, ips []net.IP, qname string, qtype uint16) (res *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	m.CheckingDisabled = true
	m.SetEdns0(4096, true)

	for _, ip := range ips {
		if res, _, err = h.exchange(ctx, m, ip.String()+":53"); err != nil {
			continue
		}

		if res.Truncated {
			err = errors.New("response truncated")
			continue
		}

		return
	}

	return
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

func (h *HIP5Resolver) lookupExtensions(ctx context.Context, tld string) ([]*dns.NS, error) {
	if !dns.IsFqdn(tld) {
		return nil, errors.New("tld must be fqdn")
	}

	if tld == "eth." {
		return ethNS, nil
	}

	if rrs, ok := h.checkTLDCache(tld); ok {
		return rrs, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(tld, dns.TypeNS)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	r, _, err := h.exchangeRoot(ctx, m, h.rootAddr)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("hip-5 lookup failed with rcode %d", r.Rcode)
	}

	if r.Truncated {
		return nil, errors.New("response truncated")
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

	// only cache positive answers
	if len(answer) > 0 {
		ttl := getTTL(nsToRR(answer))
		h.tldCache.set(tld, &entry{
			msg: answer,
			ttl: time.Now().Add(ttl),
		})
	}

	return answer, nil
}
