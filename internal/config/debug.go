package config

import (
	"errors"
	"fingertip/internal/resolvers"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
	letterBytes   = "abcdefghijklmnopqrstuvwxyz"
)

var weakRandSrc = rand.NewSource(time.Now().UnixNano())
var dnsTestClient = dns.Client{Timeout: time.Second * 5, SingleInflight: true}

type Debugger struct {
	proxyProbeDomain   string
	proxyProbeReached  bool
	dnsProbeInProgress bool
	dnsProbeErr        error
	checkCert          func() bool
	checkSynced        func() bool

	blockHeight uint64
	progress    float64

	lastPing time.Time
	sync.RWMutex
}

type DebugInfo struct {
	BlockHeight   uint64 `json:"blockHeight"`
	Progress      float64 `json:"progress"`
	ProbeURL      string `json:"proxyProbeUrl"`
	ProbeReached  bool   `json:"proxyProbeReached"`
	Syncing       bool   `json:"syncing"`
	CertInstalled bool   `json:"certInstalled"`

	DNSReachable       bool   `json:"dnsTestPassed"`
	DNSProbeInProgress bool   `json:"dnsTestInProgress"`
	DNSProbeErr        string `json:"dnsTestError"`
}

// Check if udp over port 53 is reachable
// and whether the network interferes with DNS
// responses.
//
// Test inspired by RFC8027 #3.2
// https://datatracker.ietf.org/doc/html/rfc8027#section-3.2
//
// Attempt to reach .org nameservers
// and ask it for the address of "isc.org":
//
// Some possible cases:
// 1. The request fails for some reason like times out ..etc
//    which indicates a interference
// 2. Receive a positive answer = probable interference
// 3. Receive a referral to isc.org nameservers
//    interference is unlikely
func testDNSInterference() error {
	msg := new(dns.Msg)
	msg.CheckingDisabled = true
	msg.RecursionDesired = false
	msg.SetEdns0(4096, true)
	msg.SetQuestion("isc.org.", dns.TypeA)

	r, _, err := exchangeWithRetry(msg, []string{
		"a0.org.afilias-nst.info:53",
		"b2.org.afilias-nst.org:53",
		// a2.org.afilias-nst.org
		"199.249.112.1:53",
	})
	switch {
	case err != nil:
		return fmt.Errorf("DNS request failed: %v", err)
	case r.Truncated:
		return fmt.Errorf("DNS response trunacted")
	case len(r.Answer) > 0:
		return fmt.Errorf("your network appears to intercept and redirect outgoing DNS requests")
	}

	referral := false
	hasRRSIGs := false

	for _, rr := range r.Ns {
		if rr.Header().Rrtype == dns.TypeNS && strings.EqualFold("isc.org.", rr.Header().Name) {
			referral = true
		}
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIGs = true
		}
	}

	if referral {
		if hasRRSIGs {
			return nil
		}
		return fmt.Errorf("received a response without DNSSEC signatures")
	}

	return fmt.Errorf("received unexpected referral")
}

func exchangeWithRetry(m *dns.Msg, addrs []string) (r *dns.Msg, rtt time.Duration, err error) {
	serverId := 0
	for i := 0; i < 3; i++ {
		if r, rtt, err = dnsTestClient.Exchange(m, addrs[serverId]); err == nil {
			if !r.Truncated {
				return
			}
		}
		serverId = (serverId + 1) % len(addrs)
	}

	return
}

func (d *Debugger) SetChainInfo(height uint64, progress float64) {
	d.Lock()
	defer d.Unlock()

	d.blockHeight = height
	d.progress = progress
}

func (d *Debugger) Ping() {
	d.Lock()
	defer d.Unlock()

	d.lastPing = time.Now()
}

func (d *Debugger) GetLastPing() time.Time {
	d.RLock()
	defer d.RUnlock()

	return d.lastPing
}

func (d *Debugger) SetCheckCert(c func() bool) {
	d.Lock()
	defer d.Unlock()

	d.checkCert = c
}

func (d *Debugger) SetCheckSynced(s func() bool) {
	d.Lock()
	defer d.Unlock()

	d.checkSynced = s
}

func (d *Debugger) NewProbe() {
	d.Lock()
	d.proxyProbeReached = false
	d.proxyProbeDomain = randString(50)
	d.dnsProbeInProgress = true
	d.Unlock()

	go func() {
		err := testDNSInterference()
		d.Lock()
		d.dnsProbeInProgress = false
		d.dnsProbeErr = err
		d.Unlock()
	}()
}

func (d *Debugger) GetInfo() DebugInfo {
	d.RLock()
	defer d.RUnlock()

	var err string
	if d.dnsProbeErr != nil {
		err = d.dnsProbeErr.Error()
	}
	return DebugInfo{
		BlockHeight:        d.blockHeight,
		Progress:           d.progress,
		ProbeURL:           "http://" + d.proxyProbeDomain,
		ProbeReached:       d.proxyProbeReached,
		Syncing:            d.checkSynced != nil && !d.checkSynced(),
		CertInstalled:      d.checkCert != nil && d.checkCert(),
		DNSReachable:       !d.dnsProbeInProgress && d.dnsProbeErr == nil,
		DNSProbeErr:        err,
		DNSProbeInProgress: d.dnsProbeInProgress,
	}
}

func (d *Debugger) GetDNSProbeMiddleware() resolvers.QueryMiddlewareFunc {
	return func(qname string, qtype uint16) (bool, *resolver.DNSResult) {
		d.RLock()
		probeName := d.proxyProbeDomain
		skipName := d.proxyProbeReached || len(probeName) != len(qname)
		d.RUnlock()

		if skipName {
			return false, nil
		}

		if strings.EqualFold(probeName, qname) {
			d.Lock()
			d.proxyProbeReached = true
			d.Unlock()

			return true, &resolver.DNSResult{
				Records: nil,
				Secure:  false,
				Err:     errors.New(""),
			}
		}

		return false, nil
	}
}

// source: http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func randString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)

	for i, cache, remain := n-1, weakRandSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = weakRandSrc.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
