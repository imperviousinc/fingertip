package dnssec

// dnssec validation utilities loosely based on
// https://gitlab.nic.cz/knot/knot-resolver/-/tree/master/lib/dnssec
// https://github.com/semihalev/sdns

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"math/big"
	"strings"
	"time"
)

var (
	ErrNoDNSKEY               = errors.New("no valid dnskey records found")
	ErrBadDS                  = errors.New("DS record doesn't match zone name")
	ErrNoSignatures           = errors.New("no rrsig records for zone that should be signed")
	ErrMissingDNSKEY          = errors.New("no matching dnskey found for rrsig records")
	ErrSignatureBailiwick     = errors.New("rrsig record out of bailiwick")
	ErrInvalidSignaturePeriod = errors.New("incorrect signature validity period")
	ErrMissingSigned          = errors.New("signed records are missing")
)

// supported dnssec algorithms weaker/unsupported algorithms are treated as unsigned
var supportedAlgorithms = []uint8{dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519}
var supportedDigests = []uint8{dns.SHA256, dns.SHA384}

// DefaultMinRSAKeySize the minimum RSA key size
// that can be used to securely verify messages
const DefaultMinRSAKeySize = 2048

func filterDS(zone string, dsSet []dns.RR) ([]*dns.DS, error) {
	if !dns.IsFqdn(zone) {
		return nil, fmt.Errorf("zone must be fqdn")
	}

	type dsKey struct {
		keyTag    uint16
		algorithm uint8
	}

	supported := make(map[dsKey]*dns.DS)
	for _, rr := range dsSet {
		if !strings.EqualFold(zone, rr.Header().Name) {
			return nil, ErrBadDS
		}

		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}

		if !isAlgorithmSupported(ds.Algorithm) ||
			!isDigestSupported(ds.DigestType) {
			continue
		}

		key := dsKey{
			keyTag:    ds.KeyTag,
			algorithm: ds.Algorithm,
		}

		// pick strongest supported digest type
		if ds2, ok := supported[key]; ok {
			if ds2.DigestType >= ds.DigestType {
				continue
			}
		}

		supported[key] = ds
	}

	var values []*dns.DS
	for _, rr := range supported {
		values = append(values, rr)
	}

	return values, nil
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func shouldDowngradeKey(k *dns.DNSKEY, minKeySize int) bool {
	if k.Algorithm != dns.RSASHA512 && k.Algorithm != dns.RSASHA256 {
		return false
	}

	// extracted from miekg/dns to check if
	// an exponent is supported by the crypto package
	keybuf, err := fromBase64([]byte(k.PublicKey))
	if err != nil {
		return false
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return false
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 {
		// Exponent larger than supported by the crypto package
		return true
	}

	if explen == 0 || keybuf[keyoff] == 0 {
		// Exponent empty, or contains prohibited leading zero.
		return false
	}

	modoff := keyoff + int(explen)
	modlen := len(keybuf) - modoff
	if modlen < 64 || modlen > 512 || keybuf[modoff] == 0 {
		// Modulus is too small, large, or contains prohibited leading zero.
		return false
	}

	pubkey := new(rsa.PublicKey)

	var expo uint64
	// The exponent of length explen is between keyoff and modoff.
	for _, v := range keybuf[keyoff:modoff] {
		expo <<= 8
		expo |= uint64(v)
	}
	if expo > 1<<31-1 {
		// Larger exponent than supported by the crypto package.
		return true
	}

	pubkey.E = int(expo)
	pubkey.N = new(big.Int).SetBytes(keybuf[modoff:])

	// downgrade if using a weak key size
	if pubkey.N.BitLen() < minKeySize {
		return true
	}

	return false
}

func isAlgorithmSupported(algo uint8) bool {
	for _, curr := range supportedAlgorithms {
		if algo == curr {
			return true
		}
	}

	return false
}

func isDigestSupported(digest uint8) bool {
	for _, curr := range supportedDigests {
		if digest == curr {
			return true
		}
	}

	return false
}

func VerifyDNSKeys(zone string, msg *dns.Msg, parentDSSet []dns.RR, t time.Time, minKeySize int) (map[uint16]*dns.DNSKEY, error) {
	var err error
	var dsSet []*dns.DS

	if dsSet, err = filterDS(zone, parentDSSet); err != nil {
		return nil, err
	}

	if len(dsSet) == 0 {
		return nil, nil
	}

	matchingKeys := make(map[uint16]*dns.DNSKEY)

	for _, ds := range dsSet {
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype != dns.TypeDNSKEY {
				continue
			}

			// simple checks
			key := rr.(*dns.DNSKEY)
			if key.Protocol != 3 {
				continue
			}
			if key.Flags != 256 && key.Flags != 257 {
				continue
			}
			if key.Algorithm != ds.Algorithm {
				continue
			}

			tag := key.KeyTag()
			if tag != ds.KeyTag {
				continue
			}

			dsFromKey := key.ToDS(ds.DigestType)
			if dsFromKey == nil {
				continue
			}

			if !strings.EqualFold(dsFromKey.Digest, ds.Digest) {
				continue
			}

			// we have a valid key
			matchingKeys[tag] = key

		}
	}

	if len(matchingKeys) == 0 {
		return nil, ErrNoDNSKEY
	}

	validKeys := make(map[uint16]*dns.DNSKEY)

	for _, key := range matchingKeys {
		if !shouldDowngradeKey(key, minKeySize) {
			validKeys[key.KeyTag()] = key
		}
	}

	if len(validKeys) == 0 {
		return nil, nil
	}

	// verifySignatures will clean up the answer
	// section in the msg with only the valid rr sets
	secure, err := verifySignatures(zone, zone, msg, validKeys, t, minKeySize)
	if err != nil {
		return nil, err
	}

	if !secure {
		return nil, nil
	}

	if len(msg.Answer) == 0 {
		return nil, ErrNoDNSKEY
	}

	trustedKeys := make(map[uint16]*dns.DNSKEY)
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			key := rr.(*dns.DNSKEY)
			trustedKeys[key.KeyTag()] = key
		}
	}

	return trustedKeys, nil
}

// IsSubDomainStrict checks if child is indeed a child of the parent. If child and parent
// are the same domain false is returned.
func IsSubDomainStrict(parent, child string) bool {
	parentLabels := dns.CountLabel(parent)
	childLabels := dns.CountLabel(child)

	return dns.CompareDomainName(parent, child) == parentLabels &&
		childLabels > parentLabels
}

// verifySignatures verifies signatures in a message
// and removes any invalid rr sets
func verifySignatures(zone string, qname string, msg *dns.Msg, trustedKeys map[uint16]*dns.DNSKEY, t time.Time, minKeySize int) (bool, error) {
	type rrsetId struct {
		owner string
		t     uint16
	}

	downgrade := false
	var lastErr error

	sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}

	// clear sections
	// will fill those as we validate
	msg.Answer = []dns.RR{}
	msg.Ns = []dns.RR{}
	msg.Extra = []dns.RR{}
	var delegations []dns.RR

	for sectionId, section := range sections {
		if len(section) == 0 {
			continue
		}

		verifiedSets := make(map[rrsetId]struct{})

		// Look for all signatures some may be invalid
		// we only need a single valid signature per RRSet
		// this will be used to "discover" covered sets
		// if some records don't have a signature they must be
		// removed from the section
		for _, rr := range section {
			// keep delegations since they are unsigned
			// they will be verified later
			if sectionId == 1 /* authority section */ &&
				rr.Header().Rrtype == dns.TypeNS {
				// must be in bailiwick and within qname
				if IsSubDomainStrict(zone, rr.Header().Name) &&
					dns.IsSubDomain(rr.Header().Name, qname) {
					delegations = append(delegations, rr)
				}

				continue
			}

			if rr.Header().Rrtype == dns.TypeRRSIG {
				if sig, ok := rr.(*dns.RRSIG); ok {
					sigName := dns.CanonicalName(sig.Header().Name)

					// if another sig verified the set ignore this one
					if _, ok := verifiedSets[rrsetId{sigName, sig.TypeCovered}]; ok {
						continue
					}

					// we don't care about signatures not in bailiwick
					if !dns.IsSubDomain(zone, sigName) {
						lastErr = ErrSignatureBailiwick
						continue
					}

					// look for any valid keys for this signature
					key, ok := trustedKeys[sig.KeyTag]
					// RFC4035 5.3.1 bullet 2 signer name must match the name of the zone
					if !ok || !strings.EqualFold(key.Header().Name, sig.SignerName) {
						lastErr = ErrMissingDNSKEY
						continue
					}

					// uses a key that can be downgraded
					// it should fallback to insecure
					// if there are no other secure
					// signatures that can verify the set
					if shouldDowngradeKey(key, minKeySize) {
						downgrade = true
						continue
					}

					// extract set covered by signature
					rrset := extractRRSet(section, sig.Header().Name, sig.TypeCovered)
					if len(rrset) == 0 {
						lastErr = ErrMissingSigned
						continue
					}

					if err := sig.Verify(key, rrset); err != nil {
						lastErr = err
						continue
					}

					if !sig.ValidityPeriod(t) {
						lastErr = ErrInvalidSignaturePeriod
						continue
					}

					// verified
					verifiedSets[rrsetId{sigName, sig.TypeCovered}] = struct{}{}

					if sectionId == 0 {
						msg.Answer = append(msg.Answer, rrset...)
						msg.Answer = append(msg.Answer, sig)
						continue
					}

					if sectionId == 1 {
						msg.Ns = append(msg.Ns, rrset...)
						msg.Ns = append(msg.Ns, sig)
						continue
					}

					msg.Extra = append(msg.Extra, rrset...)
					msg.Extra = append(msg.Extra, sig)
				}
			}
		}
	}

	if len(msg.Answer) > 0 || len(msg.Ns) > 0 {
		// append any unsigned delegations
		// to the authority section
		if len(delegations) > 0 {
			msg.Ns = append(msg.Ns, delegations...)
		}

		return true, nil
	}

	// we don't have any secure validation paths
	// if its okay to downgrade mark zone as insecure
	if downgrade {
		msg.Answer = sections[0]
		msg.Ns = sections[1]
		msg.Extra = sections[2]
		return false, nil
	}

	if lastErr != nil {
		return false, fmt.Errorf("error verifying signatures: %v", lastErr)
	}

	return false, ErrNoSignatures
}

func Verify(msg *dns.Msg, zone, qname string, qtype uint16, trustedKeys map[uint16]*dns.DNSKEY, t time.Time, minRSA int) (bool, error) {
	if !dns.IsFqdn(zone) || !dns.IsFqdn(qname) {
		return false, fmt.Errorf("zone and qname must be fqdn")
	}

	secure, err := verifySignatures(zone, qname, msg, trustedKeys, t, minRSA)
	if err != nil {
		return false, err
	}
	if !secure {
		return false, nil
	}

	// signatures are good verify answer
	if msg.Rcode == dns.RcodeSuccess {
		if len(msg.Answer) == 0 {
			return verifyNoData(msg, zone, qname, qtype)
		}

		return verifyAnswer(msg, qname, qtype)
	}

	if msg.Rcode == dns.RcodeNameError {
		return verifyNameError(msg, zone, qname)
	}

	return false, fmt.Errorf("verify error: unexpected rcode %v", msg.Rcode)
}

// verifyAnswer pass a verified msg with fqdn canonical qname
func verifyAnswer(msg *dns.Msg, qname string, qtype uint16) (bool, error) {
	if len(msg.Answer) == 0 {
		return false, errors.New("empty answer")
	}

	wildcard := false
	nx := false
	labels := uint8(dns.CountLabel(qname))

	// sanitized answer section
	var answer []dns.RR

	for _, rr := range msg.Answer {
		t := rr.Header().Rrtype
		owner := rr.Header().Name

		if t == qtype || t == dns.TypeCNAME {
			// only include rrs that match owner name
			// TODO: flatten CNAMEs if possible
			if strings.EqualFold(qname, owner) {
				answer = append(answer, rr)
			}
			continue
		}

		if t == dns.TypeRRSIG && strings.EqualFold(qname, owner) {
			sig := rr.(*dns.RRSIG)
			if sig.TypeCovered != qtype &&
				sig.TypeCovered != dns.TypeCNAME {
				continue
			}

			answer = append(answer, rr)
			if sig.Labels < labels {
				wildcard = true
			}
			continue
		}
	}

	if len(answer) == 0 {
		return false, errors.New("empty answer")
	}

	msg.Answer = answer

	// if the rrsig is for a wildcard
	// there must be an NSEC proving the original name
	// doesn't exist
	if wildcard {
		for _, rr := range msg.Ns {
			if rr.Header().Rrtype != dns.TypeNSEC {
				continue
			}

			nsec := rr.(*dns.NSEC)
			if nx = covers(nsec.Header().Name, nsec.NextDomain, qname); nx {
				break
			}
		}

		if !nx {
			return false, fmt.Errorf("bad wildcard substitution")
		}
	}

	return true, nil
}

func verifyNoData(msg *dns.Msg, zone, qname string, qtype uint16) (bool, error) {
	if len(msg.Ns) == 0 {
		return false, fmt.Errorf("no nsec records found")
	}

	for _, rr := range msg.Ns {
		// no authenticated denial of existence
		// for NSEC3 for now it should be downgraded
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			// must be in bailiwick already checked
			// by verifySignatures
			if dns.IsSubDomain(zone, rr.Header().Name) {
				return false, nil
			}
		}

		if rr.Header().Rrtype == dns.TypeDS {
			hasNs := false

			if !IsSubDomainStrict(zone, rr.Header().Name) {
				return false, fmt.Errorf("ds record must be a child of zone %s", zone)
			}

			// NS records aren't signed
			// the owner name must still match
			// the DS record.
			for _, ns := range msg.Ns {
				if ns.Header().Rrtype == dns.TypeNS {
					hasNs = true
					if !strings.EqualFold(ns.Header().Name, rr.Header().Name) {
						return false, fmt.Errorf("bad referral DS owner doesn't match NS")
					}
				}
			}

			// secure delegation with valid
			// NS records
			if hasNs {
				return true, nil
			}

			return false, fmt.Errorf("DS record exists without a delegation")
		}

		if rr.Header().Rrtype == dns.TypeNSEC {
			if nsec, ok := rr.(*dns.NSEC); ok {
				// RFC4035 5.4 bullet 1
				if !strings.EqualFold(nsec.Header().Name, qname) {
					// owner name doesn't match
					// RFC4035 5.4 bullet 2
					return verifyNameError(msg, zone, qname)
				}

				// nsec matches qname
				// next domain must be in bailiwick
				if !dns.IsSubDomain(zone, nsec.NextDomain) {
					continue
				}

				hasDelegation := false
				hasDS := false

				for _, t := range nsec.TypeBitMap {
					if t == qtype {
						return false, fmt.Errorf("type exists")
					}
					if t == dns.TypeCNAME {
						return false, fmt.Errorf("cname exists")
					}

					if t == dns.TypeDS {
						hasDS = true
						continue
					}

					if t == dns.TypeNS {
						hasDelegation = true
					}
				}

				// verify delegation
				for _, nsRR := range msg.Ns {
					if nsRR.Header().Rrtype == dns.TypeNS {
						if hasDS {
							return false, fmt.Errorf("bad insecure delegation proof " +
								"DS exists in NSEC bitmap")
						}
						if !hasDelegation {
							return false, fmt.Errorf("NS isn't set in NSEC bitmap")
						}
						if !strings.EqualFold(nsRR.Header().Name, nsec.Header().Name) {
							return false, fmt.Errorf("invalid NS owner name")
						}
						if strings.EqualFold(nsRR.Header().Name, zone) {
							return false, fmt.Errorf("bad referral")
						}
					}
				}

				return true, nil
			}
		}
	}

	return false, fmt.Errorf("no valid nsec records found")
}

func verifyNameError(msg *dns.Msg, zone, qname string) (bool, error) {
	nameProof := false
	wildcardProof := false
	qnameParts := dns.SplitDomainName(qname)
	for _, rr := range msg.Ns {
		if nameProof && wildcardProof {
			break
		}

		if rr.Header().Rrtype == dns.TypeNSEC {
			nsec, ok := rr.(*dns.NSEC)
			if !ok {
				continue
			}

			if !nameProof && covers(nsec.Header().Name, nsec.NextDomain, qname) {
				nameProof = true
			}

			// TODO: handle empty non-terminals
			if !wildcardProof {
				// find closest wildcardProof that covers qname
				i := 1
				for {
					if len(qnameParts) < i {
						break
					}

					domain := dns.Fqdn("*." + strings.Join(qnameParts[i:], "."))
					if !dns.IsSubDomain(zone, domain) {
						break
					}
					if covers(nsec.Header().Name, nsec.NextDomain, domain) {
						wildcardProof = true
						break
					}
					i++
				}
			}
		}
	}

	if !nameProof {
		return false, fmt.Errorf("missing name proof")
	}

	if !wildcardProof {
		return false, fmt.Errorf("missing wildcardProof proof")
	}

	return true, nil
}

// RFC4034 6.1. Canonical DNS Name Order
// https://tools.ietf.org/html/rfc4034#section-6.1
// Returns -1 if name1 comes before name2, 1 if name1 comes after name2, and 0 if they are equal.
func canonicalNameCompare(name1 string, name2 string) (int, error) {
	// TODO: optimize comparison
	name1 = dns.Fqdn(name1)
	name2 = dns.Fqdn(name2)

	if _, ok := dns.IsDomainName(name1); !ok {
		return 0, errors.New("invalid domain name")
	}
	if _, ok := dns.IsDomainName(name2); !ok {
		return 0, errors.New("invalid domain name")
	}

	labels1 := dns.SplitDomainName(name1)
	labels2 := dns.SplitDomainName(name2)

	var buf1, buf2 [64]byte
	// start comparison from the right
	currentLabel1, currentLabel2, min := len(labels1)-1, len(labels2)-1, 0

	if min = currentLabel1; min > currentLabel2 {
		min = currentLabel2
	}

	for i := min; i > -1; i-- {
		off1, err := dns.PackDomainName(labels1[currentLabel1]+".", buf1[:], 0, nil, false)
		if err != nil {
			return 0, err
		}

		off2, err := dns.PackDomainName(labels2[currentLabel2]+".", buf2[:], 0, nil, false)
		if err != nil {
			return 0, err
		}

		currentLabel1--
		currentLabel2--

		// if the two labels at the same index aren't equal return result
		if res := bytes.Compare(bytes.ToLower(buf1[1:off1-1]),
			bytes.ToLower(buf2[1:off2-1])); res != 0 {
			return res, nil
		}
	}

	// all labels are equal name with least labels is the smallest
	if len(labels1) == len(labels2) {
		return 0, nil
	}

	if len(labels1)-1 == min {
		return -1, nil
	}

	return 1, nil
}

func covers(owner, next, qname string) (result bool) {
	var errs int

	// qname is equal to or before owner can't be covered
	if compareWithErrors(qname, owner, &errs) <= 0 {
		return false
	}

	lastNSEC := compareWithErrors(owner, next, &errs) >= 0
	inRange := lastNSEC || compareWithErrors(qname, next, &errs) < 0
	if !inRange {
		return false
	}

	if errs > 0 {
		return false
	}

	return true
}

func compareWithErrors(a, b string, errs *int) int {
	res, err := canonicalNameCompare(a, b)
	if err != nil {
		*errs++
	}

	return res
}

func extractRRSet(in []dns.RR, name string, types ...uint16) []dns.RR {
	var out []dns.RR
	tMap := make(map[uint16]struct{}, len(types))
	for _, t := range types {
		tMap[t] = struct{}{}
	}
	for _, r := range in {
		if _, ok := tMap[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}
