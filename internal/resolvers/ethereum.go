package resolvers

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/miekg/dns"
	"time"
)

// hardcoded .eth NS rrset pointing to their registry
var ethNS = []*dns.NS{
	{
		Hdr: dns.RR_Header{
			Name:   "eth.",
			Rrtype: dns.TypeNS,
			Class:  1,
			Ttl:    86400,
		},
		Ns: "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e._eth.",
	},
}

type Ethereum struct {
	client *ethclient.Client
	rCache *cache
}

func NewEthereum(rawurl string) (*Ethereum, error) {
	conn, err := ethclient.Dial(rawurl)
	if err != nil {
		return nil, err
	}

	return &Ethereum{
		client: conn,
		rCache: newCache(200),
	}, nil
}

func (e *Ethereum) GetResolverAddress(node, registryAddress string) (common.Address, error) {
	key := node + ";" + registryAddress
	r, ok := e.rCache.get(key)
	if ok {
		if time.Now().Before(r.ttl) {
			return r.msg.(common.Address), nil
		}
		e.rCache.remove(key)
	}

	registry, err := NewENSRegistry(common.HexToAddress(registryAddress), e.client)
	if err != nil {
		return common.Address{}, err
	}

	addr, err := registry.Resolver(nil, EnsNode(node))
	if err != nil {
		return common.Address{}, err
	}

	e.rCache.set(key, &entry{
		msg: addr,
		ttl: time.Now().Add(6 * time.Hour),
	})

	return addr, nil
}

func (e *Ethereum) Resolve(resolverAddress common.Address, qname string, qtype uint16) ([]dns.RR, error) {
	resolver, err := NewDNSResolver(resolverAddress, e.client)
	if err != nil {
		return nil, err
	}

	qname = dns.CanonicalName(qname)
	node := toNode(qname)
	nodeHash, err := NameHash(node)
	if err != nil {
		return nil, err
	}

	res, err := e.queryWithResolver(resolver, nodeHash, qname, qtype)
	if err != nil {
		return nil, err
	}

	return unpackRRSet(res), nil
}

func (e *Ethereum) dnsRecord(resolver *DNSResolver, node [32]byte, qname string, qtype uint16) ([]byte, error) {
	qnameHash, err := hashDnsName(qname)
	if err != nil {
		return nil, err
	}

	return resolver.DnsRecord(nil, node, qnameHash, qtype)
}

func (e *Ethereum) queryWithResolver(resolver *DNSResolver, nodeHash [32]byte, qname string, qtype uint16) ([]byte, error) {
	rawRecords, err := e.dnsRecord(resolver, nodeHash, qname, qtype)
	if err != nil {
		return nil, err
	}

	maxLabels := dns.CountLabel(qname)
	if maxLabels > 3 {
		maxLabels = 3
	}

	// Look for NS records up to maxLabels
	if len(rawRecords) == 0 {
		labels := 2
		for {
			if labels > maxLabels {
				break
			}

			name := dns.Fqdn(LastNLabels(qname, labels))
			labels++

			if rawRecords, err = e.dnsRecord(resolver, nodeHash, name, dns.TypeNS); err != nil {
				return nil, err
			}

			// a delegation exists check if it's signed
			if len(rawRecords) > 0 {
				var dsSet []byte
				if dsSet, err = e.dnsRecord(resolver, nodeHash, name, dns.TypeDS); err != nil {
					return nil, err
				}

				if len(dsSet) > 0 {
					rawRecords = append(rawRecords, dsSet...)
				}

				return rawRecords, nil
			}
		}
	}

	if len(rawRecords) == 0 {
		// no records for original qname and no delegations
		// check if a CNAME exists
		if rawRecords, err = e.dnsRecord(resolver, nodeHash, qname, dns.TypeCNAME); err != nil {
			return nil, err
		}
	}

	return rawRecords, nil
}

func (e *Ethereum) Handler(ctx context.Context, qname string, qtype uint16, ns *dns.NS) ([]dns.RR, error) {
	registryAddress := FirstNLabels(ns.Ns, 1)
	node := toNode(qname)

	var resolverAddr common.Address
	var err error

	resolverAddr, err = e.GetResolverAddress(node, registryAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to get resolver address from registry %s: %v", registryAddress, err)
	}

	return e.Resolve(resolverAddr, qname, qtype)
}
