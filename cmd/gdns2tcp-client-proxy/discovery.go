package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gdns2tcp/internal/protocol"

	"github.com/miekg/dns"
)

const (
	dnsDiscoveryTimeout         = 10 * time.Second
	dnsDiscoveryExchangeTimeout = 2 * time.Second
)

type dnsSelectionSource uint8

const (
	dnsSelectionExplicit dnsSelectionSource = iota
	dnsSelectionDelegation
	dnsSelectionSystem
)

type dnsSelection struct {
	server       string
	source       dnsSelectionSource
	parent       string
	nameServer   string
	discoveryErr error
	tcpRequired  bool
}

type authoritativeDiscovery struct {
	server      string
	parent      string
	nameServer  string
	tcpRequired bool
}

type authoritativeDiscoveryFunc func(context.Context, config) (authoritativeDiscovery, error)
type systemResolverFunc func() (string, error)

func formatResolverAddress(ip net.IP, scopeID uint32) string {
	if ip == nil {
		return ""
	}
	address := ip.String()
	if scopeID != 0 && ip.To4() == nil && ip.IsLinkLocalUnicast() {
		address += "%" + strconv.FormatUint(uint64(scopeID), 10)
	}
	return address
}

// selectDNSPath keeps an explicit -ds authoritative over every automatic
// choice. Without it, delegation discovery is attempted first and the system
// resolver is retained only as a compatibility fallback for private or
// temporarily broken DNS hierarchies.
func selectDNSPath(ctx context.Context, cfg config, discover authoritativeDiscoveryFunc, systemResolver systemResolverFunc) (dnsSelection, error) {
	if server := strings.TrimSpace(cfg.dnsServer); server != "" {
		return dnsSelection{server: server, source: dnsSelectionExplicit}, nil
	}

	found, discoveryErr := discover(ctx, cfg)
	if discoveryErr == nil {
		if server := strings.TrimSpace(found.server); server != "" {
			return dnsSelection{
				server:      server,
				source:      dnsSelectionDelegation,
				parent:      strings.TrimSuffix(found.parent, "."),
				nameServer:  strings.TrimSuffix(found.nameServer, "."),
				tcpRequired: found.tcpRequired,
			}, nil
		}
		discoveryErr = errors.New("delegation discovery returned an empty server address")
	}

	fallback, fallbackErr := systemResolver()
	if fallbackErr != nil || strings.TrimSpace(fallback) == "" {
		if fallbackErr == nil {
			fallbackErr = errors.New("system resolver returned an empty address")
		}
		return dnsSelection{}, fmt.Errorf("authoritative DNS discovery failed: %v; system DNS fallback failed: %w", discoveryErr, fallbackErr)
	}
	return dnsSelection{
		server:       strings.TrimSpace(fallback),
		source:       dnsSelectionSystem,
		discoveryErr: discoveryErr,
	}, nil
}

type dnsDiscoveryBackend struct {
	lookupNS func(context.Context, string) ([]*net.NS, error)
	lookupIP func(context.Context, string, string) ([]net.IP, error)
	exchange func(context.Context, string, string, *dns.Msg) (*dns.Msg, error)
}

func systemDNSDiscoveryBackend() dnsDiscoveryBackend {
	return dnsDiscoveryBackend{
		lookupNS: net.DefaultResolver.LookupNS,
		lookupIP: net.DefaultResolver.LookupIP,
		exchange: func(ctx context.Context, network, address string, request *dns.Msg) (*dns.Msg, error) {
			client := &dns.Client{Net: network, Timeout: dnsDiscoveryExchangeTimeout}
			response, _, err := client.ExchangeContext(ctx, request, address)
			return response, err
		},
	}
}

// discoverAuthoritativeDNS uses the system resolver only to bootstrap parent
// NS addresses. It then asks those parent servers directly (RD=0) for the
// target delegation and validates every resulting address against the real
// gdns2tcp TXT endpoint before returning it.
func discoverAuthoritativeDNS(ctx context.Context, cfg config) (authoritativeDiscovery, error) {
	return discoverAuthoritativeDNSWithBackend(ctx, cfg, systemDNSDiscoveryBackend())
}

func discoverAuthoritativeDNSWithBackend(parentCtx context.Context, cfg config, backend dnsDiscoveryBackend) (authoritativeDiscovery, error) {
	ctx, cancel := context.WithTimeout(parentCtx, dnsDiscoveryTimeout)
	defer cancel()

	domain := dns.Fqdn(strings.TrimSpace(cfg.domain))
	parents := parentDomainNames(domain)
	if len(parents) == 0 {
		return authoritativeDiscovery{}, fmt.Errorf("domain %q has no discoverable parent zone", cfg.domain)
	}

	attemptedCandidates := make(map[string]struct{})
	var lastErr error
	var lastCandidateErr error
	candidateCount := 0
	for _, parent := range parents {
		if err := ctx.Err(); err != nil {
			return authoritativeDiscovery{}, fmt.Errorf("discover authoritative DNS for %s: %w", cfg.domain, err)
		}

		parentNS, err := backend.lookupNS(ctx, parent)
		if err != nil {
			lastErr = fmt.Errorf("resolve parent NS for %s: %w", parent, err)
			continue
		}
		parentNames := make([]string, 0, len(parentNS))
		for _, record := range parentNS {
			if record != nil && strings.TrimSpace(record.Host) != "" {
				parentNames = append(parentNames, dns.Fqdn(record.Host))
			}
		}
		parentEndpoints, resolveErr := resolveNameServerEndpoints(ctx, backend, parentNames, nil)
		if len(parentEndpoints) == 0 {
			if resolveErr == nil {
				resolveErr = errors.New("parent has no usable NS addresses")
			}
			lastErr = fmt.Errorf("resolve parent NS addresses for %s: %w", parent, resolveErr)
			continue
		}

		for _, parentEndpoint := range parentEndpoints {
			response, queryErr := queryDelegation(ctx, backend, parentEndpoint.ip.String(), domain)
			if queryErr != nil {
				lastErr = fmt.Errorf("query %s (%s) for %s delegation: %w", parentEndpoint.name, parentEndpoint.ip, domain, queryErr)
				continue
			}
			referral, referralErr := parseDelegationReferral(response, domain)
			if referralErr != nil {
				lastErr = fmt.Errorf("parse %s referral from %s: %w", domain, parentEndpoint.name, referralErr)
				continue
			}
			childEndpoints, childResolveErr := resolveNameServerEndpoints(ctx, backend, referral.nameServers, referral.glue)
			if len(childEndpoints) == 0 {
				if childResolveErr == nil {
					childResolveErr = errors.New("delegation has no usable NS addresses")
				}
				lastErr = fmt.Errorf("resolve authoritative NS addresses for %s: %w", domain, childResolveErr)
				continue
			}

			for _, candidate := range childEndpoints {
				server := candidate.ip.String()
				if _, alreadyTried := attemptedCandidates[server]; alreadyTried {
					continue
				}
				attemptedCandidates[server] = struct{}{}
				candidateCount++
				tcpRequired, err := validateAuthoritativeCandidate(ctx, backend, cfg, server)
				if err != nil {
					lastCandidateErr = fmt.Errorf("validate authoritative candidate %s (%s): %w", candidate.name, server, err)
					lastErr = lastCandidateErr
					continue
				}
				return authoritativeDiscovery{server: server, parent: parent, nameServer: candidate.name, tcpRequired: tcpRequired}, nil
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return authoritativeDiscovery{}, fmt.Errorf("discover authoritative DNS for %s: %w", cfg.domain, err)
	}
	if lastCandidateErr != nil {
		lastErr = lastCandidateErr
	}
	if lastErr == nil {
		lastErr = errors.New("no matching NS delegation was returned")
	}
	return authoritativeDiscovery{}, fmt.Errorf("discover authoritative DNS for %s after %d candidate(s): %w", cfg.domain, candidateCount, lastErr)
}

func parentDomainNames(domain string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(domain))
	if len(labels) < 2 {
		return nil
	}
	parents := make([]string, 0, len(labels)-1)
	for i := 1; i < len(labels); i++ {
		parents = append(parents, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return parents
}

type nameServerEndpoint struct {
	name string
	ip   net.IP
}

// resolveNameServerEndpoints uses in-bailiwick glue when present. Names
// without glue are resolved through the bootstrap resolver. IPv4 endpoints
// are returned before IPv6 endpoints while preserving the NS order within
// each address family.
func resolveNameServerEndpoints(ctx context.Context, backend dnsDiscoveryBackend, names []string, glue map[string][]net.IP) ([]nameServerEndpoint, error) {
	var ipv4, ipv6 []nameServerEndpoint
	seen := make(map[string]struct{})
	var lastErr error
	for _, rawName := range names {
		name := dns.Fqdn(strings.TrimSpace(rawName))
		if name == "." {
			continue
		}
		ips := glue[canonicalDNSName(name)]
		if len(ips) == 0 {
			resolved, err := backend.lookupIP(ctx, "ip", name)
			if err != nil {
				lastErr = fmt.Errorf("resolve %s: %w", name, err)
				continue
			}
			ips = resolved
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			key := ip.String()
			if key == "<nil>" {
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			endpoint := nameServerEndpoint{name: name, ip: ip}
			if ip.To4() != nil {
				ipv4 = append(ipv4, endpoint)
			} else if ip.To16() != nil {
				ipv6 = append(ipv6, endpoint)
			}
		}
	}
	return append(ipv4, ipv6...), lastErr
}

type delegationReferral struct {
	nameServers []string
	glue        map[string][]net.IP
}

func parseDelegationReferral(response *dns.Msg, target string) (delegationReferral, error) {
	if response == nil {
		return delegationReferral{}, errors.New("empty DNS response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return delegationReferral{}, fmt.Errorf("DNS response code %s", dns.RcodeToString[response.Rcode])
	}

	target = canonicalDNSName(target)
	seenNS := make(map[string]struct{})
	referral := delegationReferral{glue: make(map[string][]net.IP)}
	collectNS := func(records []dns.RR) {
		for _, record := range records {
			ns, ok := record.(*dns.NS)
			if !ok || ns == nil || canonicalDNSName(ns.Hdr.Name) != target {
				continue
			}
			name := canonicalDNSName(ns.Ns)
			if name == "." {
				continue
			}
			if _, duplicate := seenNS[name]; duplicate {
				continue
			}
			seenNS[name] = struct{}{}
			referral.nameServers = append(referral.nameServers, name)
		}
	}
	collectNS(response.Answer)
	collectNS(response.Ns)
	if len(referral.nameServers) == 0 {
		return delegationReferral{}, fmt.Errorf("response contains no NS records owned by %s", target)
	}

	for _, record := range response.Extra {
		var (
			owner string
			ip    net.IP
		)
		switch typed := record.(type) {
		case *dns.A:
			if typed == nil {
				continue
			}
			owner, ip = canonicalDNSName(typed.Hdr.Name), typed.A
		case *dns.AAAA:
			if typed == nil {
				continue
			}
			owner, ip = canonicalDNSName(typed.Hdr.Name), typed.AAAA
		default:
			continue
		}
		if _, matchesDelegation := seenNS[owner]; !matchesDelegation || ip == nil {
			continue
		}
		referral.glue[owner] = append(referral.glue[owner], ip)
	}
	return referral, nil
}

func canonicalDNSName(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

// queryDelegation asks a parent NS directly. UDP errors and truncated replies
// are retried over TCP because this traffic is only bootstrap traffic; the
// selected tunnel transport is validated independently below.
func queryDelegation(ctx context.Context, backend dnsDiscoveryBackend, server, target string) (*dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(target), dns.TypeNS)
	request.RecursionDesired = false
	address := net.JoinHostPort(server, defaultDNSPort)

	udpResponse, udpErr := discoveryExchange(ctx, backend, "udp", address, request)
	if udpErr == nil && udpResponse != nil && !udpResponse.Truncated {
		return udpResponse, nil
	}
	tcpResponse, tcpErr := discoveryExchange(ctx, backend, "tcp", address, request)
	if tcpErr == nil && tcpResponse != nil && !tcpResponse.Truncated {
		return tcpResponse, nil
	}
	if tcpErr != nil {
		if udpErr != nil {
			return nil, fmt.Errorf("UDP failed: %v; TCP fallback failed: %w", udpErr, tcpErr)
		}
		return nil, fmt.Errorf("truncated UDP response; TCP fallback failed: %w", tcpErr)
	}
	return nil, errors.New("TCP fallback returned an empty or truncated response")
}

func validateAuthoritativeCandidate(ctx context.Context, backend dnsDiscoveryBackend, cfg config, server string) (bool, error) {
	domains := cfg.shardDomains
	if len(domains) == 0 {
		domains = []string{cfg.domain}
	}
	port := strings.TrimSpace(cfg.dnsPort)
	if port == "" {
		port = defaultDNSPort
	}
	address := net.JoinHostPort(server, port)
	validateAll := func(network string) (bool, error) {
		truncated := false
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			probeName, err := newAuthoritativeProbeName(domain)
			if err != nil {
				return false, err
			}
			probeName = dns.Fqdn(probeName)
			request := new(dns.Msg)
			request.SetQuestion(probeName, dns.TypeTXT)
			request.RecursionDesired = false

			response, err := discoveryExchange(ctx, backend, network, address, request)
			if err != nil {
				return false, fmt.Errorf("probe %s via %s: %w", probeName, network, err)
			}
			if response != nil && response.Truncated {
				truncated = true
				continue
			}
			if err := validateAuthoritativeTXTResponse(response, probeName); err != nil {
				return false, err
			}
		}
		return truncated, nil
	}
	if cfg.tcp {
		truncated, err := validateAll("tcp")
		if err != nil {
			return false, err
		}
		if truncated {
			return false, errors.New("authoritative TCP probe returned a truncated response")
		}
		return false, nil
	}
	truncated, err := validateAll("udp")
	if err != nil {
		return false, err
	}
	if !truncated {
		return false, nil
	}
	tcpTruncated, err := validateAll("tcp")
	if err != nil {
		return false, fmt.Errorf("TCP fallback: %w", err)
	}
	if tcpTruncated {
		return false, errors.New("TCP fallback returned a truncated response")
	}
	return true, nil
}

func validateAuthoritativeTXTResponse(response *dns.Msg, probeName string) error {
	if response == nil {
		return errors.New("authoritative probe returned an empty response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("authoritative probe returned %s", dns.RcodeToString[response.Rcode])
	}
	if !response.Authoritative {
		return errors.New("authoritative probe response does not have AA set")
	}
	probeName = canonicalDNSName(probeName)
	for _, record := range response.Answer {
		txt, ok := record.(*dns.TXT)
		if ok && txt != nil && canonicalDNSName(txt.Hdr.Name) == probeName && validProbePayload(txt.Txt) {
			return nil
		}
	}
	return fmt.Errorf("authoritative probe response contains no valid gdns2tcp TXT answer for %s", probeName)
}

func validProbePayload(segments []string) bool {
	value := strings.Join(segments, "")
	return value == "base32" || value == "base64"
}

// newAuthoritativeProbeName gives every liveness check a distinct QNAME.
// This prevents an enterprise recursive cache (or a transparent DNS proxy)
// from satisfying startup with an old encoding.test response.
func newAuthoritativeProbeName(domain string) (string, error) {
	nonce, err := protocol.NewSID()
	if err != nil {
		return "", fmt.Errorf("generate DNS probe nonce: %w", err)
	}
	return nonce + ".encoding.test." + strings.TrimSuffix(strings.TrimSpace(domain), "."), nil
}

func discoveryExchange(ctx context.Context, backend dnsDiscoveryBackend, network, address string, request *dns.Msg) (*dns.Msg, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, dnsDiscoveryExchangeTimeout)
	defer cancel()
	response, err := backend.exchange(attemptCtx, network, address, request.Copy())
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("empty DNS response")
	}
	return response, nil
}
