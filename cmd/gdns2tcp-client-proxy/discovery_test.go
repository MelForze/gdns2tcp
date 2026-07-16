package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFormatResolverAddressPreservesIPv6Scope(t *testing.T) {
	if got := formatResolverAddress(net.ParseIP("fe80::1"), 12); got != "fe80::1%12" {
		t.Fatalf("scoped IPv6=%q", got)
	}
	if got := formatResolverAddress(net.ParseIP("2001:db8::1"), 12); got != "2001:db8::1" {
		t.Fatalf("global IPv6 unexpectedly scoped: %q", got)
	}
	if got := formatResolverAddress(net.ParseIP("192.0.2.1"), 12); got != "192.0.2.1" {
		t.Fatalf("IPv4 unexpectedly scoped: %q", got)
	}
}

func TestParseDelegationReferral(t *testing.T) {
	target := "files.example.test."
	var malformedGlue *dns.A
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.test."},
	}
	response.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "NS2.EXAMPLE.TEST."},
		&dns.NS{Hdr: dns.RR_Header{Name: "other.example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ignored.example.test."},
	}
	response.Extra = []dns.RR{
		malformedGlue,
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.10")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns2.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::10")},
		&dns.A{Hdr: dns.RR_Header{Name: "ignored.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.99")},
	}

	referral, err := parseDelegationReferral(response, target)
	if err != nil {
		t.Fatalf("parseDelegationReferral: %v", err)
	}
	if got, want := strings.Join(referral.nameServers, ","), "ns1.example.test.,ns2.example.test."; got != want {
		t.Fatalf("nameservers=%q, want %q", got, want)
	}
	if got := referral.glue["ns1.example.test."]; len(got) != 1 || got[0].String() != "192.0.2.10" {
		t.Fatalf("ns1 glue=%v", got)
	}
	if got := referral.glue["ns2.example.test."]; len(got) != 1 || got[0].String() != "2001:db8::10" {
		t.Fatalf("ns2 glue=%v", got)
	}
	if _, exists := referral.glue["ignored.example.test."]; exists {
		t.Fatal("unrelated glue was accepted")
	}
}

func TestParseDelegationReferralErrors(t *testing.T) {
	tests := []struct {
		name     string
		response *dns.Msg
	}{
		{name: "nil"},
		{name: "nxdomain", response: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
		{name: "no exact ns", response: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}, Ns: []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "other.example.test.", Rrtype: dns.TypeNS}, Ns: "ns.example.test."},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDelegationReferral(test.response, "files.example.test."); err == nil {
				t.Fatal("expected referral parse error")
			}
		})
	}
}

func TestResolveNameServerEndpointsUsesGlueAndPrefersIPv4(t *testing.T) {
	lookupCalls := 0
	backend := dnsDiscoveryBackend{
		lookupIP: func(_ context.Context, _, host string) ([]net.IP, error) {
			lookupCalls++
			if host != "ns2.example.test." {
				t.Fatalf("unexpected lookup for %s", host)
			}
			return []net.IP{net.ParseIP("2001:db8::2"), net.ParseIP("192.0.2.2")}, nil
		},
	}
	endpoints, err := resolveNameServerEndpoints(context.Background(), backend,
		[]string{"ns1.example.test.", "ns2.example.test."},
		map[string][]net.IP{"ns1.example.test.": {net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}},
	)
	if err != nil {
		t.Fatalf("resolveNameServerEndpoints: %v", err)
	}
	if lookupCalls != 1 {
		t.Fatalf("lookup calls=%d, want 1 for the NS without glue", lookupCalls)
	}
	got := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		got = append(got, endpoint.ip.String())
	}
	if want := "192.0.2.1,192.0.2.2,2001:db8::1,2001:db8::2"; strings.Join(got, ",") != want {
		t.Fatalf("endpoint order=%v, want %s", got, want)
	}
}

func TestSelectDNSPathExplicitSkipsDiscovery(t *testing.T) {
	discoveryCalled := false
	fallbackCalled := false
	selection, err := selectDNSPath(context.Background(), config{dnsServer: " 203.0.113.10 "},
		func(context.Context, config) (authoritativeDiscovery, error) {
			discoveryCalled = true
			return authoritativeDiscovery{}, errors.New("must not run")
		},
		func() (string, error) {
			fallbackCalled = true
			return "192.0.2.53", nil
		},
	)
	if err != nil {
		t.Fatalf("selectDNSPath: %v", err)
	}
	if discoveryCalled || fallbackCalled {
		t.Fatalf("explicit -ds called automatic paths: discovery=%v fallback=%v", discoveryCalled, fallbackCalled)
	}
	if selection.source != dnsSelectionExplicit || selection.server != "203.0.113.10" {
		t.Fatalf("selection=%+v", selection)
	}
}

func TestSelectDNSPathFallsBackToSystemResolver(t *testing.T) {
	discoveryErr := errors.New("private zone has no delegation")
	selection, err := selectDNSPath(context.Background(), config{domain: "files.internal"},
		func(context.Context, config) (authoritativeDiscovery, error) {
			return authoritativeDiscovery{}, discoveryErr
		},
		func() (string, error) { return "10.0.0.53", nil },
	)
	if err != nil {
		t.Fatalf("selectDNSPath: %v", err)
	}
	if selection.source != dnsSelectionSystem || selection.server != "10.0.0.53" || !errors.Is(selection.discoveryErr, discoveryErr) {
		t.Fatalf("selection=%+v", selection)
	}
}

func TestSelectDNSPathReportsMissingFallback(t *testing.T) {
	_, err := selectDNSPath(context.Background(), config{domain: "files.internal"},
		func(context.Context, config) (authoritativeDiscovery, error) {
			return authoritativeDiscovery{}, errors.New("no delegation")
		},
		func() (string, error) { return "", errors.New("no system resolver") },
	)
	if err == nil || !strings.Contains(err.Error(), "system DNS fallback failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiscoverAuthoritativeDNSHierarchy(t *testing.T) {
	parentAddr := startDiscoveryDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Ns = []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "files.parent.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.files.parent.test."},
		}
		response.Extra = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ns.files.parent.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("198.51.100.20")},
		}
		_ = w.WriteMsg(response)
	}))
	childAddr := startDiscoveryDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []dns.RR{
			&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"base32"}},
		}
		_ = w.WriteMsg(response)
	}))

	systemBackend := systemDNSDiscoveryBackend()
	backend := dnsDiscoveryBackend{
		lookupNS: func(_ context.Context, name string) ([]*net.NS, error) {
			if name != "parent.test." {
				return nil, fmt.Errorf("unexpected bootstrap NS lookup %s", name)
			}
			return []*net.NS{{Host: "ns.parent.test."}}, nil
		},
		lookupIP: func(_ context.Context, _, host string) ([]net.IP, error) {
			if host != "ns.parent.test." {
				return nil, fmt.Errorf("unexpected bootstrap IP lookup %s", host)
			}
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		},
		exchange: func(ctx context.Context, network, address string, request *dns.Msg) (*dns.Msg, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			switch host {
			case "192.0.2.10":
				address = parentAddr
			case "198.51.100.20":
				address = childAddr
			default:
				return nil, fmt.Errorf("unexpected direct DNS host %s", host)
			}
			return systemBackend.exchange(ctx, network, address, request)
		},
	}

	found, err := discoverAuthoritativeDNSWithBackend(context.Background(), config{
		domain:       "files.parent.test",
		shardDomains: []string{"files.parent.test", "files2.parent.test"},
		dnsPort:      "5353",
	}, backend)
	if err != nil {
		t.Fatalf("discoverAuthoritativeDNSWithBackend: %v", err)
	}
	if found.server != "198.51.100.20" || found.parent != "parent.test." || found.nameServer != "ns.files.parent.test." {
		t.Fatalf("found=%+v", found)
	}
}

func TestQueryDelegationRetriesTruncatedUDPOverTCP(t *testing.T) {
	var networks []string
	backend := dnsDiscoveryBackend{exchange: func(_ context.Context, network, _ string, request *dns.Msg) (*dns.Msg, error) {
		networks = append(networks, network)
		response := new(dns.Msg)
		response.SetReply(request)
		if network == "udp" {
			response.Truncated = true
			return response, nil
		}
		response.Ns = []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "files.example.test.", Rrtype: dns.TypeNS}, Ns: "ns.example.test."},
		}
		return response, nil
	}}
	response, err := queryDelegation(context.Background(), backend, "192.0.2.10", "files.example.test.")
	if err != nil {
		t.Fatalf("queryDelegation: %v", err)
	}
	if response.Truncated || strings.Join(networks, ",") != "udp,tcp" {
		t.Fatalf("networks=%v truncated=%v", networks, response.Truncated)
	}
}

func TestDiscoveryTriesNextAuthoritativeCandidate(t *testing.T) {
	var probed []string
	backend := fakeDiscoveryBackend(t, func(_ context.Context, network, address string, request *dns.Msg) (*dns.Msg, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeNS {
			response.Ns = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: "files.parent.test.", Rrtype: dns.TypeNS}, Ns: "ns1.files.parent.test."},
				&dns.NS{Hdr: dns.RR_Header{Name: "files.parent.test.", Rrtype: dns.TypeNS}, Ns: "ns2.files.parent.test."},
			}
			response.Extra = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns1.files.parent.test.", Rrtype: dns.TypeA}, A: net.ParseIP("198.51.100.20")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.files.parent.test.", Rrtype: dns.TypeA}, A: net.ParseIP("198.51.100.21")},
			}
			return response, nil
		}
		if network != "udp" || port != "53" {
			t.Fatalf("unexpected probe transport %s %s", network, address)
		}
		probed = append(probed, host)
		if host == "198.51.100.20" {
			return nil, errors.New("first candidate unavailable")
		}
		response.Authoritative = true
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT}, Txt: []string{"base32"}}}
		return response, nil
	})

	found, err := discoverAuthoritativeDNSWithBackend(context.Background(), config{domain: "files.parent.test", dnsPort: "53"}, backend)
	if err != nil {
		t.Fatalf("discoverAuthoritativeDNSWithBackend: %v", err)
	}
	if found.server != "198.51.100.21" || strings.Join(probed, ",") != "198.51.100.20,198.51.100.21" {
		t.Fatalf("found=%+v probed=%v", found, probed)
	}
}

func TestDiscoveryRequiresEveryShard(t *testing.T) {
	var probeCount int
	backend := fakeDiscoveryBackend(t, func(_ context.Context, _ string, _ string, request *dns.Msg) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeNS {
			response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "files.parent.test.", Rrtype: dns.TypeNS}, Ns: "ns.files.parent.test."}}
			response.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.files.parent.test.", Rrtype: dns.TypeA}, A: net.ParseIP("198.51.100.20")}}
			return response, nil
		}
		probeCount++
		response.Authoritative = !strings.HasSuffix(strings.ToLower(request.Question[0].Name), ".files2.parent.test.")
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT}, Txt: []string{"base32"}}}
		return response, nil
	})

	_, err := discoverAuthoritativeDNSWithBackend(context.Background(), config{
		domain:       "files.parent.test",
		shardDomains: []string{"files.parent.test", "files2.parent.test"},
		dnsPort:      "53",
	}, backend)
	if err == nil {
		t.Fatal("candidate authoritative for only one shard was accepted")
	}
	if probeCount != 2 {
		t.Fatalf("probe count=%d, want 2", probeCount)
	}
}

func TestAuthoritativeProbeNamesBypassCaches(t *testing.T) {
	first, err := newAuthoritativeProbeName("files.example.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := newAuthoritativeProbeName("files.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("probe QNAME was reused: %s", first)
	}
	for _, name := range []string{first, second} {
		if !strings.HasSuffix(name, ".encoding.test.files.example.test") {
			t.Fatalf("unexpected probe name %q", name)
		}
	}
}

func fakeDiscoveryBackend(t *testing.T, exchange func(context.Context, string, string, *dns.Msg) (*dns.Msg, error)) dnsDiscoveryBackend {
	t.Helper()
	return dnsDiscoveryBackend{
		lookupNS: func(_ context.Context, name string) ([]*net.NS, error) {
			if name != "parent.test." {
				return nil, fmt.Errorf("no NS for %s", name)
			}
			return []*net.NS{{Host: "ns.parent.test."}}, nil
		},
		lookupIP: func(_ context.Context, _, host string) ([]net.IP, error) {
			if host != "ns.parent.test." {
				return nil, fmt.Errorf("no IP for %s", host)
			}
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		},
		exchange: exchange,
	}
}

func startDiscoveryDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	packetConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}

	udpServer := &dns.Server{PacketConn: packetConn, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Net: "tcp", Handler: handler, MaxTCPQueries: -1}
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			_ = udpServer.Shutdown()
			_ = tcpServer.Shutdown()
		})
	}
	t.Cleanup(shutdown)
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
}

func TestDiscoveryHonorsCallerDeadline(t *testing.T) {
	backend := dnsDiscoveryBackend{
		lookupNS: func(ctx context.Context, _ string) ([]*net.NS, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := discoverAuthoritativeDNSWithBackend(ctx, config{domain: "files.parent.test"}, backend)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("deadline result err=%v duration=%s", err, time.Since(started))
	}
}

func TestCandidateUDPTruncationPromotesAndRechecksEveryShardOverTCP(t *testing.T) {
	var networks []string
	backend := dnsDiscoveryBackend{exchange: func(_ context.Context, network, _ string, request *dns.Msg) (*dns.Msg, error) {
		networks = append(networks, network)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if network == "udp" {
			response.Truncated = true
			return response, nil
		}
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"base64"}}}
		return response, nil
	}}
	required, err := validateAuthoritativeCandidate(context.Background(), backend, config{
		domain: "one.test", shardDomains: []string{"one.test", "two.test"}, dnsPort: "53",
	}, "192.0.2.1")
	if err != nil || !required {
		t.Fatalf("tcpRequired=%v err=%v", required, err)
	}
	if got, want := strings.Join(networks, ","), "udp,udp,tcp,tcp"; got != want {
		t.Fatalf("probe networks=%s, want %s", got, want)
	}
}
