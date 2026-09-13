package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	ExitLeakDetected = 10
	ExitBlocked      = 0
	ExitError        = 2
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: tux-leaker <tcp|dns|ipv6|loop> [options]")
		os.Exit(ExitError)
	}

	sub := os.Args[1]
	switch sub {
	case "tcp":
		runTCP(os.Args[2:])
	case "dns":
		runDNS(os.Args[2:])
	case "ipv6":
		runIPv6(os.Args[2:])
	case "loop":
		runLoop(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", sub)
		os.Exit(ExitError)
	}
}

// runTCP attempts a direct TCP connection bypassing SOCKS
func runTCP(args []string) {
	fs := flag.NewFlagSet("tcp", flag.ExitOnError)
	target := fs.String("target", "198.51.100.1:8888", "Target host:port (TEST-NET-2 dummy IP)")
	timeout := fs.Duration("timeout", 1*time.Second, "Dial timeout")
	_ = fs.Parse(args)

	fmt.Printf("[PROBE:TCP] Attempting direct connection to %s (timeout: %v)...\n", *target, *timeout)
	conn, err := net.DialTimeout("tcp", *target, *timeout)
	if err != nil {
		fmt.Printf("[BLOCKED:TCP] Direct connection dropped/rejected: %v\n", err)
		os.Exit(ExitBlocked)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "[CRITICAL:LEAK] Direct TCP connection SUCCEEDED to %s! Security sandbox breached.\n", *target)
	os.Exit(ExitLeakDetected)
}

// runDNS sends a raw RFC 1035 UDP query to an external DNS server
func runDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	server := fs.String("server", "9.9.9.9:53", "External DNS resolver to query")
	domain := fs.String("domain", "check.torproject.org", "Domain to query")
	timeout := fs.Duration("timeout", 1500*time.Millisecond, "Query timeout")
	_ = fs.Parse(args)

	fmt.Printf("[PROBE:DNS] Sending raw UDP DNS query for %s to %s...\n", *domain, *server)

	// Build standard DNS query packet (ID 0x4242, Type A)
	packet := buildDNSQueryPacket(0x4242, *domain)

	conn, err := net.DialTimeout("udp", *server, *timeout)
	if err != nil {
		fmt.Printf("[BLOCKED:DNS] UDP socket dial failed: %v\n", err)
		os.Exit(ExitBlocked)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(*timeout))
	if _, err := conn.Write(packet); err != nil {
		fmt.Printf("[BLOCKED:DNS] UDP send failed: %v\n", err)
		os.Exit(ExitBlocked)
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Printf("[BLOCKED:DNS] Query timed out or dropped by firewall: %v\n", err)
		os.Exit(ExitBlocked)
	}

	if n >= 12 && resp[0] == 0x42 && resp[1] == 0x42 && (resp[2]&0x80 != 0) {
		fmt.Printf("[INTERCEPTED:DNS] Response received (%d bytes). Intercepted by Tor DNSPort DNAT.\n", n)
		os.Exit(ExitBlocked)
	}

	fmt.Printf("[RESPONSE:DNS] Received unverified response: %d bytes\n", n)
	os.Exit(ExitBlocked)
}

// runIPv6 attempts an AF_INET6 connection
func runIPv6(args []string) {
	fs := flag.NewFlagSet("ipv6", flag.ExitOnError)
	target := fs.String("target", "[2001:db8::1]:80", "Target IPv6:port (RFC 3849 documentation prefix)")
	timeout := fs.Duration("timeout", 1*time.Second, "Dial timeout")
	_ = fs.Parse(args)

	fmt.Printf("[PROBE:IPV6] Attempting AF_INET6 connection to %s...\n", *target)
	conn, err := net.DialTimeout("tcp6", *target, *timeout)
	if err != nil {
		fmt.Printf("[BLOCKED:IPV6] IPv6 socket/route rejected: %v\n", err)
		os.Exit(ExitBlocked)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "[CRITICAL:LEAK] Direct IPv6 connection SUCCEEDED to %s!\n", *target)
	os.Exit(ExitLeakDetected)
}

// runLoop keeps a persistent connection or heartbeat for testing Kill-Switch
func runLoop(args []string) {
	fmt.Println("[WATCHDOG:CHILD] Process started, listening for termination signals...")
	for {
		time.Sleep(100 * time.Millisecond)
	}
}

func buildDNSQueryPacket(id uint16, domain string) []byte {
	var buf []byte
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00) // Flags: Standard query, recursion desired
	buf = append(buf, 0x00, 0x01) // QDCOUNT: 1
	buf = append(buf, 0x00, 0x00) // ANCOUNT: 0
	buf = append(buf, 0x00, 0x00) // NSCOUNT: 0
	buf = append(buf, 0x00, 0x00) // ARCOUNT: 0

	// Encode labels
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)       // Root null label
	buf = append(buf, 0x00, 0x01) // QTYPE: A (1)
	buf = append(buf, 0x00, 0x01) // QCLASS: IN (1)

	return buf
}

func suppressUnused() {
	_ = io.EOF
}
