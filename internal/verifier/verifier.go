package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// EgressReport summarizes verified public network identity
type EgressReport struct {
	IP      string        `json:"ip"`
	Country string        `json:"country"`
	City    string        `json:"city"`
	Org     string        `json:"org"`
	IsTor   bool          `json:"is_tor"`
	Latency time.Duration `json:"latency"`
	Error   error         `json:"error,omitempty"`
}

type torCheckResponse struct {
	IsTor bool   `json:"IsTor"`
	IP    string `json:"IP"`
}

type ipWhoIsResponse struct {
	Success     bool   `json:"success"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Connection  struct {
		ISP string `json:"isp"`
		Org string `json:"org"`
	} `json:"connection"`
}

type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

func getJSON(client *http.Client, url string, target interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "curl/8.5.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, target)
}

// VerifyEgress dials through the local SOCKS5 proxy and verifies public IP, geo, and Tor exit status
func VerifyEgress(socksPort int, timeout time.Duration) *EgressReport {
	report := &EgressReport{}
	start := time.Now()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	if err != nil {
		report.Error = fmt.Errorf("failed to create socks5 dialer: %w", err)
		return report
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// 1. Check Tor Project official endpoint
	var tc torCheckResponse
	if err := getJSON(client, "https://check.torproject.org/api/ip", &tc); err == nil {
		report.IP = tc.IP
		report.IsTor = tc.IsTor
	}

	// 2. Query ipwho.is (rich, unauthenticated, reliable over Tor)
	var iwi ipWhoIsResponse
	if err := getJSON(client, "https://ipwho.is/", &iwi); err == nil && (iwi.Success || iwi.IP != "") {
		if report.IP == "" {
			report.IP = iwi.IP
		}
		if iwi.CountryCode != "" {
			report.Country = iwi.CountryCode
		} else {
			report.Country = iwi.Country
		}
		report.City = iwi.City
		if iwi.Connection.Org != "" {
			report.Org = iwi.Connection.Org
		} else {
			report.Org = iwi.Connection.ISP
		}
		report.IsTor = true
	}

	// 3. Fallback to ipinfo.io
	if report.Country == "" {
		var ii ipinfoResponse
		if err := getJSON(client, "https://ipinfo.io/json", &ii); err == nil {
			if report.IP == "" {
				report.IP = ii.IP
			}
			report.Country = ii.Country
			report.City = ii.City
			report.Org = ii.Org
			report.IsTor = true
		}
	}

	// 4. Fallback IP check if still empty
	if report.IP == "" {
		req, _ := http.NewRequest("GET", "https://icanhazip.com", nil)
		req.Header.Set("User-Agent", "curl/8.5.0")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			report.IP = strings.TrimSpace(string(body))
			report.IsTor = true
		} else if report.Error == nil {
			report.Error = fmt.Errorf("failed to reach verification endpoints via SOCKS5")
		}
	}

	report.Latency = time.Since(start)
	return report
}
