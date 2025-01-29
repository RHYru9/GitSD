package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"github.com/fatih/color"
)

var paths = []string{
	"/.git/",
	"/.git/index",
	"/.git/logs/",
	"/.git/HEAD",
	"/.git/logs/HEAD",
	"/.git/logs/refs",
	"/.git/logs/refs/remotes/origin/master",
	"/.git/config",
	"/.git/description",
	"/.git/hooks/",
	"/.git/info/",
	"/.git/objects/",
	"/.git/refs/",
}

var vulnerabilitySigns = []string{
	"ref:",
	"index of",
	"initial commit",
	"update by push",
	"[core]",
	"repository",
	"bare = false",
	"filemode",
	"[remote",
	"[branch",
	"master",
	"origin",
	"HEAD branch:",
	"refs/heads/",
	"autopull",
	"repositoryformatversion",
}

func isHTML(responseText string) bool {
	return strings.Contains(strings.ToLower(responseText), "<html") ||
		strings.Contains(strings.ToLower(responseText), "<!doctype html")
}

func formatStatus(code int) string {
	switch code {
	case 200:
		return "200 vulnerable!"
	case 301:
		return "301 moved permanently"
	case 302:
		return "302 redirect"
	case 303:
		return "303 see other"
	case 304:
		return "304 not modified"
	case 307:
		return "307 temporary redirect"
	case 308:
		return "308 permanent redirect"
	case 400:
		return "400 error"
	case 401:
		return "401 unauthorized"
	case 403:
		return "403 forbidden"
	case 404:
		return "404 not found"
	case 405:
		return "405 method not allowed"
	case 406:
		return "406 not acceptable"
	case 407:
		return "407 proxy auth required"
	case 408:
		return "408 request timeout"
	case 429:
		return "429 too many requests"
	case 500:
		return "500 server error"
	case 501:
		return "501 not implemented"
	case 502:
		return "502 bad gateway"
	case 503:
		return "503 service unavailable"
	case 504:
		return "504 gateway timeout"
	default:
		return fmt.Sprintf("%d unknown status", code)
	}
}

func checkVulnerability(content string) bool {
	for _, sign := range vulnerabilitySigns {
		if strings.Contains(strings.ToLower(content), strings.ToLower(sign)) {
			return true
		}
	}
	return false
}

func followRedirect(client *http.Client, initialURL string) (string, int, error) {
	maxRedirects := 10
	currentURL := initialURL

	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return "", 0, err
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0")
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return currentURL, resp.StatusCode, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return currentURL, resp.StatusCode, nil
		}

		nextURL, err := url.Parse(location)
		if err != nil {
			return "", 0, err
		}

		currentURL = resp.Request.URL.ResolveReference(nextURL).String()
		color.Yellow("\t\t\t\t[+] Following redirect to: %s", currentURL)
	}

	return currentURL, 0, fmt.Errorf("too many redirects")
}

func scanPath(domain string) bool {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	parsedDomain, err := url.Parse(domain)
	if err != nil {
		return false
	}

	color.White("[+] %s", domain)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	finalDomain, _, err := followRedirect(client, domain)
	if err != nil {
		color.Red("\t\t\t\t[+] Error following redirects: %v", err)
		return false
	}

	if finalDomain != domain {
		color.Yellow("\t\t\t\t[+] Domain redirects to: %s", finalDomain)
		parsedDomain, err = url.Parse(finalDomain)
		if err != nil {
			return false
		}
	}

	vulnerable := false
	for _, path := range paths {
		targetURL := parsedDomain.Scheme + "://" + parsedDomain.Host + path

		finalURL, _, err := followRedirect(client, targetURL)
		if err != nil {
			fmt.Printf("\t\t\t\t[+] path %-40s| 400 error\n", path)
			continue
		}

		req, err := http.NewRequest("GET", finalURL, nil)
		if err != nil {
			fmt.Printf("\t\t\t\t[+] path %-40s| 400 error\n", path)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GitSD/1.0)")
		resp, err := client.Do(req)

		if err != nil {
			if strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "deadline exceeded") {
				fmt.Printf("\t\t\t\t[+] path %-40s| 400 error\n", path)
			} else {
				fmt.Printf("\t\t\t\t[+] path %-40s| 400 error\n", path)
			}
			continue
		}

		if resp != nil {
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("\t\t\t\t[+] path %-40s| 400 error\n", path)
					continue
				}

				content := string(bodyBytes)
				if isHTML(content) {
					fmt.Printf("\t\t\t\t[+] path %-40s| 404 not found\n", path)
				} else if checkVulnerability(content) {
					color.Green("\t\t\t\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
					vulnerable = true
				} else {
					fmt.Printf("\t\t\t\t[+] path %-40s| 404 not found\n", path)
				}
			} else {
				switch {
				case resp.StatusCode >= 300 && resp.StatusCode < 400:
					color.Yellow("\t\t\t\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
				case resp.StatusCode >= 400 && resp.StatusCode < 500:
					color.Red("\t\t\t\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
				case resp.StatusCode >= 500:
					color.Red("\t\t\t\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
				}
			}
		}
	}
	return vulnerable
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gitsd <file containing list of domains>")
		return
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	var vulnerableDomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			if scanPath(domain) {
				vulnerableDomains = append(vulnerableDomains, domain)
			}
		}
	}

	if len(vulnerableDomains) > 0 {
		color.Green("\n[+] Found %d vulnerable domains:", len(vulnerableDomains))
		for _, domain := range vulnerableDomains {
			color.Green("[+] %s", domain)
		}
	} else {
		color.Yellow("\n[+] No vulnerable domains found.")
	}
}
