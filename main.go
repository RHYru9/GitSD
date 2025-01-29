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
	lowerText := strings.ToLower(responseText)
	return strings.Contains(lowerText, "<html") || strings.Contains(lowerText, "<!doctype html")
}

func formatStatus(code int) string {
	statusMessages := map[int]string{
		200: "200 vulnerable!",
		301: "301 moved permanently",
		302: "302 redirect",
		303: "303 see other",
		304: "304 not modified",
		307: "307 temporary redirect",
		308: "308 permanent redirect",
		400: "400 error",
		401: "401 unauthorized",
		403: "403 forbidden",
		404: "404 not found",
		405: "405 method not allowed",
		406: "406 not acceptable",
		407: "407 proxy auth required",
		408: "408 request timeout",
		429: "429 too many requests",
		500: "500 server error",
		501: "501 not implemented",
		502: "502 bad gateway",
		503: "503 service unavailable",
		504: "504 gateway timeout",
	}

	if msg, exists := statusMessages[code]; exists {
		return msg
	}
	return fmt.Sprintf("%d unknown status", code)
}

func checkVulnerability(content string) bool {
	lowerContent := strings.ToLower(content)
	for _, sign := range vulnerabilitySigns {
		if strings.Contains(lowerContent, strings.ToLower(sign)) {
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
		color.Yellow("\t[+] Following redirect to: %s", currentURL)
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

	finalDomain, statusCode, err := followRedirect(client, domain)
	if err != nil {
		color.Red("\t[+] Error following redirects: %v", err)
		return false
	}

	color.Cyan("\t[+] Final domain: %s (Status: %s)", finalDomain, formatStatus(statusCode))

	if finalDomain != domain {
		parsedDomain, err = url.Parse(finalDomain)
		if err != nil {
			return false
		}
	}

	vulnerable := false
	for _, path := range paths {
		targetURL := parsedDomain.Scheme + "://" + parsedDomain.Host + path

		finalURL, statusCode, err := followRedirect(client, targetURL)
		if err != nil {
			fmt.Printf("\t[+] path %-40s| 400 error\n", path)
			continue
		}

		req, err := http.NewRequest("GET", finalURL, nil)
		if err != nil {
			fmt.Printf("\t[+] path %-40s| 400 error\n", path)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GitSD/1.0)")
		resp, err := client.Do(req)

		if err != nil {
			fmt.Printf("\t[+] path %-40s| 400 error\n", path)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("\t[+] path %-40s| 400 error\n", path)
				continue
			}

			content := string(bodyBytes)
			if isHTML(content) {
				fmt.Printf("\t[+] path %-40s| 404 not found\n", path)
			} else if checkVulnerability(content) {
				color.Green("\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
				vulnerable = true
			} else {
				fmt.Printf("\t[+] path %-40s| 404 not found\n", path)
			}
		} else {
			color.Yellow("\t[+] path %-40s| %s", path, formatStatus(resp.StatusCode))
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
		if domain != "" && scanPath(domain) {
			vulnerableDomains = append(vulnerableDomains, domain)
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
