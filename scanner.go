package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/http2"
)

var standardGitPaths = []string{
	"/.git/", "/.git/config", "/.git/index", "/.git/logs/", "/.git/HEAD",
	"/.git/logs/HEAD", "/.git/logs/refs", "/.git/logs/refs/remotes/origin/master",
	"/.git/description", "/.git/hooks/", "/.git/info/", "/.git/objects/", "/.git/refs/",
	"/.git/logs/refs/heads/main", "/.git/logs/refs/heads/master", "/.git/logs/refs/heads/develop",
	"/.git/logs/refs/remotes/origin/main", "/.git/refs/heads/main", "/.git/refs/heads/master",
	"/.git/refs/remotes/origin/main", "/.git/COMMIT_EDITMSG", "/.git/packed-refs",
}
var vulnerabilitySigns = []string{
	"ref:", "index of", "initial commit", "update by push", "[core]", "repository",
	"bare = false", "filemode", "[remote", "[branch", "master", "origin", "HEAD branch:",
	"refs/heads/", "autopull", "repositoryformatversion",
}
var secretIndicators = []string{
	"gitlab-ci-token", "x-oauth-basic",
}

type Config struct {
	ForceProtocol   string
	PathPrefixes    []string
	Filename        string
	OutputFile      string
	Threads         int
	FollowRedirect  bool
	DebugMode       bool
}
type ScanResult struct {
	Domain        string
	Path          string
	StatusCode    int
	Vulnerable    bool
	Error         string
	Content       string
	SecretLevel   string
	SecretDetails []string
	Protocol      string
	IsCustomPath  bool
}
type ScanStats struct {
	TotalDomains      int
	BasePaths         int
	CustomPaths       int
	VulnerableDomains int
	CriticalFindings  int
	MediumFindings    int
	NormalFindings    int
	StartTime         time.Time
	EndTime           time.Time
}

func scanDomain(domain string, config *Config, results chan<- ScanResult, writer *OutputWriter) {
	normalizedDomain := normalizeURL(domain, config.ForceProtocol)
	writer.WriteColor(color.New(color.FgHiCyan, color.Bold), "\n┌─ Scanning: %s\n", normalizedDomain)
	parsedDomain, err := url.Parse(normalizedDomain)
	if err != nil {
		results <- ScanResult{Domain: domain, Error: fmt.Sprintf("Invalid URL: %v", err)}
		return
	}
	client := createHTTPClient(config)
	basePaths, customPaths := buildPaths(config)
	vulnerableFound := false
	criticalSecretsFound := false

	if len(customPaths) > 0 {
		writer.WriteColor(color.New(color.FgHiWhite), " ├─ Base paths: %d | Custom paths: %d\n", len(basePaths), len(customPaths))
	} else {
		writer.WriteColor(color.New(color.FgHiWhite), " ├─ Base paths: %d (no custom prefixes)\n", len(basePaths))
	}
	allPaths := append(basePaths, customPaths...)
	for i, path := range allPaths {
		isCustomPath := i >= len(basePaths)
		targetURL := fmt.Sprintf("%s://%s%s", parsedDomain.Scheme, parsedDomain.Host, path)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			printResult(domain, path, 0, false, "Request creation failed", "NORMAL", nil, "N/A", isCustomPath, writer)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GitScanner/2.1)")
		resp, err := client.Do(req)
		if err != nil {
			printResult(domain, path, 0, false, "Connection failed", "NORMAL", nil, "N/A", isCustomPath, writer)
			continue
		}
		func() {
			defer resp.Body.Close()
			proto := "HTTP/1.1"
			if resp.ProtoMajor == 2 {
				proto = "HTTP/2.0"
			}
			if resp.StatusCode == 200 {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					printResult(domain, path, resp.StatusCode, false, "Read error", "NORMAL", nil, proto, isCustomPath, writer)
					return
				}
				content := string(bodyBytes)
				if isHTML(content) {
					printResult(domain, path, 404, false, "", "NORMAL", nil, proto, isCustomPath, writer)
				} else if checkVulnerability(content) {
					secretLevel, secrets := analyzeSecrets(content, domain)
					printResult(domain, path, resp.StatusCode, true, "", secretLevel, secrets, proto, isCustomPath, writer)
					vulnerableFound = true
					if secretLevel == "CRITICAL" {
						criticalSecretsFound = true
					}
					results <- ScanResult{
						Domain:        domain,
						Path:          path,
						StatusCode:    resp.StatusCode,
						Vulnerable:    true,
						Content:       content,
						SecretLevel:   secretLevel,
						SecretDetails: secrets,
						Protocol:      proto,
						IsCustomPath:  isCustomPath,
					}
				} else {
					printResult(domain, path, 404, false, "", "NORMAL", nil, proto, isCustomPath, writer)
				}
			} else {
				printResult(domain, path, resp.StatusCode, false, "", "NORMAL", nil, proto, isCustomPath, writer)
			}
		}()
	}
	if criticalSecretsFound {
		writer.WriteColor(color.New(color.FgHiRed, color.Bold), "└─ 🚨 CRITICAL SECRETS FOUND!\n")
	} else if vulnerableFound {
		writer.WriteColor(color.New(color.FgHiGreen, color.Bold), "└─ ✓ VULNERABLE DOMAIN FOUND!\n")
	} else {
		writer.WriteColor(color.New(color.FgHiBlack), "└─ No vulnerabilities detected\n")
	}
}

func checkVulnerability(content string) bool {
	contentLower := strings.ToLower(content)
	for _, sign := range vulnerabilitySigns {
		if strings.Contains(contentLower, strings.ToLower(sign)) {
			return true
		}
	}
	return false
}
func analyzeSecrets(content, domain string) (string, []string) {
	var secrets []string
	secretLevel := "NORMAL"
	ghpRegex := regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)
	ghpMatches := ghpRegex.FindAllString(content, -1)
	for _, match := range ghpMatches {
		secrets = append(secrets, fmt.Sprintf("GitHub Token: %s", match))
		secretLevel = "CRITICAL"
	}
	urlWithCredsRegex := regexp.MustCompile(`url\s*=\s*https?://([^:]+):([^@]+)@([^/\s]+)(/[^\s]*)?`)
	urlMatches := urlWithCredsRegex.FindAllStringSubmatch(content, -1)
	for _, match := range urlMatches {
		if len(match) >= 4 {
			username := match[1]
			password := match[2]
			host := match[3]
			path := ""
			if len(match) > 4 {
				path = match[4]
			}
			fullURL := fmt.Sprintf("https://%s:%s@%s%s", username, password, host, path)
			isCritical := false
			if strings.Contains(password, "glpat-") {
				isCritical = true
			}
			if strings.Contains(strings.ToLower(password), "token") {
				isCritical = true
			}
			if strings.Contains(host, "github.com") {
				if strings.Contains(password, "ghp_") || strings.Contains(password, "token") || strings.Contains(strings.ToLower(password), "oauth") {
					isCritical = true
				} else {
					if secretLevel != "CRITICAL" {
						secretLevel = "MEDIUM"
					}
					secrets = append(secrets, fmt.Sprintf("GitHub Credentials: %s", fullURL))
					continue
				}
			} else {
				isCritical = true
			}
			if isCritical {
				secretLevel = "CRITICAL"
				secrets = append(secrets, fmt.Sprintf("CRITICAL Credentials: %s", fullURL))
			}
		}
	}
	contentLower := strings.ToLower(content)
	for _, indicator := range secretIndicators {
		if strings.Contains(contentLower, indicator) {
			secrets = append(secrets, fmt.Sprintf("Secret Indicator: %s", indicator))
			if secretLevel == "NORMAL" {
				secretLevel = "MEDIUM"
			}
		}
	}
	githubURLRegex := regexp.MustCompile(`url\s*=\s*(https?://github\.com/[^\s]+)`)
	githubMatches := githubURLRegex.FindAllStringSubmatch(content, -1)
	for _, match := range githubMatches {
		if len(match) >= 2 {
			urlFound := false
			for _, secret := range secrets {
				if strings.Contains(secret, match[1]) {
					urlFound = true
					break
				}
			}
			if !urlFound {
				secrets = append(secrets, fmt.Sprintf("GitHub Repository: %s", match[1]))
				if secretLevel == "NORMAL" {
					secretLevel = "MEDIUM"
				}
			}
		}
	}
	return secretLevel, secrets
}
func buildPaths(config *Config) ([]string, []string) {
	var basePaths []string
	var customPaths []string
	basePaths = append(basePaths, standardGitPaths...)
	if len(config.PathPrefixes) > 0 {
		for _, prefix := range config.PathPrefixes {
			sanitized := sanitizePrefix(prefix)
			if sanitized != "" {
				for _, gitPath := range standardGitPaths {
					cleanGitPath := strings.TrimPrefix(gitPath, "/")
					customPath := fmt.Sprintf("/%s/%s", sanitized, cleanGitPath)
					customPaths = append(customPaths, customPath)
				}
			}
		}
	}
	return basePaths, customPaths
}
func normalizeURL(domain string, forceProtocol string) string {
	domain = strings.TrimSpace(domain)
	if forceProtocol != "" {
		if strings.HasPrefix(domain, "http://") {
			domain = strings.TrimPrefix(domain, "http://")
		} else if strings.HasPrefix(domain, "https://") {
			domain = strings.TrimPrefix(domain, "https://")
		}
		return forceProtocol + "://" + domain
	}
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}
	return domain
}
func createHTTPClient(config *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	if strings.Contains(strings.ToLower(config.ForceProtocol), "http2") {
		http2.ConfigureTransport(transport)
	} else if strings.Contains(strings.ToLower(config.ForceProtocol), "http1") {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

