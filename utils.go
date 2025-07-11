package main

import (
	"fmt"
	"os"
	"regexp"
	"time"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/term"
)

type OutputWriter struct {
	file   *os.File
	stdout bool
}

func NewOutputWriter(filename string) (*OutputWriter, error) {
	if filename == "" {
		return &OutputWriter{stdout: true}, nil
	}
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{file: file}, nil
}
func (ow *OutputWriter) Write(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	if ow.stdout {
		fmt.Print(text)
	} else {
		ow.file.WriteString(text)
	}
}
func (ow *OutputWriter) WriteColor(c *color.Color, format string, args ...interface{}) {
	if ow.stdout {
		c.Printf(format, args...)
	} else {
		text := fmt.Sprintf(format, args...)
		ow.file.WriteString(text)
	}
}
func (ow *OutputWriter) Close() {
	if ow.file != nil {
		ow.file.Close()
	}
}

func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 80 {
		return 80
	}
	return width
}
func printSeparator(char rune, writer *OutputWriter) {
	width := getTerminalWidth()
	writer.Write("%s\n", strings.Repeat(string(char), width))
}
func printCentered(text string, writer *OutputWriter, c *color.Color) {
	width := getTerminalWidth()
	padding := (width - len(text)) / 2
	if padding < 0 {
		padding = 0
	}
	if c != nil {
		writer.WriteColor(c, "%s%s\n", strings.Repeat(" ", padding), text)
	} else {
		writer.Write("%s%s\n", strings.Repeat(" ", padding), text)
	}
}
func printHeader(writer *OutputWriter) {
	printSeparator('=', writer)
	printCentered("GIT SCANNER ENHANCED v2.1", writer, color.New(color.FgCyan, color.Bold))
	printCentered("Advanced Git Exposure & Secret Scanner", writer, color.New(color.FgCyan))
	printSeparator('=', writer)
}
func isHTML(responseText string) bool {
	return strings.Contains(strings.ToLower(responseText), "<html") || strings.Contains(strings.ToLower(responseText), "<!doctype html")
}
func formatStatus(code int) (string, *color.Color) {
	switch code {
	case 200:
		return "200 VULNERABLE!", color.New(color.FgHiRed, color.Bold)
	case 301:
		return "301 Moved Permanently", color.New(color.FgYellow)
	case 302:
		return "302 Found", color.New(color.FgYellow)
	case 303:
		return "303 See Other", color.New(color.FgYellow)
	case 304:
		return "304 Not Modified", color.New(color.FgYellow)
	case 307:
		return "307 Temporary Redirect", color.New(color.FgYellow)
	case 308:
		return "308 Permanent Redirect", color.New(color.FgYellow)
	case 400:
		return "400 Bad Request", color.New(color.FgRed)
	case 401:
		return "401 Unauthorized", color.New(color.FgRed)
	case 403:
		return "403 Forbidden", color.New(color.FgRed)
	case 404:
		return "404 Not Found", color.New(color.FgHiBlack)
	case 405:
		return "405 Method Not Allowed", color.New(color.FgRed)
	case 429:
		return "429 Too Many Requests", color.New(color.FgMagenta)
	case 500:
		return "500 Internal Server Error", color.New(color.FgRed)
	case 502:
		return "502 Bad Gateway", color.New(color.FgRed)
	case 503:
		return "503 Service Unavailable", color.New(color.FgRed)
	case 504:
		return "504 Gateway Timeout", color.New(color.FgRed)
	default:
		return fmt.Sprintf("%d Unknown Status", code), color.New(color.FgWhite)
	}
}
func sanitizePrefix(prefix string) string {
	cleaned := strings.Trim(strings.TrimSpace(prefix), "/")
	validChars := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validChars.MatchString(cleaned) {
		return ""
	}
	if len(cleaned) == 0 || len(cleaned) > 50 {
		return ""
	}
	return cleaned
}

func printResult(domain, path string, statusCode int, vulnerable bool, errorMsg string, secretLevel string, secrets []string, protocol string, isCustomPath bool, writer *OutputWriter) {
	width := getTerminalWidth()
	maxPathWidth := 35
	if width > 120 {
		maxPathWidth = 50
	} else if width < 100 {
		maxPathWidth = 25
	}
	displayPath := path
	if len(path) > maxPathWidth {
		displayPath = path[:maxPathWidth-3] + "..."
	}
	pathField := fmt.Sprintf("%-*s", maxPathWidth, displayPath)
	pathType := "STD"
	if isCustomPath {
		pathType = "CST"
	}
	if errorMsg != "" {
		writer.WriteColor(color.New(color.FgRed), " ├─ [%s] %s │ ERROR: %s\n", pathType, pathField, errorMsg)
		return
	}
	statusText, statusColor := formatStatus(statusCode)
	statusText = fmt.Sprintf("%s (%s)", statusText, protocol)
	if vulnerable {
		if len(secrets) > 0 {
			switch secretLevel {
			case "CRITICAL":
				writer.WriteColor(color.New(color.FgHiRed, color.Bold), " ├─ [%s] %s │ 🚨 %s [CRITICAL SECRETS]\n", pathType, pathField, statusText)
			case "MEDIUM":
				writer.WriteColor(color.New(color.FgHiYellow, color.Bold), " ├─ [%s] %s │ ⚠️ %s [MEDIUM SECRETS]\n", pathType, pathField, statusText)
			default:
				writer.WriteColor(color.New(color.FgHiGreen, color.Bold), " ├─ [%s] %s │ ✓ %s\n", pathType, pathField, statusText)
			}
			for _, secret := range secrets {
				if secretLevel == "CRITICAL" {
					writer.WriteColor(color.New(color.FgHiRed), " │ └─ %s\n", secret)
				} else if secretLevel == "MEDIUM" {
					writer.WriteColor(color.New(color.FgHiYellow), " │ └─ %s\n", secret)
				} else {
					writer.WriteColor(color.New(color.FgGreen), " │ └─ %s\n", secret)
				}
			}
		} else {
			writer.WriteColor(color.New(color.FgHiGreen, color.Bold), " ├─ [%s] %s │ ✓ %s\n", pathType, pathField, statusText)
		}
	} else {
		writer.WriteColor(statusColor, " ├─ [%s] %s │ %s\n", pathType, pathField, statusText)
	}
}

func printUsage() {
	width := getTerminalWidth()
	separator := strings.Repeat("=", width)
	fmt.Println(separator)
	fmt.Println("Usage: gitsd [OPTIONS] <domains_file>")
	fmt.Println("\nOptions:")
	fmt.Println(" -f, --force <protocol> Force protocol (http/https/http1.1/http2.0)")
	fmt.Println(" -p, --paths <prefixes> Custom path prefixes (comma-separated)")
	fmt.Println(" -o, --output <file> Output results to file")
	fmt.Println(" -t, --threads <num> Number of concurrent threads (default: 10)")
	fmt.Println(" -d, --debug Enable debug mode")
	fmt.Println(" -h, --help Show this help message")
	fmt.Println("\nPath Logic:")
	fmt.Println(" Without -p: domain.com/.git/config (standard paths only)")
	fmt.Println(" With -p web,api: domain.com/.git/config + domain.com/web/.git/config + domain.com/api/.git/config")
	fmt.Println("\nExamples:")
	fmt.Println(" gitsd domains.txt")
	fmt.Println(" gitsd -f https domains.txt")
	fmt.Println(" gitsd -f http1.1 domains.txt")
	fmt.Println(" gitsd -f http2.0 domains.txt")
	fmt.Println(" gitsd -p web,api domains.txt")
	fmt.Println(" gitsd -p web,api,test,admin,backup domains.txt")
	fmt.Println(" gitsd -p admin,backup -o results.txt domains.txt")
	fmt.Println(" gitsd -t 20 -o scan_results.txt domains.txt")
	fmt.Println(" gitsd -d -p web,api domains.txt # Enable debug mode")
	fmt.Println(separator)
}

func printResultDetails(result ScanResult, writer *OutputWriter) {
	pathType := "STD"
	if result.IsCustomPath {
		pathType = "CST"
	}
	statusText, _ := formatStatus(result.StatusCode)
	statusText = fmt.Sprintf("%s (%s)", statusText, result.Protocol)
	writer.WriteColor(color.New(color.FgWhite), " ├─ [%s] %s │ %s\n", pathType, result.Path, statusText)
	for i, secret := range result.SecretDetails {
		prefix := " │"
		if i == len(result.SecretDetails)-1 {
			prefix = " └─"
		}
		writer.Write(" %s %s\n", prefix, secret)
	}
}

func printCriticalFindings(resultsByDomain map[string]map[string][]ScanResult, domainMaxSeverity map[string]string, writer *OutputWriter) {
	criticalDomains := make(map[string]bool)
	for domain, maxSev := range domainMaxSeverity {
		if maxSev == "CRITICAL" {
			criticalDomains[domain] = true
		}
	}
	if len(criticalDomains) > 0 {
		writer.WriteColor(color.New(color.FgHiRed, color.Bold), "\n🚨 CRITICAL FINDINGS (%d domains)\n", len(criticalDomains))
		printSeparator('-', writer)
		for domain := range criticalDomains {
			if severityMap, ok := resultsByDomain[domain]; ok {
				writer.WriteColor(color.New(color.FgHiRed, color.Bold), "▶ %s\n", domain)
				for _, result := range severityMap["CRITICAL"] {
					printResultDetails(result, writer)
				}
			}
		}
	}
}

func printMediumFindings(resultsByDomain map[string]map[string][]ScanResult, domainMaxSeverity map[string]string, writer *OutputWriter) {
	mediumDomains := make(map[string]bool)
	for domain, maxSev := range domainMaxSeverity {
		if maxSev == "MEDIUM" {
			mediumDomains[domain] = true
		}
	}
	if len(mediumDomains) > 0 {
		writer.WriteColor(color.New(color.FgHiYellow, color.Bold), "\n⚠️ MEDIUM RISK FINDINGS (%d domains)\n", len(mediumDomains))
		printSeparator('-', writer)
		for domain := range mediumDomains {
			if severityMap, ok := resultsByDomain[domain]; ok {
				writer.WriteColor(color.New(color.FgHiYellow, color.Bold), "▶ %s\n", domain)
				for _, result := range severityMap["MEDIUM"] {
					printResultDetails(result, writer)
				}
			}
		}
	}
}

func printNormalFindings(resultsByDomain map[string]map[string][]ScanResult, domainMaxSeverity map[string]string, writer *OutputWriter) {
	normalDomains := make(map[string]bool)
	for domain, maxSev := range domainMaxSeverity {
		if maxSev == "NORMAL" {
			normalDomains[domain] = true
		}
	}
	if len(normalDomains) > 0 {
		writer.WriteColor(color.New(color.FgHiGreen, color.Bold), "\n✓ STANDARD VULNERABILITIES (%d domains)\n", len(normalDomains))
		printSeparator('-', writer)
		for domain := range normalDomains {
			if severityMap, ok := resultsByDomain[domain]; ok {
				writer.WriteColor(color.New(color.FgGreen), "▶ %s\n", domain)
				for _, result := range severityMap["NORMAL"] {
					printResultDetails(result, writer)
				}
			}
		}
	}
}

func printSummary(vulnerableDomains []ScanResult, domains []string, config Config, stats ScanStats, writer *OutputWriter) {
	printSeparator('=', writer)
	printCentered("SCAN SUMMARY", writer, color.New(color.FgCyan, color.Bold))
	printSeparator('=', writer)
	resultsByDomain := make(map[string]map[string][]ScanResult)
	domainMaxSeverity := make(map[string]string)
	allVulnerableDomains := make(map[string]bool)
	for _, result := range vulnerableDomains {
		allVulnerableDomains[result.Domain] = true
		if _, ok := resultsByDomain[result.Domain]; !ok {
			resultsByDomain[result.Domain] = make(map[string][]ScanResult)
		}
		resultsByDomain[result.Domain][result.SecretLevel] = append(
			resultsByDomain[result.Domain][result.SecretLevel], result)
		currentMax := domainMaxSeverity[result.Domain]
		if result.SecretLevel == "CRITICAL" || currentMax == "" {
			domainMaxSeverity[result.Domain] = result.SecretLevel
		} else if result.SecretLevel == "MEDIUM" && currentMax != "CRITICAL" {
			domainMaxSeverity[result.Domain] = result.SecretLevel
		}
	}
	writer.WriteColor(color.New(color.FgHiGreen, color.Bold), "\n✓ ALL VULNERABLE DOMAINS (%d)\n", len(allVulnerableDomains))
	printSeparator('-', writer)
	for domain := range allVulnerableDomains {
		writer.Write("▶ %s\n", domain)
	}
	printCriticalFindings(resultsByDomain, domainMaxSeverity, writer)
	printMediumFindings(resultsByDomain, domainMaxSeverity, writer)
	printNormalFindings(resultsByDomain, domainMaxSeverity, writer)
	printSeparator('=', writer)
	printCentered("STATISTICS", writer, color.New(color.FgCyan, color.Bold))
	printSeparator('=', writer)
	duration := stats.EndTime.Sub(stats.StartTime).Round(time.Second)
	writer.WriteColor(color.New(color.FgWhite), "Total domains scanned: %d\n", stats.TotalDomains)
	writer.WriteColor(color.New(color.FgHiCyan), "Base paths per domain: %d\n", stats.BasePaths)
	if stats.CustomPaths > 0 {
		writer.WriteColor(color.New(color.FgHiCyan), "Custom paths per domain: %d\n", stats.CustomPaths)
		writer.WriteColor(color.New(color.FgHiCyan), "Total paths per domain: %d\n", stats.BasePaths+stats.CustomPaths)
	}
	writer.WriteColor(color.New(color.FgHiGreen), "Vulnerable domains: %d\n", stats.VulnerableDomains)
	writer.WriteColor(color.New(color.FgHiRed), "Critical severity: %d\n", stats.CriticalFindings)
	writer.WriteColor(color.New(color.FgHiYellow), "Medium severity: %d\n", stats.MediumFindings)
	writer.WriteColor(color.New(color.FgGreen), "Standard vulnerabilities: %d\n", stats.NormalFindings)
	writer.WriteColor(color.New(color.FgHiMagenta), "Scan duration: %s\n", duration)
	if config.OutputFile != "" {
		writer.WriteColor(color.New(color.FgCyan), "\nResults saved to: %s\n", config.OutputFile)
	}
	printSeparator('=', writer)
}

