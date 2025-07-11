package main

import (
	"bufio"
	"flag"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

func main() {
	var config Config
	var pathPrefixesStr string
	var showHelp bool

	flag.StringVar(&config.ForceProtocol, "f", "", "Force protocol (http/https/http1.1/http2.0)")
	flag.StringVar(&config.ForceProtocol, "force", "", "Force protocol (http/https/http1.1/http2.0)")
	flag.StringVar(&pathPrefixesStr, "p", "", "Custom path prefixes (comma-separated)")
	flag.StringVar(&pathPrefixesStr, "paths", "", "Custom path prefixes (comma-separated)")
	flag.StringVar(&config.OutputFile, "o", "", "Output file")
	flag.StringVar(&config.OutputFile, "output", "", "Output file")
	flag.IntVar(&config.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&config.Threads, "threads", 10, "Number of concurrent threads")
	flag.BoolVar(&config.DebugMode, "d", false, "Enable debug mode")
	flag.BoolVar(&config.DebugMode, "debug", false, "Enable debug mode")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.Parse()

	if showHelp || len(flag.Args()) < 1 {
		printUsage()
		return
	}
	config.Filename = flag.Args()[0]

	validProtocols := map[string]bool{
		"http": true, "https": true, "http1.1": true, "http2.0": true,
	}
	if config.ForceProtocol != "" && !validProtocols[strings.ToLower(config.ForceProtocol)] {
		color.Red("Error: Force protocol must be 'http', 'https', 'http1.1', or 'http2.0'")
		return
	}

	if pathPrefixesStr != "" {
		prefixes := strings.Split(pathPrefixesStr, ",")
		config.PathPrefixes = make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			trimmed := strings.TrimSpace(prefix)
			if trimmed != "" {
				sanitized := sanitizePrefix(trimmed)
				if sanitized != "" {
					config.PathPrefixes = append(config.PathPrefixes, sanitized)
				}
			}
		}
	}

	writer, err := NewOutputWriter(config.OutputFile)
	if err != nil {
		color.Red("Error creating output file: %v", err)
		return
	}
	defer writer.Close()

	file, err := os.Open(config.Filename)
	if err != nil {
		color.Red("Error opening file: %v", err)
		return
	}
	defer file.Close()

	printHeader(writer)
	basePaths, customPaths := buildPaths(&config)
	stats := ScanStats{
		TotalDomains: 0,
		BasePaths:    len(basePaths),
		CustomPaths:  len(customPaths),
		StartTime:    time.Now(),
	}

	writer.WriteColor(color.New(color.FgCyan), "Configuration:\n")
	if config.ForceProtocol != "" {
		writer.WriteColor(color.New(color.FgWhite), " Protocol: %s\n", strings.ToUpper(config.ForceProtocol))
	} else {
		writer.WriteColor(color.New(color.FgWhite), " Protocol: Auto-detect\n")
	}
	if len(config.PathPrefixes) > 0 {
		writer.WriteColor(color.New(color.FgWhite), " Path Prefixes: %s\n", strings.Join(config.PathPrefixes, ", "))
		writer.WriteColor(color.New(color.FgWhite), " Base paths: %d | Custom paths: %d\n", stats.BasePaths, stats.CustomPaths)
	} else {
		writer.WriteColor(color.New(color.FgWhite), " Path Prefixes: None\n")
		writer.WriteColor(color.New(color.FgWhite), " Base paths: %d (no custom prefixes)\n", stats.BasePaths)
	}
	writer.WriteColor(color.New(color.FgWhite), " Threads: %d\n", config.Threads)
	if config.OutputFile != "" {
		writer.WriteColor(color.New(color.FgWhite), " Output: %s\n", config.OutputFile)
	}
	if config.DebugMode {
		writer.WriteColor(color.New(color.FgWhite), " Debug Mode: Enabled\n")
	}
	printSeparator('-', writer)

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}
	if len(domains) == 0 {
		writer.WriteColor(color.New(color.FgYellow), "No domains found in file\n")
		return
	}
	stats.TotalDomains = len(domains)
	writer.WriteColor(color.New(color.FgWhite), "Loaded %d domains for scanning...\n", stats.TotalDomains)

	results := make(chan ScanResult, len(domains)*(stats.BasePaths+stats.CustomPaths))
	semaphore := make(chan struct{}, config.Threads)
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			semaphore <- struct{}{}
			scanDomain(d, &config, results, writer)
			<-semaphore
		}(domain)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var vulnerableDomains []ScanResult
	var criticalDomains []ScanResult
	var mediumDomains []ScanResult
	var normalDomains []ScanResult

	for result := range results {
		if result.Vulnerable {
			vulnerableDomains = append(vulnerableDomains, result)
			switch result.SecretLevel {
			case "CRITICAL":
				criticalDomains = append(criticalDomains, result)
			case "MEDIUM":
				mediumDomains = append(mediumDomains, result)
			default:
				normalDomains = append(normalDomains, result)
			}
		}
	}
	stats.EndTime = time.Now()
	stats.VulnerableDomains = len(vulnerableDomains)
	stats.CriticalFindings = len(criticalDomains)
	stats.MediumFindings = len(mediumDomains)
	stats.NormalFindings = len(normalDomains)

	printSummary(vulnerableDomains, domains, config, stats, writer)
}

