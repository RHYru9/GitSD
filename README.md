# Git Scanner Enhanced v2.1

## 🔍 Advanced Git Exposure & Secret Scanner

A simple, multi-threaded scanner to check for exposed Git repositories on websites. Helps you find accidentally exposed `.git` folders and see what's inside them.

### 🚀 Features

- **Multi-Protocol Support**: HTTP/1.1, HTTP/2.0, HTTP, HTTPS
- **Custom Path Scanning**: Configure custom prefixes for comprehensive coverage
- **Secret Detection**: Automatically identifies and categorizes sensitive information
- **Concurrent Scanning**: Multi-threaded architecture for faster results
- **Detailed Reporting**: Color-coded output with severity levels
- **Export Results**: Save scan results to file for further analysis

## 🛠️ Installation

### Prerequisites
- Go 1.19 or higher
- Internet connection for scanning targets

### Quick Install 

```bash
go install github.com/rhyru9/gitsd@v1.1.0
```

### Build from Source
```bash
git clone https://github.com/yourusername/git-scanner-enhanced.git
cd git-scanner-enhanced
go mod init git-scanner
go mod tidy
go build -o gitsd main.go
```

### Dependencies
The tool uses the following Go modules:
- `github.com/fatih/color` - Terminal color output
- `golang.org/x/net/http2` - HTTP/2 support
- `golang.org/x/term` - Terminal utilities

## 📋 Usage

### Basic Usage
```bash
# Scan domains from a file
./gitsd domains.txt

# Force HTTPS protocol
./gitsd -f https domains.txt

# Use custom path prefixes
./gitsd -p web,api,admin domains.txt

# Save results to file
./gitsd -o results.txt domains.txt
```

### Advanced Usage
```bash
# Scan with custom prefixes and increased threads
./gitsd -p web,api,test,admin,backup -t 20 domains.txt

# Force HTTP/2.0 with debug mode
./gitsd -f http2.0 -d domains.txt

# Full scan with all options
./gitsd -f https -p admin,backup,web -t 15 -o scan_results.txt domains.txt
```

## 🎯 Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--force` | `-f` | Force protocol (http/https/http1.1/http2.0) |
| `--paths` | `-p` | Custom path prefixes (comma-separated) |
| `--output` | `-o` | Output results to file |
| `--threads` | `-t` | Number of concurrent threads (default: 10) |
| `--debug` | `-d` | Enable debug mode |
| `--help` | `-h` | Show help message |

## 🔧 Path Logic

The scanner works with two types of paths:

### Standard Paths (STD)
Default Git paths that are automatically scanned:
- `/.git/config`
- `/.git/index`
- `/.git/HEAD`
- `/.git/logs/HEAD`
- And many more...

### Custom Paths (CST)
When you specify prefixes with `-p`, the scanner creates additional paths:
- Without `-p`: `domain.com/.git/config`
- With `-p web,api`: `domain.com/.git/config` + `domain.com/web/.git/config` + `domain.com/api/.git/config`

## 🏆 Detection Capabilities

### Vulnerability Detection
The scanner identifies exposed Git repositories by looking for:
- Git configuration files
- Git index files
- Git log files
- Repository metadata

### Secret Analysis
**Critical Secrets (🚨)**:
- GitHub Personal Access Tokens (`ghp_*`)
- GitLab Private Access Tokens (`glpat-*`)
- URLs with embedded credentials
- API tokens and OAuth credentials

**Medium Risk Secrets (⚠️)**:
- Git repository URLs
- Basic authentication credentials
- CI/CD tokens

**Standard Vulnerabilities (✓)**:
- Exposed Git configuration
- Repository structure information

## 📊 Output Format

The scanner provides detailed, color-coded output:

```
┌─ Scanning: https://example.com
    ├─ Base paths: 22 | Custom paths: 44
    ├─ [STD] /.git/config                    │ 🚨 200 VULNERABLE! (HTTP/2.0) [CRITICAL SECRETS]
    │      └─ CRITICAL Credentials: https://user:ghp_xxxx@github.com/repo.git
    ├─ [CST] /admin/.git/config              │ ⚠️  200 VULNERABLE! (HTTP/1.1) [MEDIUM SECRETS]
    │      └─ GitHub Repository: https://github.com/company/internal-repo.git
    └─ [STD] /.git/index                     │ ✓ 200 VULNERABLE! (HTTP/1.1)
└─ 🚨 CRITICAL SECRETS FOUND!
```

## 📝 Domain File Format

Create a text file with one domain per line:
```
example.com
test.example.com
api.company.com
admin.site.org
```

## 🔥 Pro Tips (The Real Shit)

### For Bug Bounty Hunters
- **Start with subdomains**: Use tools like `subfinder` or `amass` to get a comprehensive list
- **Check staging environments**: Look for `staging.`, `dev.`, `test.` subdomains
- **Don't forget about ports**: Some apps run on non-standard ports
- **Custom prefixes are your friend**: Try `api`, `admin`, `panel`, `dashboard`, `backup`

### For Penetration Testers
- **Document everything**: Use the `-o` flag to save results for your report
- **Check for false positives**: Not every 200 response is a real vulnerability
- **Follow up on secrets**: That GitHub token might give you access to private repos
- **Be fucking patient**: Some sites are slow, increase timeout if needed

### Common Prefixes to Try
```bash
# Web applications
./gitsd -p web,www,api,admin,panel,dashboard domains.txt

# Development environments  
./gitsd -p dev,test,staging,qa,uat,demo domains.txt

# Administrative interfaces
./gitsd -p admin,panel,manage,control,cp domains.txt

# Backup and legacy systems
./gitsd -p backup,old,legacy,archive,bak domains.txt
```

## ⚠️ Usage Notes

Just scan your own stuff or get permission first. This is for learning and testing, not for being a pain in the ass to random websites.

## 🤝 Contributing

Found a bug? Want to add a feature? Cool!

1. Fork it
2. Fix it
3. Test it
4. Send a pull request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by [GitTools](https://github.com/internetwache/GitTools.git) from **Internetwache**
- Thanks to the security research community for vulnerability research
- Special thanks to the Go community for excellent libraries
- Shoutout to all the bug bounty hunters who keep the internet safer

---

**Remember**: With great power comes great responsibility. Use this tool wisely, and always stay on the right side of the law. Happy hunting! 🎯

*P.S. - If you find some juicy secrets, don't forget to follow responsible disclosure. Nobody likes a script kiddie who goes straight to Twitter with their findings.*
