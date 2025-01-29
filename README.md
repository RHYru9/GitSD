# 🕵️ GitSD - Git Source Disclosure Vulnerability Scanner

## 🌐 Overview
GitSD is a Go-based tool designed to scan domains for Git source code disclosure vulnerabilities. It checks for exposed Git configuration and log files that might reveal sensitive project information.

## ✨ Features
- 🔍 Scan a list of domains
- 🕸️ Check for common Git-related exposed paths

## 💻 Installation
```bash
go install github.com/RHYru9/GitSD@latest
```

## 🚀 Usage
```bash
Usage: gitsd <file containing list of domains>
```

### 📝 Example
```bash
gitsd urls.txt
```

## 🔬 Scanned Paths
- `/.git/`
- `/.git/index`
- `/.git/logs/`
- `/.git/HEAD`
- `/.git/logs/HEAD`
- `/.git/logs/refs`
- `/.git/logs/refs/remotes/origin/master`
- `/.git/config`
- `/.git/description`
- `/.git/hooks/`
- `/.git/info/`
- `/.git/objects/`
- `/.git/refs/`

## 🚨 Vulnerability Detection
The tool checks for specific signs of vulnerability:
- `ref:`
- `index of`
- `initial commit`
- `update by push`
- `[core]`
- `repository`
- `bare = false`
- `filemode`
- `[remote`
- `[branch`
- `master`
- `origin`
- `HEAD branch:`
- `refs/heads/`
- `autopull`
- `repositoryformatversion`

## how it works:

- First, we check if the domain redirects somewhere
- If it does, we follow where it goes until we hit the final URL 
- Then use that final URL as our starting point to scan for Git stuff
- Finally, check if there's any Git exposure at the end

It's like following a trail - if a website tries to send us somewhere else, we follow the breadcrumbs until we get to where it actually lives, then start looking for Git folders there!

## 🚧 Output Example
```
[+] http://domain-8.tld
				[+] Following redirect to: https://domain-8.tld/
				[+] Domain redirects to: https://domain-8.tld/
				[+] Following redirect to: https://domain-8.tld/.git
				[+] path /.git/                                  | 404 not found
				[+] path /.git/index                             | 404 not found
				[+] Following redirect to: https://domain-8.tld/.git/logs
				[+] path /.git/logs/                             | 404 not found
				[+] path /.git/HEAD                              | 404 not found
				[+] path /.git/logs/HEAD                         | 404 not found
				[+] path /.git/logs/refs                         | 404 not found
				[+] path /.git/logs/refs/remotes/origin/master   | 404 not found
				[+] path /.git/config                            | 404 not found
				[+] path /.git/description                       | 404 not found
				[+] Following redirect to: https://domain-8.tld/.git/hooks
				[+] path /.git/hooks/                            | 404 not found
				[+] Following redirect to: https://domain-8.tld/.git/info
				[+] path /.git/info/                             | 404 not found
				[+] Following redirect to: https://domain-8.tld/.git/objects
				[+] path /.git/objects/                          | 404 not found
				[+] Following redirect to: https://domain-8.tld/.git/refs
				[+] path /.git/refs/                             | 404 not found
[+] http://domain-1.tld
				[+] path /.git/                                  | 403 forbidden
				[+] path /.git/index                             | 404 not found
				[+] path /.git/logs/                             | 403 forbidden
				[+] path /.git/HEAD                              | 200 vulnerable!
				[+] path /.git/logs/HEAD                         | 200 vulnerable!
				[+] Following redirect to: http://domain-1.tld/.git/logs/refs/
				[+] path /.git/logs/refs                         | 403 forbidden
				[+] path /.git/logs/refs/remotes/origin/master   | 404 not found
				[+] path /.git/config                            | 200 vulnerable!
				[+] path /.git/description                       | 200 vulnerable!
				[+] path /.git/hooks/                            | 403 forbidden
				[+] path /.git/info/                             | 403 forbidden
				[+] path /.git/objects/                          | 403 forbidden
				[+] path /.git/refs/                             | 403 forbidden
[+] http://domain-6.tld
				[+] Error following redirects: Get `http://domain-6.tld`: dial tcp: lookup domain-6.tld: no such host

[+] Found 4 vulnerable domains:
[+] domain-1.tld
[+] domain-2.tld
[+] domain-3.tld
[+] domain-4.tld
```

## ⚠️ Disclaimer
**Use only on domains you have permission to test. Unauthorized scanning may be illegal.**
