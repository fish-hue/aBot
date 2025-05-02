---

aBot.py — Web Vulnerability Scanner

**aBot.py** is a Python GUI application that performs **asynchronous web crawling** and **vulnerability testing**. It allows security researchers and developers to quickly scan websites for common vulnerabilities like **XSS** and **Command Injection**, with options for proxies, custom headers, and cookies.

---

## Features

- **Graphical User Interface** to control scans (Start, Pause, Resume, Stop, Save)
- **Async crawling** of links up to a user-defined depth
- **Vulnerability tests** including:
  - Cross-site Scripting (XSS)
  - Command Injection
  - (Potential to extend for SQLi, Open Redirect, etc.)
- Support for **proxies**, **custom headers**, and **cookies**
- Live progress bar, logs, and statistics
- Export results as CSV
- Generate an HTML report with all findings
- CLI support for automation

---

## Requirements

- Python 3.7 or higher
- Dependencies:
  - `aiohttp`
  - `beautifulsoup4`
- (Tkinter is usually included with Python)

### Install dependencies:

```bash
pip install aiohttp beautifulsoup4
```

---

## Usage

### GUI Mode

1. Run the script:

```bash
python aBot.py
```

2. Enter the target URL and optional proxies, headers, cookies.
3. Click **Start** to begin scanning.
4. Use **Pause**, **Resume**, **Stop** controls as needed.
5. Watch live logs, progress, and stats.
6. Save results with the **Save Results** button.
7. After completion, an HTML report is generated (`report.html`).

---

### CLI Mode (for automation)

Run with command-line arguments:

```bash
python aBot.py --url http://targetsite.com --headers "User-Agent:MyScanner" --proxies "http://proxy1:port, http://proxy2:port"
```

---
