# Security Tools

AI-powered XSS scanner for authorized security testing.

## Features

- Crawl pages and extract parameters
- Test forms, URL params, headers, hidden inputs, and JSON bodies
- Generate smart payloads with AI support
- Verify findings in a browser
- Export reports as JSON or PDF

## Requirements

- Python 3.10+
- Windows, Linux, or macOS

## Install

```bat
git clone https://github.com/BalaTharun7331/security-tools.git
cd security-tools
pip install -r requirements.txt
```

If you already have the project locally:

```bat
cd /d C:\xss-scanner
pip install -r requirements.txt
```

## Run

### Windows

```bat
start.bat
```

Or run directly:

```bat
python dashboard\app.py
```

### Open the app

```text
http://127.0.0.1:5001
```

## How to Use

1. Open the web interface in your browser.
2. Enter the target URL.
3. Choose the scan mode if available.
4. Start the scan.
5. Wait for crawling and testing to finish.
6. Review the logs, findings, and reports.
7. Download JSON or PDF reports if needed.

## Reports

Available endpoints:

- `/report/json`
- `/report/pdf`

## Notes

- Only scan systems you own or have explicit permission to test.
- Some checks may require browser support or AI API keys.
- If the tool cannot start, verify that `requirements.txt` is installed and that Python is on PATH.

## Project Entry Points

- `start.bat`
- `dashboard/app.py`
- `requirements.txt`

