# SecureOps Toolkit

A modern web application designed to help you learn essential DevOps commands and improve your security analysis skills. Features an interactive command reference guide with 45+ Docker, Git, and GitHub CLI commands, plus a rule-based log analyzer that detects common security threats and suspicious activity patterns. Built with Flask, Alpine.js, and Tailwind CSS for a clean, responsive experience.

## Features

- **Command Guide** — 45+ Docker, Git, and GitHub CLI commands with descriptions, flags, and usage examples
- **Log Analyzer** — Upload log files to detect security issues: failed logins, SSH attacks, privilege escalation, and more
- **Search & Filter** — Find commands by name, category, or workflow
- **Language Support** — Security detection in English and Swedish
- **Responsive Design** — Works on desktop, tablet, and mobile

## Quick Start

1. **Clone & setup** (requires Python 3.12+):
   ```bash
   git clone <repo-url>
   cd DevSecOps-App
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```

2. **Open** `http://localhost:5000`

## Run with Docker

```bash
docker-compose up --build
```
Or build manually: `docker build -t secureops-toolkit . && docker run -p 5000:5000 secureops-toolkit`

## Testing

Run all tests: `pytest tests/` (30 tests covering commands, log analysis, and routes)

## Project Structure

```
app.py                     Main Flask application
data/commands.json         Command database (45 entries)
templates/                 HTML pages (base, cheatsheet, analyze)
services/log_analyzer.py   Security detection rules
tests/                     Automated tests
Dockerfile                 Container configuration
requirements.txt           Python dependencies
```

## License

MIT
