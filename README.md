# SSH Log Analyzer (LogLens)

A robust, modular Python utility designed to parse SSH authentication logs, detect brute-force attack patterns, analyze suspicious IP activity, and export clean CSV security reports.

## Features
* **Regex Parsing:** Extracts failed and successful logins alongside timestamps.
* **Brute-Force Detection:** Identifies rapid-fire login attempts within custom time windows.
* **Severity Ranking:** Classifies malicious IPs into medium, high, and critical threat levels.
* **Automated Reporting:** Generates a summary in the console and exports a `security_report.csv`.

## Usage
Run the script from your terminal by passing the log file as an argument:

```bash
python loglens.py <logfile>
