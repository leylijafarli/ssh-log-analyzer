# LogLens

A small Python tool that reads a Linux authentication log (`auth.log`) and finds signs of brute-force login attempts, such as someone guessing passwords again and again. It prints a clear report and saves a CSV file.

It is a mini version of what security analysts do every day: read logs, spot patterns, and decide what looks suspicious.

## What it detects

- **Failed logins per IP address**: who tried, how many times, and when (first and last attempt).
- **Fast bursts**: many failed attempts inside a short time window (a sign of an automated attack).
- **Many usernames from one IP**: guessing names like `root`, `admin`, `test`.
- **Login after failures**: a successful login that happened *after* the same IP started failing. This is the most dangerous case, because the guessing may have worked.
- **Severity level** for each suspicious IP: `medium`, `high` or `critical`.


## How to use

```
python loglens.py <logfile>
```

Try it with the included sample file:

```
python loglens.py sample_auth.log
```

The tool prints the report in the terminal and also writes `security_report.csv` in the current folder.

## Example output

```
Summary:
Total failed attempts: 8
Total successful logins: 2
Unique IP addresses: 2
Unique targeted usernames: 4
Suspicious IP addresses: 2

Suspicious IP addresses:

[high]
IP address: 192.0.2.99
Users: admin, root, test
Failed attempts: 5
First seen: Oct 5 03:00:30
Last seen: Oct 5 03:00:34
Tried many different usernames (3)
Possible brute-force attack: 5+ attempts within 60 seconds
Successful login AFTER the failed attempts (users: root)

[high]
IP address: 198.51.100.7
Users: pi
Failed attempts: 3
First seen: Oct 5 04:00:01
Last seen: Oct 5 04:00:03
Successful login AFTER the failed attempts (users: pi)
```

## Settings

All settings are at the top of `loglens.py`:

| Setting | Meaning | Default |
| `THRESHOLD` | Failed attempts before an IP counts as suspicious | 5 |
| `RAPID_ATTEMPTS` | Failures needed inside the time window to flag a burst | 5 |
| `TIME_WINDOW` | Length of the burst window, in seconds | 60 |
| `MANY_USERNAMES` | Different usernames from one IP that count as suspicious | 3 |
| `HIGH_SEVERITY` | Failed attempts for the `high` level | 10 |
| `CRITICAL_SEVERITY` | Failed attempts for the `critical` level | 20 |

## CSV report

`security_report.csv` has one row per suspicious IP, with these columns: IP, Severity, Failed Attempts, Users, First Seen, Last Seen, Many Usernames, Rapid Brute Force, Login After Failures.

## How it works

1. `read_log` goes through the file line by line and uses regular expressions to pull out the username, IP address and time from "Failed password" and "Accepted password/publickey" lines.
2. `analyze` ranks the IPs by failed attempts and checks each suspicious one for bursts, many usernames and logins after failures.
3. `print_report` and `export_csv` show the results.

## Known limits

- Log lines do not contain a year, so the tool assumes the current year. A log that crosses New Year (31 December to 1 January) can give wrong time differences.
- It only understands standard OpenSSH messages (`Failed password`, `Accepted password`, `Accepted publickey`) in the usual `auth.log` format.
- The sample file uses fake data and reserved example IP addresses.

## Ideas for the future

- Email or Telegram alerts
- Support for web server logs
- Automated tests
- Reading other log formats (for example `journalctl` output)
