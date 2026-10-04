import csv
import re
import sys
from datetime import datetime

THRESHOLD = 5
RAPID_ATTEMPTS = 5
TIME_WINDOW = 60
MANY_USERNAMES = 3
HIGH_SEVERITY = 10
CRITICAL_SEVERITY = 20
LOGIN_AFTER_MIN_FAILS = 3
REPORT_FILENAME = "security_report.csv"

YEAR = datetime.now().year

failed_pattern = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+)"
)

success_pattern = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+)"
)

iso_time_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")


def parse_time(line):
    iso = iso_time_pattern.match(line)
    if iso:
        time_text = f"{iso.group(1)} {iso.group(2)}"
        try:
            return time_text, datetime.strptime(time_text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return time_text, None

    words = line.split()
    time_text = " ".join(words[:3])

    try:
        timestamp = datetime.strptime(
            f"{YEAR} {time_text}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        timestamp = None

    return time_text, timestamp


def read_log(filename):
    data = {
        "failed_count": {},
        "failed_names": {},
        "names_by_ip": {},
        "first_seen": {},
        "last_seen": {},
        "failed_times": {},
        "success_events": {},
    }

    with open(filename, "r", errors="replace") as file:
        for line in file:
            if "Failed password" in line:
                match = failed_pattern.search(line)
                if not match:
                    continue

                username, ip = match.groups()
                time_text, timestamp = parse_time(line)

                data["failed_count"][ip] = data["failed_count"].get(ip, 0) + 1
                data["failed_names"][username] = (
                    data["failed_names"].get(username, 0) + 1
                )
                data["names_by_ip"].setdefault(ip, set()).add(username)
                data["first_seen"].setdefault(ip, time_text)
                data["last_seen"][ip] = time_text

                if timestamp is not None:
                    data["failed_times"].setdefault(ip, []).append(timestamp)

            elif "Accepted password" in line or "Accepted publickey" in line:
                match = success_pattern.search(line)
                if not match:
                    continue

                username, ip = match.groups()
                _, timestamp = parse_time(line)
                data["success_events"].setdefault(ip, []).append(
                    (timestamp, username)
                )

    return data


def get_severity(count):
    if count >= CRITICAL_SEVERITY:
        return "critical"
    if count >= HIGH_SEVERITY:
        return "high"
    return "medium"


def has_rapid_attempts(timestamps):
    timestamps = sorted(timestamps)

    for i in range(len(timestamps)):
        attempts_in_window = 1

        for j in range(i + 1, len(timestamps)):
            difference = (timestamps[j] - timestamps[i]).total_seconds()

            if difference <= TIME_WINDOW:
                attempts_in_window += 1
            else:
                break

        if attempts_in_window >= RAPID_ATTEMPTS:
            return True

    return False


def logins_after_failures(ip, data):
    failed = data["failed_times"].get(ip, [])
    if not failed:
        return []

    first_failure = min(failed)
    users = set()

    for timestamp, username in data["success_events"].get(ip, []):
        if timestamp is not None and timestamp > first_failure:
            users.add(username)

    return sorted(users)


def analyze(data):
    rows = []

    ranked = sorted(
        data["failed_count"].items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for ip, count in ranked:
        if count >= LOGIN_AFTER_MIN_FAILS:
            after = logins_after_failures(ip, data)
        else:
            after = []

        if count < THRESHOLD and not after:
            continue

        severity = get_severity(count)
        if after and severity == "medium":
            severity = "high"

        usernames = sorted(data["names_by_ip"][ip])

        rows.append({
            "IP": ip,
            "Severity": severity,
            "Failed Attempts": count,
            "Users": ", ".join(usernames),
            "First Seen": data["first_seen"][ip],
            "Last Seen": data["last_seen"][ip],
            "Many Usernames": len(usernames) >= MANY_USERNAMES,
            "Rapid Brute Force": has_rapid_attempts(
                data["failed_times"].get(ip, [])
            ),
            "Login After Failures": ", ".join(after),
        })

    return rows


def print_report(data, rows):
    total_attempts = sum(data["failed_count"].values())
    total_successes = sum(len(v) for v in data["success_events"].values())

    print("Summary:")
    print(f"Total failed attempts: {total_attempts}")
    print(f"Total successful logins: {total_successes}")
    print(f"Unique IP addresses: {len(data['failed_count'])}")
    print(f"Unique targeted usernames: {len(data['failed_names'])}")
    print(f"Suspicious IP addresses: {len(rows)}")

    print("\nSuspicious IP addresses:")
    if not rows:
        print("None found.")

    for row in rows:
        print(
            f"\n[{row['Severity']}]"
            f"\nIP address: {row['IP']}"
            f"\nUsers: {row['Users']}"
            f"\nFailed attempts: {row['Failed Attempts']}"
            f"\nFirst seen: {row['First Seen']}"
            f"\nLast seen: {row['Last Seen']}"
        )

        if row["Many Usernames"]:
            print(
                f"Tried many different usernames "
                f"({len(row['Users'].split(', '))})"
            )

        if row["Rapid Brute Force"]:
            print(
                f"Possible brute-force attack: "
                f"{RAPID_ATTEMPTS}+ attempts within {TIME_WINDOW} seconds"
            )

        if row["Login After Failures"]:
            print(
                f"Successful login AFTER the failed attempts "
                f"(users: {row['Login After Failures']})"
            )

    print("\nMost targeted usernames:")
    ranked_names = sorted(
        data["failed_names"].items(),
        key=lambda item: item[1],
        reverse=True,
    )
    for username, count in ranked_names:
        print(f"{username}: {count} failed attempts")

    print("\nSuccessful logins:")
    if not data["success_events"]:
        print("None found.")

    for ip, events in data["success_events"].items():
        users = ", ".join(sorted({username for _, username in events}))
        print(f"IP: {ip} | Successful logins: {len(events)} | Users: {users}")


def export_csv(rows):
    fieldnames = [
        "IP",
        "Severity",
        "Failed Attempts",
        "Users",
        "First Seen",
        "Last Seen",
        "Many Usernames",
        "Rapid Brute Force",
        "Login After Failures",
    ]

    with open(REPORT_FILENAME, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    if len(sys.argv) != 2:
        print("Usage: python loglens.py <logfile>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        data = read_log(filename)
    except FileNotFoundError:
        print(f"{filename} not found")
        sys.exit(1)
    except (PermissionError, IsADirectoryError):
        print(f"Cannot read {filename}")
        sys.exit(1)

    rows = analyze(data)
    print_report(data, rows)
    export_csv(rows)
    print(f"\nSecurity report exported to {REPORT_FILENAME}")


if __name__ == "__main__":
    main()
