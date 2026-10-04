import os
import tempfile
import unittest

import loglens


def make_log(lines, binary=False):
    """Write lines to a temporary log file and return its path."""
    handle = tempfile.NamedTemporaryFile(
        "wb" if binary else "w", suffix=".log", delete=False
    )
    with handle as f:
        for line in lines:
            f.write(line if binary else line + "\n")
    return handle.name


def failed(sec, ip="192.0.2.1", user="root"):
    return (
        f"Oct  5 03:00:{sec:02d} host sshd[1]: "
        f"Failed password for {user} from {ip} port 22 ssh2"
    )


def accepted(sec, ip="192.0.2.1", user="root"):
    return (
        f"Oct  5 03:00:{sec:02d} host sshd[1]: "
        f"Accepted password for {user} from {ip} port 22 ssh2"
    )


class TestParseTime(unittest.TestCase):
    def test_old_style_time(self):
        text, ts = loglens.parse_time("Oct  5 03:00:30 host sshd[1]: x")
        self.assertEqual(text, "Oct 5 03:00:30")
        self.assertEqual((ts.month, ts.day, ts.second), (10, 5, 30))

    def test_iso_time(self):
        line = "2026-10-05T03:00:30.123456+04:00 host sshd[1]: x"
        text, ts = loglens.parse_time(line)
        self.assertEqual(text, "2026-10-05 03:00:30")
        self.assertEqual((ts.year, ts.month, ts.hour), (2026, 10, 3))

    def test_garbage_time_gives_none(self):
        _, ts = loglens.parse_time("not a real log line")
        self.assertIsNone(ts)


class TestDetection(unittest.TestCase):
    def analyze(self, lines, **kw):
        path = make_log(lines, **kw)
        self.addCleanup(os.remove, path)
        return loglens.analyze(loglens.read_log(path))

    def test_five_fast_failures_are_flagged_as_burst(self):
        rows = self.analyze([failed(s) for s in range(5)])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["Rapid Brute Force"])

    def test_slow_failures_are_not_a_burst(self):
        lines = [
            f"Oct  5 0{h}:00:00 host sshd[1]: "
            f"Failed password for root from 192.0.2.1 port 22 ssh2"
            for h in range(5)
        ]
        rows = self.analyze(lines)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["Rapid Brute Force"])

    def test_few_failures_are_ignored(self):
        self.assertEqual(self.analyze([failed(0), failed(1)]), [])

    def test_login_after_failures_is_flagged(self):
        lines = [failed(s) for s in range(5)] + [accepted(30)]
        rows = self.analyze(lines)
        self.assertEqual(rows[0]["Login After Failures"], "root")

    def test_login_after_few_failures_is_still_flagged(self):
        # Only 3 failures (below THRESHOLD) but then a successful login.
        lines = [failed(s) for s in range(3)] + [accepted(30)]
        rows = self.analyze(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Severity"], "high")

    def test_login_before_failures_is_not_flagged(self):
        lines = [accepted(0)] + [failed(s) for s in range(1, 6)]
        rows = self.analyze(lines)
        self.assertEqual(rows[0]["Login After Failures"], "")

    def test_many_usernames(self):
        users = ["root", "admin", "test", "pi", "oracle"]
        rows = self.analyze([failed(i, user=u) for i, u in enumerate(users)])
        self.assertTrue(rows[0]["Many Usernames"])

    def test_invalid_user_lines_are_counted(self):
        line = (
            "Oct  5 03:00:01 host sshd[1]: Failed password for invalid user "
            "bob from 192.0.2.1 port 22 ssh2"
        )
        rows = self.analyze([line] * 5)
        self.assertEqual(rows[0]["Users"], "bob")

    def test_weird_bytes_do_not_crash(self):
        lines = [(failed(s) + "\n").encode() for s in range(5)]
        lines.append(b"Oct  5 03:00:59 host junk \xff\xfe\xfa\n")
        rows = self.analyze(lines, binary=True)
        self.assertEqual(len(rows), 1)


class TestSeverity(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(loglens.get_severity(5), "medium")
        self.assertEqual(loglens.get_severity(10), "high")
        self.assertEqual(loglens.get_severity(20), "critical")


if __name__ == "__main__":
    unittest.main()