import datetime
import json
import tempfile
import unittest
from pathlib import Path

import ubuntu_auth_parser


class UbuntuAuthParserTest(unittest.TestCase):
    def test_parse_failed_password_from_iso_log(self):
        line = (
            "2026-08-20T16:20:58.328302+00:00 UbuntuServer "
            "sshd-session[1680]: Failed password for vboxuser from 10.0.0.30 port 52604 ssh2"
        )

        event = ubuntu_auth_parser.parse_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        expected = datetime.datetime(
            2026, 8, 20, 16, 20, 58, 328302, tzinfo=datetime.timezone.utc
        )
        self.assertEqual(int(expected.timestamp() * 1000), event["timestamp"])
        self.assertEqual("10.0.0.30", event["source_ip"])
        self.assertEqual("vboxuser", event["user"])
        self.assertEqual("LOGIN_FAIL", event["action"])
        self.assertEqual("sshd", event["target"])
        self.assertEqual("UbuntuServer", event["metadata"]["hostname"])
        self.assertEqual("sshd-session", event["metadata"]["process"])
        self.assertEqual(1680, event["metadata"]["pid"])
        self.assertEqual("password", event["metadata"]["auth_method"])
        self.assertEqual(52604, event["metadata"]["source_port"])
        self.assertEqual("SSH", event["metadata"]["protocol"])

    def test_parse_accepted_publickey_from_syslog(self):
        line = (
            "Aug 20 12:03:01 ubuntu sshd[1234]: "
            "Accepted publickey for alice from 2001:db8::10 port 60022 ssh2"
        )

        event = ubuntu_auth_parser.parse_line(line, syslog_year=2026)

        self.assertIsNotNone(event)
        assert event is not None
        expected = datetime.datetime(2026, 8, 20, 12, 3, 1, tzinfo=datetime.timezone.utc)
        self.assertEqual(int(expected.timestamp() * 1000), event["timestamp"])
        self.assertEqual("2001:db8::10", event["source_ip"])
        self.assertEqual("alice", event["user"])
        self.assertEqual("LOGIN_SUCCESS", event["action"])
        self.assertEqual("publickey", event["metadata"]["auth_method"])

    def test_parse_invalid_user_failed_password(self):
        line = (
            "Aug 20 12:04:01 ubuntu sshd[1234]: "
            "Failed password for invalid user admin from 192.0.2.15 port 51444 ssh2"
        )

        event = ubuntu_auth_parser.parse_line(line, syslog_year=2026)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual("admin", event["user"])
        self.assertEqual("LOGIN_FAIL", event["action"])
        self.assertTrue(event["metadata"]["invalid_user"])

    def test_skip_non_sshd_and_unsupported_sshd_lines(self):
        sudo_line = (
            "2026-08-20T16:53:12.572272+00:00 UbuntuServer sudo: "
            "vboxuser : TTY=/dev/tty1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/grep"
        )
        disconnect_line = (
            "Aug 20 12:03:03 ubuntu sshd[1234]: "
            "Disconnected from authenticating user root 10.0.0.30 port 52604 [preauth]"
        )

        self.assertIsNone(ubuntu_auth_parser.parse_line(sudo_line))
        self.assertIsNone(ubuntu_auth_parser.parse_line(disconnect_line, syslog_year=2026))

    def test_parse_file_writes_valid_json_array(self):
        lines = [
            "2026-08-20T16:20:58.328302+00:00 UbuntuServer sshd-session[1680]: Failed password for vboxuser from 10.0.0.30 port 52604 ssh2",
            "2026-08-20T16:53:12.572272+00:00 UbuntuServer sudo: vboxuser : TTY=/dev/tty1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/grep",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            out_path = Path(temp_dir) / "Events.json"
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            events, skipped = ubuntu_auth_parser.parse_file(log_path, syslog_year=2026)
            ubuntu_auth_parser.log_parser.write_events(events, str(out_path))
            saved = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(1, len(events))
        self.assertEqual(1, skipped)
        self.assertEqual("LOGIN_FAIL", saved[0]["action"])


if __name__ == "__main__":
    unittest.main()
