import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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

    def test_parse_ufw_block_tcp_syn_from_iso_log(self):
        line = (
            "2026-08-20T21:21:26.389826+00:00 UbuntuServer kernel: "
            "[UFW BLOCK] IN=enp0s8 OUT= MAC=08:00:27:8e:2e:20:08:00:27:82:fb:5c:08:00 "
            "SRC=10.0.0.30 DST=10.0.0.10 LEN=44 TOS=0x00 PREC=0x00 TTL=58 ID=57963 "
            "PROTO=TCP SPT=41816 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0 "
        )

        event = ubuntu_auth_parser.parse_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        expected = datetime.datetime(
            2026, 8, 20, 21, 21, 26, 389826, tzinfo=datetime.timezone.utc
        )
        self.assertEqual(int(expected.timestamp() * 1000), event["timestamp"])
        self.assertEqual("10.0.0.30", event["source_ip"])
        self.assertEqual("unknown", event["user"])
        self.assertEqual("PROBE", event["action"])
        self.assertEqual("10.0.0.10", event["target"])
        self.assertEqual("10.0.0.10", event["metadata"]["destination_ip"])
        self.assertEqual(443, event["metadata"]["destination_port"])
        self.assertEqual(41816, event["metadata"]["source_port"])
        self.assertEqual("TCP", event["metadata"]["protocol"])
        self.assertEqual("BLOCK", event["metadata"]["firewall_action"])
        self.assertEqual("UbuntuServer", event["metadata"]["hostname"])
        self.assertEqual("kernel", event["metadata"]["process"])
        self.assertEqual("SYN", event["metadata"]["tcp_flags"])
        self.assertTrue(event["metadata"]["syn"])

    def test_parse_ufw_block_tcp_multiple_flags(self):
        line = (
            "2026-08-17T00:43:35.674688+00:00 UbuntuServer kernel: "
            "[UFW BLOCK] IN=enp0s8 OUT= MAC=08:00:27:8e:2e:20:08:00:27:82:fb:5c:08:00 "
            "SRC=10.0.0.30 DST=10.0.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=45 ID=24995 "
            "PROTO=TCP SPT=40036 DPT=22 WINDOW=256 RES=0x00 URG PSH SYN FIN URGP=0 "
        )

        event = ubuntu_auth_parser.parse_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(22, event["metadata"]["destination_port"])
        self.assertEqual("URG PSH SYN FIN", event["metadata"]["tcp_flags"])
        self.assertTrue(event["metadata"]["syn"])
        self.assertNotIn("ack", event["metadata"])

    def test_skip_malformed_ufw_line_without_destination_port(self):
        line = (
            "2026-08-20T21:21:26.389826+00:00 UbuntuServer kernel: "
            "[UFW BLOCK] IN=enp0s8 SRC=10.0.0.30 DST=10.0.0.10 PROTO=TCP SPT=41816 SYN"
        )

        self.assertIsNone(ubuntu_auth_parser.parse_line(line))

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

    def test_parse_file_with_mixed_ssh_ufw_and_unsupported_lines(self):
        lines = [
            "2026-08-20T16:20:58.328302+00:00 UbuntuServer sshd-session[1680]: Failed password for vboxuser from 10.0.0.30 port 52604 ssh2",
            "2026-08-20T21:21:26.389826+00:00 UbuntuServer kernel: [UFW BLOCK] IN=enp0s8 OUT= MAC=08:00:27:8e:2e:20:08:00:27:82:fb:5c:08:00 SRC=10.0.0.30 DST=10.0.0.10 LEN=44 TOS=0x00 PREC=0x00 TTL=58 ID=57963 PROTO=TCP SPT=41816 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0 ",
            "2026-08-20T16:53:12.572272+00:00 UbuntuServer sudo: vboxuser : TTY=/dev/tty1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/grep",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "mixed.log"
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            events, skipped = ubuntu_auth_parser.parse_file(log_path, syslog_year=2026)

        self.assertEqual(2, len(events))
        self.assertEqual(1, skipped)
        self.assertEqual("LOGIN_FAIL", events[0]["action"])
        self.assertEqual("PROBE", events[1]["action"])
        self.assertEqual(443, events[1]["metadata"]["destination_port"])

    def test_parse_directory_combines_log_files(self):
        ssh_line = (
            "2026-08-20T16:20:58.328302+00:00 UbuntuServer "
            "sshd-session[1680]: Failed password for vboxuser from 10.0.0.30 port 52604 ssh2"
        )
        ufw_line = (
            "2026-08-20T21:21:26.389826+00:00 UbuntuServer kernel: "
            "[UFW BLOCK] IN=enp0s8 OUT= SRC=10.0.0.30 DST=10.0.0.10 "
            "PROTO=TCP SPT=41816 DPT=443 SYN"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            (log_dir / "ssh_failed.log").write_text(ssh_line + "\n", encoding="utf-8")
            (log_dir / "ufw.log").write_text(ufw_line + "\n", encoding="utf-8")

            events, skipped = ubuntu_auth_parser.parse_directory(log_dir)

        self.assertEqual(2, len(events))
        self.assertEqual(0, skipped)
        self.assertEqual(["LOGIN_FAIL", "PROBE"], [event["action"] for event in events])

    def test_parse_path_uses_directory_when_given_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            (log_dir / "auth.log").write_text(
                "2026-08-20T16:20:58.328302+00:00 UbuntuServer "
                "sshd-session[1680]: Failed password for vboxuser from 10.0.0.30 port 52604 ssh2\n",
                encoding="utf-8",
            )

            events, skipped = ubuntu_auth_parser.parse_path(log_dir)

        self.assertEqual(1, len(events))
        self.assertEqual(0, skipped)
        self.assertEqual("LOGIN_FAIL", events[0]["action"])


if __name__ == "__main__":
    unittest.main()
