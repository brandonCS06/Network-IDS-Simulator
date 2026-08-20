import argparse
import datetime
import logging
import re
import sys
from pathlib import Path
from typing import NamedTuple

import log_parser
from log_parser import Event


"""
Ubuntu log parser for converting sshd authentication activity and UFW firewall
packet logs into the canonical Events.json schema consumed by the Java IDS
engine.

The parser emits brute-force-ready SSH login events and port-scan-ready UFW
probe events. It supports both traditional syslog timestamps, such as:

    Aug 20 12:03:01 ubuntu sshd[1234]: Failed password for alice from ...

and ISO-8601 journal/auth exports, such as:

    2026-08-20T16:20:58.328302+00:00 UbuntuServer sshd-session[1680]: ...
"""


LOGGER = logging.getLogger(__name__)
UTC = datetime.timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = PROJECT_ROOT / "homelab_logs"
DEFAULT_OUTPUT = PROJECT_ROOT / "Events.json"

ISO_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[\w.@/-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[\w.@/-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

SSH_LOGIN_RE = re.compile(
    r"^(?P<outcome>Failed|Accepted)\s+"
    r"(?P<auth_method>\S+)\s+for\s+"
    r"(?:(?P<invalid_user>invalid user)\s+)?"
    r"(?P<user>.+?)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+"
    r"(?P<source_port>\d+)\s+"
    r"(?P<ssh_version>\S+)"
    r"(?:\s|$)"
)

UFW_ACTION_RE = re.compile(r"^\[UFW\s+(?P<action>[^\]]+)\]\s+(?P<body>.*)$")
UFW_KEY_VALUE_RE = re.compile(r"(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>\S*)")
TCP_FLAG_TOKENS = {
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
    "ECE",
    "CWR",
}


class ParsedLogLine(NamedTuple):
    timestamp: int
    hostname: str
    process: str
    pid: str | None
    message: str


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse Ubuntu auth logs into Events.json for the Java IDS core."
    )
    parser.add_argument(
        "--input",
        help=(
            "Path to a Ubuntu auth/UFW log file or directory. "
            f"Defaults to parsing all files under {DEFAULT_INPUT_DIR}."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output path for Events.json (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.datetime.now(UTC).year,
        help="Year to apply to syslog timestamps that do not include one.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()
    configure_logging(args.verbose)

    input_path = Path(args.input).resolve() if args.input else DEFAULT_INPUT_DIR.resolve()
    output_path = Path(args.output).resolve()

    try:
        events, skipped = parse_path(input_path, args.year)
        log_parser.write_events(events, str(output_path))
    except FileNotFoundError:
        LOGGER.error("Input file not found: %s", input_path)
        return 1
    except (OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1

    LOGGER.info("Wrote %d event(s) to %s", len(events), output_path)
    if skipped:
        LOGGER.info("Skipped %d unsupported or blank line(s)", skipped)
    return 0


def parse_path(path: Path, syslog_year: int | None = None) -> tuple[list[Event], int]:
    if path.is_dir():
        return parse_directory(path, syslog_year)
    return parse_file(path, syslog_year)


def parse_directory(path: Path, syslog_year: int | None = None) -> tuple[list[Event], int]:
    events: list[Event] = []
    skipped = 0
    log_files = sorted(p for p in path.iterdir() if p.is_file())
    if not log_files:
        raise ValueError(f"No log files found in directory: {path}")

    for log_file in log_files:
        file_events, file_skipped = parse_file(log_file, syslog_year)
        events.extend(file_events)
        skipped += file_skipped

    return events, skipped


def parse_file(path: Path, syslog_year: int | None = None) -> tuple[list[Event], int]:
    events: list[Event] = []
    skipped = 0
    year = syslog_year or datetime.datetime.now(UTC).year

    with path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            event = parse_line(line.rstrip("\n"), line_number, year)
            if event is None:
                skipped += 1
                continue
            log_parser.validate_event(event)
            events.append(event)

    return events, skipped


def parse_line(line: str, line_number: int = 0, syslog_year: int | None = None) -> Event | None:
    if not line.strip():
        return None

    parsed = parse_log_envelope(line, syslog_year or datetime.datetime.now(UTC).year)
    if parsed is None:
        LOGGER.debug("Skipping unrecognized log envelope on line %s: %s", line_number, line)
        return None

    if parsed.process.startswith("sshd"):
        return parse_ssh_login_message(parsed, line, line_number)

    if parsed.process == "kernel" and parsed.message.startswith("[UFW "):
        return parse_ufw_message(parsed, line)

    LOGGER.debug("Skipping unsupported process on line %s from %s", line_number, parsed.process)
    return None


def parse_ssh_login_message(parsed: ParsedLogLine, raw_line: str, line_number: int = 0) -> Event | None:
    login_match = SSH_LOGIN_RE.match(parsed.message)
    if login_match is None:
        LOGGER.debug("Skipping unsupported sshd message on line %s: %s", line_number, parsed.message)
        return None

    values = login_match.groupdict()
    action = "LOGIN_FAIL" if values["outcome"] == "Failed" else "LOGIN_SUCCESS"
    metadata = {
        "hostname": parsed.hostname,
        "process": parsed.process,
        "auth_method": values["auth_method"],
        "source_port": int(values["source_port"]),
        "protocol": "SSH",
        "ssh_version": values["ssh_version"],
        "raw_line": raw_line,
    }
    if parsed.pid is not None:
        metadata["pid"] = int(parsed.pid)
    if values["invalid_user"] is not None:
        metadata["invalid_user"] = True

    event: Event = {
        "timestamp": parsed.timestamp,
        "source_ip": values["source_ip"],
        "user": values["user"].strip(),
        "action": action,
        "target": "sshd",
        "metadata": metadata,
    }
    return event


def parse_ufw_message(parsed: ParsedLogLine, raw_line: str) -> Event | None:
    action_match = UFW_ACTION_RE.match(parsed.message)
    if action_match is None:
        return None

    firewall_action = action_match.group("action").strip()
    fields = parse_ufw_key_values(action_match.group("body"))
    source_ip = fields.get("SRC")
    destination_ip = fields.get("DST")
    destination_port = coerce_optional_int(fields.get("DPT"))
    if not source_ip or not destination_ip or destination_port is None:
        LOGGER.debug("Skipping malformed UFW message: %s", parsed.message)
        return None

    protocol = fields.get("PROTO", "").upper()
    metadata = {
        "hostname": parsed.hostname,
        "process": parsed.process,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "firewall_action": firewall_action,
        "raw_line": raw_line,
    }

    field_mappings = {
        "IN": "interface_in",
        "OUT": "interface_out",
        "LEN": "packet_length",
        "TTL": "ttl",
        "WINDOW": "window",
        "SPT": "source_port",
    }
    for ufw_key, metadata_key in field_mappings.items():
        value = fields.get(ufw_key)
        if value in (None, ""):
            continue
        parsed_int = coerce_optional_int(value)
        metadata[metadata_key] = parsed_int if parsed_int is not None else value

    flags = parse_ufw_flags(parsed.message)
    if flags:
        metadata["tcp_flags"] = " ".join(flags)
        normalized_flags = {flag.upper() for flag in flags}
        if "SYN" in normalized_flags:
            metadata["syn"] = True
        if "ACK" in normalized_flags:
            metadata["ack"] = True

    event: Event = {
        "timestamp": parsed.timestamp,
        "source_ip": source_ip,
        "user": "unknown",
        "action": "PROBE",
        "target": destination_ip,
        "metadata": metadata,
    }
    return event


def parse_ufw_key_values(message: str) -> dict[str, str]:
    return {match.group("key"): match.group("value") for match in UFW_KEY_VALUE_RE.finditer(message)}


def parse_ufw_flags(message: str) -> list[str]:
    fields = parse_ufw_key_values(message)
    flags: list[str] = []
    seen_keys = set(fields.keys())
    for token in message.split():
        flag = token.strip()
        if flag in TCP_FLAG_TOKENS and flag not in seen_keys:
            flags.append(flag)
    return flags


def coerce_optional_int(value: str | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_log_envelope(line: str, syslog_year: int) -> ParsedLogLine | None:
    iso_match = ISO_LOG_RE.match(line)
    if iso_match is not None:
        values = iso_match.groupdict()
        return ParsedLogLine(
            timestamp=log_parser.coerce_timestamp(values["timestamp"]),
            hostname=values["hostname"],
            process=values["process"],
            pid=values["pid"],
            message=values["message"],
        )

    syslog_match = SYSLOG_RE.match(line)
    if syslog_match is None:
        return None

    values = syslog_match.groupdict()
    timestamp = parse_syslog_timestamp(
        values["month"],
        int(values["day"]),
        values["clock"],
        syslog_year,
    )
    return ParsedLogLine(
        timestamp=timestamp,
        hostname=values["hostname"],
        process=values["process"],
        pid=values["pid"],
        message=values["message"],
    )


def parse_syslog_timestamp(month: str, day: int, clock: str, year: int) -> int:
    try:
        parsed = datetime.datetime.strptime(
            f"{year} {month} {day} {clock}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError as exc:
        raise ValueError(f"invalid syslog timestamp: {month} {day} {clock}") from exc
    parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


if __name__ == "__main__":
    sys.exit(main())
