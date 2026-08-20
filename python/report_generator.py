import argparse
import csv
import datetime
import html
import json
import logging
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO, TypedDict


LOGGER = logging.getLogger(__name__)
UTC = datetime.timezone.utc


class Alert(TypedDict, total=False):
    timestamp: int
    rule_name: str
    severity: str
    source_ip: str
    target: str
    description: str
    recommendation: str
    metrics: dict[str, Any]
    evidence: list[dict[str, Any]]


@dataclass(frozen=True)
class ReportSummary:
    total: int
    by_rule: Counter[str]
    by_ip: Counter[str]
    by_severity: Counter[str]
    by_target: Counter[str]
    by_time_window: Counter[str]


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def default_alerts_path() -> Path:
    return Path(__file__).resolve().parent.parent / "Alerts.json"


def default_report_path(alerts_path: str | Path | None = None) -> Path:
    if alerts_path is None:
        alerts_path = default_alerts_path()
    return Path(alerts_path).resolve().with_name("report.html")


def format_utc_datetime(dt: datetime.datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z").replace("T", " ")


def load_alerts(path: str | Path | None = None) -> list[Alert]:
    if path is None:
        path = default_alerts_path()
    else:
        path = Path(path)
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Alerts file must contain a JSON array")
    return [coerce_alert(item, index) for index, item in enumerate(data)]


def coerce_alert(item: Any, index: int) -> Alert:
    if not isinstance(item, dict):
        raise ValueError(f"Alert at index {index} is not a JSON object")
    return item


def summarize(alerts: list[Alert]):
    """
    Backwards-compatible summary used by the original text report.
    """
    summary = build_summary(alerts)
    return summary.total, summary.by_rule, summary.by_ip


def build_summary(alerts: list[Alert], window_minutes: int = 5) -> ReportSummary:
    total = len(alerts)
    by_rule = Counter(alert.get("rule_name") or "UNKNOWN" for alert in alerts)
    by_ip = Counter(alert.get("source_ip") or "UNKNOWN" for alert in alerts)
    by_severity = Counter((alert.get("severity") or "UNKNOWN").lower() for alert in alerts)
    by_target = Counter(extract_target(alert) for alert in alerts)
    by_time_window = Counter(time_window(alert.get("timestamp"), window_minutes) for alert in alerts)
    return ReportSummary(total, by_rule, by_ip, by_severity, by_target, by_time_window)


def extract_target(alert: Alert) -> str:
    target = alert.get("target")
    if target:
        return str(target)
    evidence = alert.get("evidence") or []
    if evidence and isinstance(evidence[0], dict):
        evidence_target = evidence[0].get("target")
        if evidence_target:
            return str(evidence_target)
    return "UNKNOWN"


def time_window(timestamp: Any, window_minutes: int) -> str:
    if timestamp in (None, ""):
        return "UNKNOWN"
    try:
        epoch_ms = int(timestamp)
    except (TypeError, ValueError):
        return "UNKNOWN"
    window_ms = max(window_minutes, 1) * 60 * 1000
    bucket_start = epoch_ms - (epoch_ms % window_ms)
    dt = datetime.datetime.fromtimestamp(bucket_start / 1000, tz=UTC)
    return format_utc_datetime(dt)


def format_timestamp(timestamp: Any) -> str:
    if timestamp in (None, ""):
        return "UNKNOWN"
    try:
        epoch_ms = int(timestamp)
    except (TypeError, ValueError):
        return "UNKNOWN"
    dt = datetime.datetime.fromtimestamp(epoch_ms / 1000, tz=UTC)
    return format_utc_datetime(dt)


def compact_metrics(metrics: Any) -> str:
    if not isinstance(metrics, dict) or not metrics:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(metrics.items()))


def example_alerts(alerts: list[Alert], limit: int = 5) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda alert: (
            severity_rank(alert.get("severity")),
            int(alert.get("timestamp") or 0),
        ),
        reverse=True,
    )[:limit]


def severity_rank(severity: Any) -> int:
    value = str(severity or "").lower()
    if value == "critical":
        return 4
    if value == "high":
        return 3
    if value in {"medium", "med"}:
        return 2
    if value == "low":
        return 1
    return 0


def format_text_report(
    total,
    by_rule,
    by_ip,
    alerts: list[Alert] | None = None,
    top_n: int = 5,
    by_severity: Counter[str] | None = None,
    by_target: Counter[str] | None = None,
    by_time_window: Counter[str] | None = None,
) -> str:
    lines: list[str] = []
    lines.append("IDS ALERT REPORT")
    lines.append("----------------")
    lines.append(f"Total Alerts: {total}")
    lines.append("")
    lines.append("Alerts by Rule:")
    for rule, count in by_rule.most_common():
        lines.append(f"{rule}: {count}")

    if by_severity is not None:
        lines.append("")
        lines.append("Alerts by Severity:")
        for severity, count in by_severity.most_common():
            lines.append(f"{severity}: {count}")

    lines.append("")
    lines.append("Top Attacker IPs:")
    for ip, count in by_ip.most_common(top_n):
        lines.append(f"{ip}: {count}")

    if by_target is not None:
        lines.append("")
        lines.append("Top Targets:")
        for target, count in by_target.most_common(top_n):
            lines.append(f"{target}: {count}")

    if by_time_window is not None:
        lines.append("")
        lines.append("Alerts by Time Window:")
        for window, count in sorted(by_time_window.items()):
            lines.append(f"{window}: {count}")

    if alerts:
        lines.append("")
        lines.append("Example Alert Details:")
        for alert in example_alerts(alerts, top_n):
            lines.append(
                f"- {format_timestamp(alert.get('timestamp'))} | "
                f"{alert.get('rule_name', 'UNKNOWN')} | "
                f"{alert.get('source_ip', 'UNKNOWN')} | "
                f"{alert.get('severity', 'UNKNOWN')}"
            )
            description = alert.get("description")
            if description:
                lines.append(f"  Why: {description}")
            metrics = compact_metrics(alert.get("metrics"))
            if metrics != "none":
                lines.append(f"  Metrics: {metrics}")
            recommendation = alert.get("recommendation")
            if recommendation:
                lines.append(f"  Next step: {recommendation}")

    return "\n".join(lines)


def alert_to_jsonable(alert: Alert) -> dict[str, Any]:
    return {
        "timestamp": alert.get("timestamp"),
        "time": format_timestamp(alert.get("timestamp")),
        "rule_name": alert.get("rule_name"),
        "severity": alert.get("severity"),
        "source_ip": alert.get("source_ip"),
        "target": extract_target(alert),
        "description": alert.get("description"),
        "recommendation": alert.get("recommendation"),
        "metrics": alert.get("metrics") or {},
    }


def summary_to_jsonable(summary: ReportSummary, alerts: list[Alert] | None = None, top_n: int = 5) -> dict[str, Any]:
    alerts = alerts or []
    return {
        "total": summary.total,
        "by_rule": dict(summary.by_rule.most_common()),
        "by_severity": dict(summary.by_severity.most_common()),
        "top_source_ips": dict(summary.by_ip.most_common(top_n)),
        "top_targets": dict(summary.by_target.most_common(top_n)),
        "by_time_window": dict(sorted(summary.by_time_window.items())),
        "example_alerts": [alert_to_jsonable(alert) for alert in example_alerts(alerts, top_n)],
    }


def write_json_report(summary: ReportSummary, alerts: list[Alert], stream: TextIO, top_n: int = 5) -> None:
    json.dump(summary_to_jsonable(summary, alerts, top_n), stream, indent=4)
    stream.write("\n")


def write_csv_report(summary: ReportSummary, alerts: list[Alert], stream: TextIO, top_n: int = 5) -> None:
    writer = csv.DictWriter(stream, fieldnames=["category", "value", "count", "description", "metrics"])
    writer.writeheader()
    write_counter_rows(writer, "rule", summary.by_rule)
    write_counter_rows(writer, "severity", summary.by_severity)
    write_counter_rows(writer, "source_ip", Counter(dict(summary.by_ip.most_common(top_n))))
    write_counter_rows(writer, "target", Counter(dict(summary.by_target.most_common(top_n))))
    write_counter_rows(writer, "time_window", Counter(dict(sorted(summary.by_time_window.items()))))
    for alert in example_alerts(alerts, top_n):
        writer.writerow(
            {
                "category": "example_alert",
                "value": f"{alert.get('rule_name', 'UNKNOWN')}:{alert.get('source_ip', 'UNKNOWN')}",
                "count": 1,
                "description": alert.get("description") or "",
                "metrics": json.dumps(alert.get("metrics") or {}, sort_keys=True),
            }
        )


def write_counter_rows(writer: csv.DictWriter, category: str, counter: Counter[str]) -> None:
    for value, count in counter.items():
        writer.writerow({"category": category, "value": value, "count": count, "description": "", "metrics": ""})


def render_counter_table(title: str, counter: Counter[str], limit: int | None = None) -> str:
    rows = counter.most_common(limit)
    if not rows:
        return f"<section><h2>{html.escape(title)}</h2><p>No data.</p></section>"

    body = "\n".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(html.escape(str(value)), count)
        for value, count in rows
    )
    return (
        f"<section><h2>{html.escape(title)}</h2>"
        "<table><thead><tr><th>Value</th><th>Count</th></tr></thead>"
        f"<tbody>{body}</tbody></table></section>"
    )


def render_metric_chips(metrics: Any) -> str:
    if not isinstance(metrics, dict) or not metrics:
        return "<span class=\"muted\">No metrics</span>"
    chips = []
    for key, value in sorted(metrics.items()):
        if isinstance(value, (dict, list)):
            rendered_value = json.dumps(value, sort_keys=True)
        else:
            rendered_value = str(value)
        chips.append(
            "<span class=\"chip\"><strong>{}</strong>{}</span>".format(
                html.escape(str(key)),
                html.escape(rendered_value),
            )
        )
    return "".join(chips)


def render_alert_cards(alerts: list[Alert], top_n: int) -> str:
    cards = []
    for alert in example_alerts(alerts, top_n):
        cards.append(
            """
            <article class="alert-card">
                <div class="alert-meta">
                    <span>{time}</span>
                    <span>{severity}</span>
                    <span>{source_ip}</span>
                </div>
                <h3>{rule}</h3>
                <p>{description}</p>
                <div class="metrics">{metrics}</div>
                <p class="recommendation">{recommendation}</p>
            </article>
            """.format(
                time=html.escape(format_timestamp(alert.get("timestamp"))),
                severity=html.escape(str(alert.get("severity") or "UNKNOWN")),
                source_ip=html.escape(str(alert.get("source_ip") or "UNKNOWN")),
                rule=html.escape(str(alert.get("rule_name") or "UNKNOWN")),
                description=html.escape(str(alert.get("description") or "No explanation available.")),
                metrics=render_metric_chips(alert.get("metrics")),
                recommendation=html.escape(str(alert.get("recommendation") or "")),
            )
        )
    if not cards:
        return "<section><h2>Alert Details</h2><p>No alerts found.</p></section>"
    return "<section><h2>Alert Details</h2>{}</section>".format("\n".join(cards))


def format_html_report(summary: ReportSummary, alerts: list[Alert], top_n: int = 5) -> str:
    generated_at = format_utc_datetime(datetime.datetime.now(UTC))
    most_common_rule = summary.by_rule.most_common(1)[0][0] if summary.by_rule else "None"
    unique_sources = len(summary.by_ip)

    return """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IDS Alert Report</title>
    <style>
        :root {{
            color-scheme: light;
            font-family: Arial, Helvetica, sans-serif;
            background: #324045;
            color: #91AFC9;
        }}
        body {{
            margin: 0;
            padding: 32px;
        }}
        main {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            margin-bottom: 24px;
        }}
        h1, h2, h3 {{
            margin: 0;
        }}
        h1 {{
            font-size: 32px;
        }}
        h2 {{
            font-size: 20px;
            margin: 24px 0 12px;
        }}
        h3 {{
            font-size: 18px;
            margin-top: 10px;
        }}
        .muted {{
            color: #497065;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin: 24px 0;
        }}
        .stat, .alert-card, table {{
            background: #1B2426;
            border: 1px solid #1A2430;
            border-radius: 8px;
            box-shadow: 0 1px 2px rgba(14, 30, 37, 0.06);
        }}
        .stat {{
            padding: 16px;
        }}
        .stat strong {{
            display: block;
            font-size: 28px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
        }}
        th, td {{
            padding: 10px 12px;
            border-bottom: 1px solid #1A2430;
            text-align: left;
        }}
        th {{
            background: #41615D;
        }}
        .alert-card {{
            padding: 18px;
            margin-bottom: 12px;
        }}
        .alert-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            color: #415861;
            font-size: 13px;
        }}
        .metrics {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 12px 0;
        }}
        .chip {{
            display: inline-flex;
            gap: 6px;
            align-items: center;
            padding: 6px 8px;
            background: #eef7f1;
            border: 1px solid #c9e7d2;
            border-radius: 999px;
            font-size: 13px;
        }}
        .recommendation {{
            color: #728FAB;
        }}
    </style>
</head>
<body>
<main>
    <header>
        <h1>IDS Alert Report</h1>
        <p class="muted">Generated {generated_at}</p>
    </header>
    <section class="stats">
        <div class="stat"><span>Total alerts</span><strong>{total}</strong></div>
        <div class="stat"><span>Unique sources</span><strong>{unique_sources}</strong></div>
        <div class="stat"><span>Most common rule</span><strong>{most_common_rule}</strong></div>
    </section>
    {by_rule}
    {by_severity}
    {top_sources}
    {top_targets}
    {alert_cards}
</main>
</body>
</html>
""".format(
        generated_at=html.escape(generated_at),
        total=summary.total,
        unique_sources=unique_sources,
        most_common_rule=html.escape(most_common_rule),
        by_rule=render_counter_table("Alerts by Rule", summary.by_rule),
        by_severity=render_counter_table("Alerts by Severity", summary.by_severity),
        top_sources=render_counter_table("Top Source IPs", summary.by_ip, top_n),
        top_targets=render_counter_table("Top Targets", summary.by_target, top_n),
        alert_cards=render_alert_cards(alerts, top_n),
    )


def write_html_report(summary: ReportSummary, alerts: list[Alert], stream: TextIO, top_n: int = 5) -> None:
    stream.write(format_html_report(summary, alerts, top_n))
    stream.write("\n")


def write_report(summary: ReportSummary, alerts: list[Alert], output_format: str, output: str | Path | None, top_n: int) -> None:
    if output is None:
        stream = sys.stdout
        close_stream = False
    else:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stream = output_path.open("w", encoding="utf-8", newline="")
        close_stream = True

    try:
        if output_format == "text":
            report = format_text_report(
                summary.total,
                summary.by_rule,
                summary.by_ip,
                alerts=alerts,
                top_n=top_n,
                by_severity=summary.by_severity,
                by_target=summary.by_target,
                by_time_window=summary.by_time_window,
            )
            print(report, file=stream)
        elif output_format == "json":
            write_json_report(summary, alerts, stream, top_n)
        elif output_format == "csv":
            write_csv_report(summary, alerts, stream, top_n)
        elif output_format == "html":
            write_html_report(summary, alerts, stream, top_n)
        else:
            raise ValueError(f"unsupported report format: {output_format}")
    finally:
        if close_stream:
            stream.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an IDS alert summary report.")
    parser.add_argument("--input", default=str(default_alerts_path()), help="Path to Alerts.json.")
    parser.add_argument(
        "--output",
        help="Optional report output path. Defaults to report.html next to the input alerts file for HTML reports and stdout for other formats.",
    )
    parser.add_argument("--format", choices=["text", "json", "csv", "html"], default="html", help="Report format.")
    parser.add_argument("--top_n", type=int, default=5, help="Number of top IPs and targets to include.")
    parser.add_argument("--window_minutes", type=int, default=5, help="Time bucket size for alert counts.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        alerts = load_alerts(args.input)
        summary = build_summary(alerts, window_minutes=args.window_minutes)
        output = args.output
        if output is None and args.format == "html":
            output = default_report_path(args.input)
        write_report(summary, alerts, args.format, output, args.top_n)
        if output is not None:
            LOGGER.info("Wrote %s report to %s", args.format, Path(output).resolve())
    except FileNotFoundError:
        LOGGER.error(
            "Alerts file not found: %s. Generate alerts by running IDSCore or placing Alerts.json there.",
            args.input,
        )
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
