# IDS Simulator

An Intrusion Detection System (IDS) simulator that processes security events and detects suspicious activities using configurable detection rules. The system combines a Java-based event processing engine with Python utilities for log generation, parsing, and reporting.

## Overview

The IDS Simulator is designed to:
- **Simulate realistic network activity** with normal and attack patterns
- **Process security events** in real-time against detection rules
- **Detect threats** using rule-based analysis (e.g., brute force attacks)
- **Generate alerts** with evidence, plain-English explanations, recommendations, and computed metrics
- **Report findings** with summary statistics, alert details, and exportable text/JSON/CSV/HTML output

## Architecture

### Core Components

#### Java Engine (`src/main/java/com/ids/`)

- **IDSCore** - Main orchestrator that loads events, processes them through the rule engine, and exports alerts
- **RuleEngine** - Evaluates each security event against registered detection rules
- **RuleEngineRules** - Interface for implementing custom threat detection rules
- **BruteForceRule** - Detects brute force login attacks using a sliding time window with configurable thresholds
- **PortScanRule** - Detects when a single source IP attempts to connect to 30+ different ports within a 60 second window
- **IcmpSweepRule** - Detects when a single source host pings many different destination IPs within a short window
- **SuspiciousDnsRule** - Detects suspicious DNS tunneling patterns using repeated high-entropy or failed DNS queries within a sliding window
- **SynFloodRule** - Detects SYN flood patterns by tracking bursty TCP SYN traffic with low ACK completion over a short sliding window
- **SlidingWindow** - Time-based event window (1-minute default) for tracking events by source IP and action type
- **Event** - Canonical representation of a security event (timestamp, source IP, user, action, target, metadata)
- **Alert** - Generated when a rule detects suspicious activity; includes severity, rule name, supporting evidence, explanation text, analyst recommendations, and computed metrics
- **AlertManager** - Manages alert collection and exports to JSON format

#### Python Utilities (`python/`)

- **log_generator.py** - Generates synthetic security events with configurable normal and attack traffic patterns
- **log_parser.py** - Parses raw logs into the standardized Event format
- **report_generator.py** - Summarizes alerts with statistics by rule, source IP, top attackers, alert explanations, metrics, and default HTML output
- **demo.py** - Runs the demo pipeline end to end: generate events, run the Java IDS, and create an HTML report

### Data Flow

```
Events.json (input)
    |
    v
IDSCore.loadEvents()
    |
    v
RuleEngine.processEvent() [runs each event through all rules]
    |
    v
[Insert Rule Name].onEvent() [evaluates against detection logic]
    |
    v
AlertManager [accumulates alerts]
    |
    v
Alerts.json (output) + Report
```

## Getting Started

### Prerequisites

- **Java**: JDK 8 or later
- **Maven**: 3.6+ for building
- **Python**: 3.11+ for log generation, parsing, reporting, and tests

### Building

```bash
mvn clean compile
mvn package
```

### Try the Demo

Run the full demo pipeline with one command:

```bash
python python/demo.py
```

This will:
1. Generate synthetic network events
2. Compile the Java IDS
3. Run the IDS against the generated events
4. Generate a demo-friendly HTML report

By default, demo artifacts are written to `demo-output/`:

```text
demo-output/Events.json
demo-output/Alerts.json
demo-output/report.html
```

The script prints the HTML report path when it finishes. Open
`demo-output/report.html` in a browser to review the alert dashboard.
Existing demo artifacts are replaced on each run, and the default event
generation uses fresh randomness/current time so the report changes between
runs.

You can run a specific scenario:

```bash
python python/demo.py --scenario syn-flood
python python/demo.py --scenario port-scan
python python/demo.py --scenario dns-tunnel
```

You can also pass custom built-in rule thresholds:

```bash
python python/demo.py --rules rules.example.json
```

For a reproducible demo run, pass a seed and optional fixed base time:

```bash
python python/demo.py --seed 42 --base-time 2026-07-15T12:00:00Z
```

Custom Java rules still use the normal project workflow: implement the rule,
register it in `IDSCore`, then run the demo script so it compiles and executes
the updated project.

### Running the IDS

#### Basic Usage

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json
```

This will:
1. Load events from `Events.json`
2. Process them through registered detection rules
3. Export detected alerts to `Alerts.json`

#### With Custom Event File

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore path/to/events.json
```

#### With Custom Rule Thresholds

Copy `rules.example.json`, adjust the values you want to tune, then pass it as
the second argument:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json rules.example.json
```

### Python Utilities

#### Generate Synthetic Events

```bash
python python/log_generator.py --output Events.json --normal 1000 --seed 42
```

Generates events with a mix of normal activity and attack patterns. `--seed`
makes the same simulation reproducible for demos and tests. The legacy
`--count` flag is still supported as an alias for `--normal`.

To include suspicious DNS activity in the sample stream:

```bash
python python/log_generator.py --output Events.json --dnsattacks 1 --dns_queries_per_attack 6
```

This adds DNS events with metadata such as `protocol`, `query_name`, `qtype`, `rcode`, `response_size`, `label_length`, and `entropy` so the SuspiciousDnsRule can evaluate them.

To include ICMP sweep activity in the sample stream:

```bash
python python/log_generator.py --output Events.json --icmpsweeps 1 --icmp_targets_per_sweep 30
```

This adds ICMP echo request events with metadata such as `protocol`, `icmp_type`, and `destination_ip` so the IcmpSweepRule can evaluate them.

To include SYN flood activity in the sample stream:

```bash
python python/log_generator.py --output Events.json --synfloods 1 --syn_packets_per_flood 80 --acks_per_flood 5
```

This adds TCP SYN burst events (with sparse ACK completion) using metadata such as `protocol`, `destination_ip`, `destination_port`, `tcp_flags`, `syn`, and `ack` so the SynFloodRule can evaluate them.
The generator can also write JSON Lines or CSV for inspection and parser testing:

```bash
python python/log_generator.py --output sample-events.jsonl --output_format jsonl --seed 42
python python/log_generator.py --output sample-events.csv --output_format csv --seed 42
```

#### Normalize Raw Logs

```bash
python python/log_parser.py --input sample-events.jsonl --format jsonl --output Events.json
python python/log_parser.py --input sample-events.csv --format csv --output Events.json
```

The parser accepts `json`, `events-json`, `jsonl`, and `csv` input, validates
source and destination IP addresses with Python's `ipaddress` module, accepts
epoch-millisecond or ISO-8601 timestamps, and writes the Java-compatible
`Events.json` array.

#### Generate Report

```bash
python python/report_generator.py
```

Creates `report.html` next to the selected `Alerts.json` by default. The report includes:
- Total alert count
- Alerts by detection rule
- Alerts by severity
- Top attacking source IPs
- Top targets
- Alert counts by time window
- Example alert details with `description`, `recommendation`, and `metrics`

Reports can also be exported for automation:

```bash
python python/report_generator.py --format text
python python/report_generator.py --format json --output report.json
python python/report_generator.py --format csv --output report.csv
python python/report_generator.py --format html --output report.html
```

The HTML report is useful for demos because it turns `Alerts.json` into a readable dashboard with summary cards, breakdown tables, and alert cards that explain why each rule fired.

### Current Rules

#### BruteForceRule
- **Purpose**: Detects repeated failed login attempts from the same source IP
- **Window**: 1-minute sliding window
- **Threshold**: 5+ failed login events
- **Severity**: High
- **Evidence**: List of failed login events that triggered the alert
- **Metrics**: Failed login count, threshold, and detection window

#### PortScanRule
- **Purpose**: Detects when a single source IP attempts to connect to 30+ different ports within a 60-second window
- **Window**: 1-minute sliding window
- **Threshold**: 30+ different ports
- **Severity**: High
- **Evidence**: The recent events from the same source IP showing 30+ unique destination ports within a 60-second window
- **Metrics**: Unique destination port count, threshold, and detection window

#### IcmpSweepRule
- **Purpose**: Detects when a single source host pings 30+ distinct destination IPs within a 60-second window
- **Window**: 1-minute sliding window
- **Threshold**: 30+ different destination IPs
- **Severity**: High
- **Evidence**: The recent ICMP echo requests from the same source host showing 30+ unique destination IPs within a 60-second window
- **Metrics**: Unique destination IP count, ICMP type, threshold, and detection window

#### SuspiciousDnsRule
- **Purpose**: Detects suspicious DNS tunneling or exfiltration patterns by combining multiple DNS indicators over time
- **Window**: 1-minute sliding window
- **Indicators**: long query names, high entropy, suspicious qtypes such as TXT or NULL, failed DNS responses such as NXDOMAIN or SERVFAIL, and unusually large responses
- **Severity**: High
- **Evidence**: DNS events from the same source IP within the detection window
- **Metrics**: DNS event count, suspicion score, score threshold, detection window, and matched indicators

#### SynFloodRule
- **Purpose**: Detects likely SYN flood behavior from a source to a destination tuple
- **Window**: 10-second sliding window
- **Threshold**: 60+ SYN packets with ACK ratio below 0.20
- **Severity**: High
- **Evidence**: TCP events from the same source/destination tuple within the detection window
- **Metrics**: SYN count, ACK count, ACK ratio, destination IP/port, threshold, and detection window

### Adding Custom Rules

Implement the `RuleEngineRules` interface:

```java
public class CustomRule implements RuleEngineRules {
    @Override
    public List<Alert> onEvent(Event event) {
        // Your detection logic here
        if (threatDetected) {
            return List.of(new Alert(...));
        }
        return new ArrayList<>();
    }
}
```

Then register in `IDSCore`:

```java
ruleEngine.registerRule(new CustomRule());
```
For threshold configurations, register them in `rules.example.json`

## Event Schema

Events follow this JSON structure:

```json
{
  "timestamp": 1234567890000,
  "source_ip": "192.168.1.10",
  "user": "alice",
  "action": "LOGIN_SUCCESS",
  "target": "web_server",
  "metadata": {
        "session_id": "abc123",
        "duration_ms": 5000,
        "protocol": "[Protocol Name]", //Ex: DNS, ICMP, etc. 
        "query_name": "token.exfil.example.com",
        "qtype": "TXT",
        "rcode": "NXDOMAIN",
        "response_size": 600,
        "label_length": 24,
        "entropy": 4.8
  }
}
```

ICMP sweep events should include `icmp_type: 8`, and `destination_ip` in `metadata`.

## Alert Schema

Generated alerts include:

```json
{
  "timestamp": 1234567890000,
  "rule_name": "BruteForceRule",
  "severity": "high",
  "source_ip": "10.0.0.5",
  "description": "Source 10.0.0.5 produced 5 failed login attempts within 60 seconds, meeting the brute-force threshold of 5.",
  "recommendation": "Review authentication logs for the source IP, verify whether the user activity is legitimate, and consider rate limiting or temporary blocking.",
  "metrics": {
    "failed_login_count": 5,
    "threshold": 5,
    "window_ms": 60000,
    "window_seconds": 60
  },
  "evidence": [...]
}
```

The exact `metrics` fields depend on the rule. For example, `SynFloodRule` includes `syn_count`, `ack_count`, `ack_ratio`, `destination_ip`, and `destination_port`, while `SuspiciousDnsRule` includes `score` and `indicators`.

## Project Structure

```
IDS-simulator/
|-- pom.xml                     # Maven project configuration
|-- Alerts.json                 # Generated alerts output
|-- Events.json                 # Input events
|-- README.md                   # This file
|-- src/
|   `-- main/java/com/ids/
|       |-- IDSCore.java           # Main orchestrator
|       |-- RuleEngine.java        # Rule evaluation engine
|       |-- RuleEngineRules.java   # Rule interface
|       |-- BruteForceRule.java    # Brute force detection
|       |-- PortScanRule.java      # Port scan detection
|       |-- IcmpSweepRule.java     # ICMP sweep detection
|       |-- SynFloodRule.java      # SYN flood detection
|       |-- Event.java             # Event model
|       |-- Alert.java             # Alert model
|       |-- AlertManager.java      # Alert collection
|       |-- SlidingWindow.java     # Time-based event window
|       `-- SuspiciousDnsRule.java # DNS tunneling detection
`-- python/
    |-- demo.py                 # End-to-end demo runner
    |-- log_generator.py        # Synthetic event generation
    |-- log_parser.py           # Raw log parsing
    `-- report_generator.py     # Alert report generation
```

## Dependencies

- **GSON 2.10.1** - JSON serialization/deserialization
- **Java Compiler Source/Target**: Java 8

## Usage Examples

### Example 1: Generate Events and Run IDS

```bash
# Generate synthetic events
python python/log_generator.py --output Events.json --normal 500 --seed 42

# Compile the Java project
mvn clean compile

# Run the IDS
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json

# Generate the default HTML report
python python/report_generator.py
```

### Example 2: Process Custom Events

Place your `Events.json` file in the project root and run:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json
```

### Example 3: Parse CSV or JSONL Logs Before Running IDS

```bash
python python/log_parser.py --input raw-events.csv --format csv --output Events.json
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json
python python/report_generator.py --format json --output report.json
```

On Windows PowerShell, use `;` instead of `:` in the Java classpath:

```powershell
java -cp "target/classes;$env:USERPROFILE\.m2\repository\com\google\code\gson\gson\2.10.1\gson-2.10.1.jar" com.ids.IDSCore Events.json
```

## Configuration

### Python Simulation Settings

The generator accepts TOML or JSON config files for repeatable lab runs:

```toml
output = "Events.json"
output_format = "json"
normal = 500
attacks = 2
attempts_per_attack = 5
portscans = 1
ports_per_scan = 30
dnsattacks = 1
dns_queries_per_attack = 6
icmpsweeps = 1
icmp_targets_per_sweep = 30
synfloods = 1
syn_packets_per_flood = 80
acks_per_flood = 5
seed = 42
base_time = "2026-07-15T12:00:00Z"
```

Run it with:

```bash
python python/log_generator.py --config simulation.toml
```

### Java Rule Settings

The Java IDS accepts an optional JSON rule config file. Start from
`rules.example.json`:

```json
{
  "brute_force": {
    "window_ms": 60000,
    "threshold": 5
  },
  "port_scan": {
    "window_ms": 60000,
    "port_threshold": 30
  },
  "suspicious_dns": {
    "window_ms": 60000,
    "minimum_dns_events": 5,
    "score_threshold": 8
  },
  "syn_flood": {
    "window_ms": 10000,
    "syn_threshold": 60,
    "minimum_syn_for_ratio": 30,
    "max_ack_ratio": 0.2
  },
  "icmp_sweep": {
    "window_ms": 60000,
    "icmp_threshold": 30
  },
  "[custom rule name]": {
    "thresholds": "threshold values",
    "..."
  }
}
```

Run the IDS with a config file:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json rules.example.json
```

Any omitted section uses the built-in default values.

## Output Files

- **Alerts.json** - Complete alert data with evidence
- **Events.json** - Normalized input events for the Java IDS
- Optional **report.json**, **report.csv**, or **report.html** from the Python reporter
- Console output with processing statistics

## Testing

```bash
mvn test
```

## Future Potential Enhancements

- Integration with a VM Homelab
- Additional detection rules (DDoS, privilege escalation, anomalous behavior)
- Performance optimization for large event volumes
- Machine learning-based anomaly detection
- Integration with SIEM platforms

## License

Read License.md

## Author

Developed by Brandon Le, Computer Science Student at Rutgers University - New Brunswick.
