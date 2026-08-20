import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import report_generator


class ReportGeneratorScriptTest(unittest.TestCase):
    def test_main_writes_default_html_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            alerts_path = temp_path / "Alerts.json"
            report_path = temp_path / "report.html"
            alerts_path.write_text(
                json.dumps(
                    [
                        {
                            "timestamp": 1767225600000,
                            "rule_name": "PortScanRule",
                            "severity": "High",
                            "source_ip": "203.0.113.10",
                            "target": "10.0.0.5",
                            "description": "Detected scan behavior.",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            argv = ["report_generator.py", "--input", str(alerts_path)]
            with patch.object(sys, "argv", argv):
                result = report_generator.main()

            self.assertEqual(0, result)
            self.assertTrue(report_path.exists())
            self.assertIn("<title>IDS Alert Report</title>", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
