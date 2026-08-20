import argparse
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import demo


class DemoScriptTest(unittest.TestCase):
    def test_scenario_options_for_all(self):
        options = demo.scenario_options("all")

        self.assertEqual(100, options["normal"])
        self.assertEqual(1, options["attacks"])
        self.assertEqual(1, options["portscans"])
        self.assertEqual(1, options["dnsattacks"])
        self.assertEqual(1, options["icmpsweeps"])
        self.assertEqual(1, options["synfloods"])

    def test_scenario_options_for_single_attack(self):
        options = demo.scenario_options("syn-flood")

        self.assertEqual(0, options["attacks"])
        self.assertEqual(0, options["portscans"])
        self.assertEqual(0, options["dnsattacks"])
        self.assertEqual(0, options["icmpsweeps"])
        self.assertEqual(1, options["synfloods"])
        self.assertEqual(80, options["syn_packets_per_flood"])
        self.assertEqual(5, options["acks_per_flood"])

    def test_project_relative_output_path(self):
        self.assertEqual(demo.PROJECT_ROOT / "demo-output", demo.project_relative_path("demo-output"))

    def test_build_java_command_without_rules(self):
        command = demo.build_java_command(Path("C:/tmp/Events.json"))

        self.assertEqual("java", command[0])
        self.assertIn("com.ids.IDSCore", command)
        self.assertEqual(str(Path("C:/tmp/Events.json").resolve()), command[-1])

    def test_build_java_command_with_rules(self):
        command = demo.build_java_command(Path("C:/tmp/Events.json"), Path("C:/tmp/rules.json"))

        self.assertEqual(str(Path("C:/tmp/rules.json").resolve()), command[-1])
        self.assertEqual(str(Path("C:/tmp/Events.json").resolve()), command[-2])

    def test_build_generator_command_contains_scenario_arguments(self):
        command = demo.build_generator_command(
            Path("C:/tmp/Events.json"),
            "port-scan",
            seed=7,
            base_time="2026-07-15T12:00:00Z",
        )

        self.assertIn("--portscans", command)
        self.assertEqual("1", command[command.index("--portscans") + 1])
        self.assertIn("--synfloods", command)
        self.assertEqual("0", command[command.index("--synfloods") + 1])
        self.assertIn("--seed", command)
        self.assertEqual("7", command[command.index("--seed") + 1])
        self.assertIn("--base_time", command)
        self.assertEqual("2026-07-15T12:00:00Z", command[command.index("--base_time") + 1])

    def test_build_generator_command_omits_seed_and_base_time_by_default(self):
        command = demo.build_generator_command(
            Path("C:/tmp/Events.json"),
            "port-scan",
            seed=None,
            base_time=None,
        )

        self.assertNotIn("--seed", command)
        self.assertNotIn("--base_time", command)

    def test_remove_stale_artifacts(self):
        output_dir = demo.PROJECT_ROOT / "target" / "demo-stale-test"
        output_dir.mkdir(parents=True, exist_ok=True)
        stale_file = output_dir / "report.html"
        stale_file.write_text("old report", encoding="utf-8")

        demo.remove_stale_artifacts([stale_file])

        self.assertFalse(stale_file.exists())

    @patch("builtins.print")
    @patch("demo.gson_jar_path")
    @patch("demo.run_command")
    def test_skip_compile_omits_compile_command(self, run_command, gson_jar_path, _print):
        fake_output_dir = demo.PROJECT_ROOT / "target" / "demo-test-output"
        gson_jar_path.return_value = demo.PROJECT_ROOT / "pom.xml"
        args = argparse.Namespace(
            scenario="all",
            rules=None,
            output_dir=str(fake_output_dir),
            seed=None,
            base_time=None,
            top_n=5,
            skip_compile=True,
            verbose=False,
        )

        result = demo.run_demo(args)

        self.assertEqual(0, result)
        labels = [call.args[1] for call in run_command.call_args_list]
        self.assertEqual(["Generate events", "Run IDS", "Generate HTML report"], labels)


if __name__ == "__main__":
    unittest.main()
