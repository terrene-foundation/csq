#!/usr/bin/env python3
"""Preserve measured failures; exempt only a validated Phase-2a unknown result."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

LIMIT = 1024 * 1024
SOURCE = "coc-eval/phase-declaration.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")
STATUS_KEYS = {"evaluator_exit_code", "tee_exit_code", "report_io_exit_code"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    """Bound reads and reject symlinks, directories, devices and FIFOs."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("report is not a regular file")
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("report exceeds size limit")
    value = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("report is not an object")
    return value


def decide(runner_rc, allow, sha, directory):
    report = {"disposition": "ERROR", "evaluator_exit_code": None,
              "runner_exit_code": runner_rc, "status": None,
              "declared_phase": "2a" if allow == "true" else None,
              "source": {"path": SOURCE, "commit": sha}, "reason": "invalid_report"}
    failure_rc = runner_rc or 74
    try:
        if not SHA.fullmatch(sha):
            raise ValueError("invalid_subject_sha")
        status = read_json(directory / "gate-status.json")
        if (set(status) != STATUS_KEYS
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in status.values())):
            raise ValueError("invalid_status")
        report["status"] = status
        evaluator_rc = status["evaluator_exit_code"]
        report["evaluator_exit_code"] = evaluator_rc
        if status["tee_exit_code"] or status["report_io_exit_code"]:
            raise ValueError("report_transport_failed")
        if runner_rc != evaluator_rc:
            raise ValueError("runner_status_mismatch")
        verdict = read_json(directory / "gate-report.json").get("verdict")
        if evaluator_rc == 0 and verdict in ("SHIP_OPT_IN", "SHIP_DIRECT_API"):
            report.update(disposition="SHIP", reason="gate_clears")
            return report, 0
        if evaluator_rc == 1 and verdict == "DEFER":
            report.update(disposition="DEFER", reason="measured_condition_failed")
            return report, 1
        if evaluator_rc == 2 and verdict == "UNDETERMINED":
            if allow == "true":
                report.update(disposition="NOT_APPLICABLE", reason="declared_2a_undetermined")
                return report, 0
            report.update(disposition="UNDETERMINED", reason="measurement_required")
            return report, 2
        raise ValueError("unexpected_evaluator_verdict")
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        report["reason"] = str(error) if isinstance(error, ValueError) else "report_unreadable"
        return report, failure_rc


def publish(report, directory, environment):
    (directory / "gate-disposition.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = (f"Phase-2b disposition: {report['disposition']} — {report['reason']}; "
               f"evaluator exit {report['evaluator_exit_code']}; "
               f"runner exit {report['runner_exit_code']}.\n")
    if environment.get("GITHUB_STEP_SUMMARY"):
        with open(environment["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(summary)
    print(summary, end="", flush=True)
    # An exemption is visible to Actions only after every reporting write.
    if environment.get("GITHUB_OUTPUT"):
        with open(environment["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("disposition=" + report["disposition"] + "\n")


def main(argv=None, environment=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-status", required=True, type=int)
    parser.add_argument("--allow-undetermined", required=True)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--report-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if not 0 <= args.runner_status <= 255:
        return 64
    report, rc = decide(args.runner_status, args.allow_undetermined,
                        args.subject_sha, args.report_dir)
    try:
        publish(report, args.report_dir, os.environ if environment is None else environment)
    except (OSError, UnicodeError):
        report.update(disposition="ERROR", reason="disposition_reporting_failed")
        try:
            (args.report_dir / "gate-disposition.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        print("Phase-2b disposition reporting failed.", file=sys.stderr)
        return args.runner_status or 74
    return rc


if __name__ == "__main__":
    sys.exit(main())
