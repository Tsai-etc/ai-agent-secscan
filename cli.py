"""
Command Line Interface for ai-agent-secscan
"""

import sys
import argparse
import json
from sec_scanner import AgentVulnerabilityScanner

def main():
    parser = argparse.ArgumentParser(
        description="ai-agent-secscan: Automated security auditor and vulnerability scanner for AI frameworks and agents."
    )
    parser.add_argument("target", help="Directory or Python file to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--ssrf-check", help="Check a specific URL for SSRF vulnerability against cloud metadata")

    args = parser.parse_args()

    if args.ssrf_check:
        res = AgentVulnerabilityScanner.check_ssrf_safety(args.ssrf_check)
        print(json.dumps(res, indent=2))
        return

    import os
    if os.path.isfile(args.target):
        with open(args.target, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        findings = AgentVulnerabilityScanner.scan_python_code(code, filename=args.target)
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            print(f"Scanned {args.target}: Found {len(findings)} issues.")
            for item in findings:
                print(f"[{item.get('severity')}] Line {item.get('line')}: {item.get('func', item.get('type'))} - {item.get('description')}")
    elif os.path.isdir(args.target):
        summary = AgentVulnerabilityScanner.scan_directory(args.target)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"=== Scan Complete: {summary['directory']} ===")
            print(f"Files Scanned: {summary['files_scanned']}")
            print(f"Total Findings: {summary['total_findings']} (Critical: {summary['critical_count']}, High: {summary['high_count']})")
            for item in summary["findings"]:
                print(f"  [{item.get('severity')}] {item.get('file')}:{item.get('line')} - {item.get('description')}")
    else:
        print(f"Error: Target '{args.target}' does not exist.")
        sys.exit(1)

if __name__ == "__main__":
    main()
