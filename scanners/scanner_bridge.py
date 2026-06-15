#!/usr/bin/env python3
import sys
import json
import argparse
import importlib
import os

def main():
    parser = argparse.ArgumentParser(description="Scanner Bridge CLI")
    parser.add_argument("--type", required=True, choices=["url", "github"])
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", required=True, choices=["basic", "modrate", "advanced"])
    args = parser.parse_args()

    # Dynamic import based on mode
    module_name = f"{args.mode}_scanner"
    try:
        # Add local dir to path to make imports work reliably
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Load the scanner module
        scanner_module = importlib.import_module(module_name)
    except Exception as e:
        error_result = {
            "status": "error",
            "target": args.target,
            "mode": args.mode,
            "findings": [],
            "error": f"Failed to load scanner module '{module_name}': {str(e)}"
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

    try:
        # Run scan
        results = scanner_module.scan(args.type, args.target)
        print(json.dumps(results, indent=2))
    except Exception as e:
        error_result = {
            "status": "error",
            "target": args.target,
            "mode": args.mode,
            "findings": [],
            "error": f"Scan failed during execution: {str(e)}"
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
