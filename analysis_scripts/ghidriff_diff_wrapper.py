import sys
import json
import ghidriff
import os
import argparse
from pathlib import Path
import uuid

def make_json_serializable(obj):
    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [make_json_serializable(v) for v in obj]
    else:
        try:
            d = vars(obj)
            return make_json_serializable(d)
        except Exception:
            try:
                json.dumps(obj)
                return obj
            except Exception:
                return str(obj)

def main():
    if len(sys.argv) < 5:
        print("Usage: python ghidriff_diff_wrapper.py <file1> <file2> <diff_type> <output_json>")
        sys.exit(1)
    file1, file2, diff_type, output_json = sys.argv[1:5]
    file1, file2 = Path(file1), Path(file2)
    args = argparse.Namespace()
    if diff_type == 'version_tracking':
        engine = ghidriff.VersionTrackingDiff(args=args, force_diff=True)
    elif diff_type == 'structural_graph':
        engine = ghidriff.StructualGraphDiff(args=args, force_diff=True)
    else:
        engine = ghidriff.SimpleDiff(args=args, force_diff=True)
    project_location = os.path.abspath("./uploads/diff_results/ghidra_projects")
    os.makedirs(project_location, exist_ok=True)
    project_name = f"wrapper_diff_{uuid.uuid4().hex[:8]}"
    engine.setup_project([file1, file2], project_location, project_name, r'C:\Symbols', None)
    engine.analyze_project()
    diff_result = engine.diff_bins(file1, file2)
    diff_result = make_json_serializable(diff_result)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(diff_result, f)

if __name__ == "__main__":
    main() 