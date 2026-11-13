"""Command line interface."""
import argparse
from pathlib import Path
from .formats import detect_format
from .parsers import parse_lock
from .report import build_report,summary_line,write_report
from .verify import verify_entries
SUPPORTED_SUFFIXES=(".json",".lock",".sum")
def _expand_lock_paths(paths):
    expanded=[]
    for raw_path in paths:
        path=Path(raw_path)
        if path.is_dir(): expanded.extend(sorted(child for child in path.iterdir() if child.is_file() and child.suffix in SUPPORTED_SUFFIXES))
        else: expanded.append(path)
    for path in expanded: detect_format(path)
    return expanded
def run(lock_paths,output_path,fixtures_root="fixtures/packages"):
    lock_records=[]
    for lock_file in _expand_lock_paths(lock_paths):
        lock_records.append((str(lock_file),verify_entries(parse_lock(lock_file),lock_file,fixtures_root)))
    report=build_report(lock_records); write_report(report,output_path); print(summary_line(report["records"])); return 0
def build_parser():
    parser=argparse.ArgumentParser(description="Verify multi-format lock file hashes.")
    parser.add_argument("--lock",action="append",required=True,help="lock file or directory; may be supplied multiple times")
    parser.add_argument("--out",required=True,help="JSON report output path")
    parser.add_argument("--fixtures",default="fixtures/packages",help="package fixture root")
    return parser
def main(argv=None):
    args=build_parser().parse_args(list(argv) if argv is not None else None)
    return run(args.lock,args.out,args.fixtures)
if __name__=="__main__": raise SystemExit(main())
