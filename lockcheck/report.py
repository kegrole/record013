"""JSON report assembly and summary output."""
import json
from pathlib import Path
from .verify import STATUS_MISMATCH,STATUS_MISSING,STATUS_MULTI_VERSION,STATUS_OK
SUMMARY_STATUSES=(STATUS_OK,STATUS_MISMATCH,STATUS_MISSING,STATUS_MULTI_VERSION)
def summarize(records):
    records=list(records); summary={status:0 for status in SUMMARY_STATUSES}; summary["total"]=len(records)
    for item in records: summary[item["status"]]+=1
    return summary
def summary_line(records):
    summary=summarize(records)
    return "total={total} ok={ok} mismatch={mismatch} missing={missing} multi_version={multi_version}".format(**summary)
def build_report(lock_records):
    records=[]; locks=[]
    for lock_file,lock_records in lock_records:
        locks.append({"file":str(lock_file),"records":len(lock_records)}); records.extend(lock_records)
    return {"summary":summarize(records),"locks":locks,"records":records}
def write_report(report,output_path):
    output=Path(output_path); output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n","utf-8")
