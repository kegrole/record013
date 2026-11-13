"""Recompute hashes and produce seven-field verification records."""
from pathlib import Path
from .formats import GO,NPM,PIP,resolve_go_module_dir,resolve_npm_file,resolve_pip_file
from .hashes import decode_value,digest,go_dir_hash,go_h1_bytes,hash_bytes
from .parsers import Entry
STATUS_OK="ok"; STATUS_MISMATCH="mismatch"; STATUS_MISSING="missing"; STATUS_MULTI_VERSION="multi_version"
RECORD_FIELDS=("name","version","declared_hash","computed_hash","status","file","line")
def record(entry,lock_file,declared,computed,status,line=None,version=None):
    return {"name":entry.name,"version":entry.version if version is None else version,"declared_hash":declared,"computed_hash":computed,"status":status,"file":str(lock_file),"line":entry.line if line is None else line}
def _matches(data,candidate):
    algorithm,encoding,expected=candidate
    try: return digest(data,algorithm)==decode_value(expected,encoding)
    except (ValueError,TypeError): return False
def _npm_candidate(token):
    algorithm,sep,value=token.partition("-"); algorithm=algorithm.lower()
    return (algorithm,"base64",value) if sep and algorithm in SUPPORTED and value else None
SUPPORTED=("sha256","sha512","md5")
def _verify_npm(entry,root):
    data=resolve_npm_file(root,entry.name,entry.version).read_bytes()
    if not entry.declared or not str(entry.declared).strip(): return None,f"sha512-{hash_bytes(data,'sha512','base64')}",STATUS_MISSING
    declared=str(entry.declared); candidates=[x for token in declared.split() if (x:=_npm_candidate(token))]
    for candidate in candidates:
        if _matches(data,candidate):
            algorithm,encoding,_=candidate; return declared,f"{algorithm}-{hash_bytes(data,algorithm,encoding)}",STATUS_OK
    algorithm,encoding,_=candidates[0] if candidates else ("sha512","base64","")
    return declared,f"{algorithm}-{hash_bytes(data,algorithm,encoding)}",STATUS_MISMATCH
def _pip_declared(candidates): return " ".join(f"--hash={a}:{v}" for a,_,v in candidates)
def _verify_pip(entry,root):
    data=resolve_pip_file(root,entry.name,entry.version).read_bytes(); candidates=list(entry.declared or [])
    if not candidates: return None,f"sha256:{hash_bytes(data,'sha256','hex')}",STATUS_MISSING
    for candidate in candidates:
        if _matches(data,candidate):
            algorithm,encoding,_=candidate; return _pip_declared(candidates),f"{algorithm}:{hash_bytes(data,algorithm,encoding)}",STATUS_OK
    algorithm,encoding,_=candidates[0]; return _pip_declared(candidates),f"{algorithm}:{hash_bytes(data,algorithm,encoding)}",STATUS_MISMATCH
def _go_files(module_dir):
    files=[(p.relative_to(module_dir).as_posix(),p.read_bytes()) for p in sorted(module_dir.rglob("*")) if p.is_file()]
    if not files: raise FileNotFoundError(f"Go module has no files: {module_dir}")
    return files
def _valid_h1(value): return isinstance(value,str) and value.startswith("h1:")
def _verify_go(entry,root):
    module_dir=resolve_go_module_dir(root,entry.name,entry.version); files=_go_files(module_dir)
    computed_dir=go_dir_hash(entry.name,entry.version,files); go_mod=[x for x in files if x[0]=="go.mod"]
    computed_mod=go_dir_hash(entry.name,entry.version,go_mod) if go_mod else None
    declared=entry.declared if isinstance(entry.declared,dict) else {}; d=declared.get("dir"); m=declared.get("go_mod")
    if not _valid_h1(d) or not _valid_h1(m): return {"dir":d,"go_mod":m},{"dir":computed_dir,"go_mod":computed_mod},STATUS_MISSING
    try: ok=go_h1_bytes(d)==go_h1_bytes(computed_dir) and computed_mod is not None and go_h1_bytes(m)==go_h1_bytes(computed_mod)
    except ValueError: ok=False
    return {"dir":d,"go_mod":m},{"dir":computed_dir,"go_mod":computed_mod},STATUS_OK if ok else STATUS_MISMATCH
def _verify_one(entry,root):
    if entry.ecosystem==NPM: return _verify_npm(entry,root)
    if entry.ecosystem==PIP: return _verify_pip(entry,root)
    if entry.ecosystem==GO: return _verify_go(entry,root)
    raise ValueError(f"unsupported ecosystem: {entry.ecosystem}")
def _group_key(entry): return (entry.ecosystem,entry.name if entry.ecosystem==NPM else entry.name.casefold())
def _multi_records(entries,lock_file):
    groups={}
    for entry in entries: groups.setdefault(_group_key(entry),[]).append(entry)
    records=[]
    for group in groups.values():
        versions=sorted({e.version for e in group})
        if len(versions)>1:
            representative=min(group,key=lambda e:e.line)
            records.append(record(representative,lock_file,None,None,STATUS_MULTI_VERSION,min(e.line for e in group),versions))
    return records
def verify_entries(entries,lock_file,fixtures_root="fixtures/packages"):
    entries=list(entries); multi=_multi_records(entries,lock_file); multi_keys={_group_key(e) for e in entries if any(r["name"]==e.name for r in multi)}
    records=[]; root=Path(fixtures_root)
    for entry in entries:
        if _group_key(entry) in multi_keys: continue
        try: declared,computed,status=_verify_one(entry,root)
        except (OSError,ValueError) as error: declared,computed,status=entry.declared,f"fixture_error: {error}",STATUS_MISMATCH
        records.append(record(entry,lock_file,declared,computed,status))
    records.extend(multi); records.sort(key=lambda x:(x["line"],x["name"],str(x["version"])))
    if any(tuple(x.keys())!=RECORD_FIELDS for x in records): raise RuntimeError("all records must contain exactly the seven required fields")
    return records
