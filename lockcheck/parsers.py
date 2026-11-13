"""Parsers for npm, pip requirements and Go go.sum formats."""
import json,re
from dataclasses import dataclass
from pathlib import Path
from .formats import GO,NPM,PIP
from .hashes import go_module_unescape,parse_pip_hashes
@dataclass
class Entry:
    ecosystem:str; name:str; version:str; line:int; declared:object=None
def parse_lock(path):
    name=Path(path).name.lower()
    if name=="go.sum" or name.endswith(".sum"): return parse_go_sum(path)
    if name.endswith(".json") and "package-lock" in name: return parse_package_lock(path)
    if name.endswith(".lock") and "requirements" in name: return parse_requirements_lock(path)
    raise ValueError(f"unsupported lock file: {path}")
def _key_line(source,key,start=0):
    match=re.compile(r'"'+re.escape(key)+r'"\s*:').search(source,start)
    if not match: return 0,start
    return source.count("\n",0,match.start())+1,match.end()
def _npm_name(key,node):
    if node.get("name"): return str(node["name"])
    if "node_modules/" in key:
        tail=key.rsplit("node_modules/",1)[1]
        return tail.split("/node_modules/",1)[0] if "/node_modules/" in tail else tail
    return key
def _package_entries(packages,source):
    entries=[]; position=0
    for key,node in packages.items():
        if not key or not isinstance(node,dict) or not node.get("version"): continue
        line,position=_key_line(source,key,position)
        entries.append(Entry(NPM,_npm_name(key,node),str(node["version"]),line,node.get("integrity")))
    return entries
def _walk_v2(dependencies,source,position,entries):
    for key,node in dependencies.items():
        if not isinstance(node,dict): continue
        if node.get("version"):
            line,position=_key_line(source,key,position)
            entries.append(Entry(NPM,str(node.get("name",key)),str(node["version"]),line,node.get("integrity")))
        if isinstance(node.get("dependencies"),dict): position=_walk_v2(node["dependencies"],source,position,entries)
    return position
def parse_package_lock(path):
    path=Path(path); source=path.read_text(encoding="utf-8"); data=json.loads(source)
    if data.get("lockfileVersion")==2 and isinstance(data.get("dependencies"),dict):
        entries=[]; _walk_v2(data["dependencies"],source,0,entries); return entries
    if isinstance(data.get("packages"),dict): return _package_entries(data["packages"],source)
    if isinstance(data.get("dependencies"),dict):
        entries=[]; _walk_v2(data["dependencies"],source,0,entries); return entries
    raise ValueError(f"npm lock has neither packages nor dependencies: {path}")
def parse_requirements_lock(path):
    pattern=re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;]+)(.*)$"); entries=[]
    for line_number,line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(),1):
        stripped=line.strip()
        if not stripped or stripped.startswith("#"): continue
        match=pattern.match(stripped)
        if match:
            name,version,rest=match.groups(); entries.append(Entry(PIP,name,version,line_number,parse_pip_hashes(rest)))
    return entries
@dataclass
class _GoGroup: name:str; version:str; line:int; dir_hash:str|None=None; go_mod_hash:str|None=None
def parse_go_sum(path):
    groups={}; order=[]; pattern=re.compile(r"^(\S+)\s+(\S+)(?:\s+(h1:\S+))?\s*$")
    for line_number,line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(),1):
        stripped=line.strip()
        if not stripped or stripped.startswith("#"): continue
        match=pattern.match(stripped)
        if not match: continue
        component,version,h1=match.groups()
        if component.endswith("/go.mod"): escaped=component[:-7]; kind="go_mod"
        else: escaped=component; kind="dir"
        if "@" not in escaped: continue
        escaped_name,_,component_version=escaped.rpartition("@")
        if component_version!=version: continue
        module=go_module_unescape(escaped_name); key=(module,version)
        if key not in groups: groups[key]=_GoGroup(module,version,line_number); order.append(key)
        group=groups[key]; group.line=min(group.line,line_number)
        if kind=="dir": group.dir_hash=h1
        else: group.go_mod_hash=h1
    return [Entry(GO,g.name,g.version,g.line,{"dir":g.dir_hash,"go_mod":g.go_mod_hash}) for g in (groups[k] for k in order)]
