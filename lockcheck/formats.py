"""Format detection and fixture path conventions."""
from pathlib import Path
NPM="npm"; PIP="pip"; GO="go"
def detect_format(path):
    name=Path(path).name.lower()
    if name=="go.sum" or name.endswith(".sum"): return GO
    if name.endswith(".json") and "package-lock" in name: return NPM
    if name.endswith(".lock") and "requirements" in name: return PIP
    raise ValueError(f"cannot determine lock format from file name: {name}")
def resolve_npm_file(root,name,version): return Path(root)/NPM/name.replace("/","__")/f"{version}.tgz"
def resolve_pip_file(root,name,version):
    matches=sorted((Path(root)/PIP/name).glob(f"{version}.*"))
    if not matches: raise FileNotFoundError(f"no pip fixture for {name}=={version}")
    if len(matches)>1: raise RuntimeError(f"ambiguous pip fixture for {name}=={version}")
    return matches[0]
def resolve_go_module_dir(root,module,version): return Path(root)/GO/f"{module}@{version}"
