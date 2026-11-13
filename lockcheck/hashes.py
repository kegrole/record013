"""Standard-library hash and Go dirhash helpers."""
import base64, hashlib
from pathlib import Path
SUPPORTED_ALGORITHMS=("sha256","sha512","md5")
def digest(data,algorithm):
    algorithm=algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS: raise ValueError(f"unsupported hash algorithm: {algorithm}")
    return hashlib.new(algorithm,data).digest()
def encode_digest(value,encoding):
    if encoding=="hex": return value.hex()
    if encoding=="base64": return base64.b64encode(value).decode("ascii")
    raise ValueError(f"unsupported encoding: {encoding}")
def hash_bytes(data,algorithm,encoding): return encode_digest(digest(data,algorithm),encoding)
def hash_file(path,algorithm,encoding): return hash_bytes(Path(path).read_bytes(),algorithm,encoding)
def decode_value(value,encoding):
    if encoding=="hex": return bytes.fromhex(value.strip())
    if encoding=="base64": return base64.b64decode(value.strip(),validate=True)
    raise ValueError(f"unsupported encoding: {encoding}")
def parse_npm_integrity(text):
    result=[]
    for token in text.split():
        algorithm,sep,value=token.partition("-")
        if sep and algorithm.lower() in SUPPORTED_ALGORITHMS and value: result.append((algorithm.lower(),"base64",value))
    return result
def parse_pip_hashes(text):
    result=[]
    for token in text.split():
        if not token.startswith("--hash="): continue
        algorithm,sep,value=token[len("--hash="):].partition(":")
        if sep and algorithm.lower() in SUPPORTED_ALGORITHMS and value: result.append((algorithm.lower(),"hex",value))
    return result
def go_module_escape(value): return "".join("!"+c.lower() if c.isupper() else c for c in value)
def go_module_unescape(value):
    out=[]; i=0
    while i<len(value):
        if value[i]=="!" and i+1<len(value): out.append(value[i+1].upper()); i+=2
        else: out.append(value[i]); i+=1
    return "".join(out)
def go_dir_hash(module,version,files):
    prefix=f"{module}@{version}/"; lines=[]
    for name,content in sorted(files,key=lambda item:item[0]):
        lines.append(hashlib.sha256(content).hexdigest()+f"  {prefix}{name}\n")
    return "h1:"+base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode("ascii")
def go_h1_bytes(value):
    if not value.startswith("h1:"): raise ValueError(f"invalid Go h1 value: {value}")
    return base64.b64decode(value[3:],validate=True)
