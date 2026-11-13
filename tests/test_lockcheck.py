"""Acceptance tests for lockcheck."""
from __future__ import annotations
import base64, hashlib, io, json, shutil, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path
from lockcheck.cli import run
from lockcheck.formats import resolve_go_module_dir
from lockcheck.hashes import go_dir_hash, go_module_escape, go_module_unescape, hash_bytes
from lockcheck.parsers import parse_lock
from lockcheck.report import summary_line
from lockcheck.verify import verify_entries
ROOT=Path(__file__).resolve().parents[1]; FIXTURES=ROOT/"fixtures/packages"; LOCKS=ROOT/"demo/locks"
FIELDS=("name","version","declared_hash","computed_hash","status","file","line")
GO_DIR="h1:CxMCafGH3he2YUx8mpZWYG7zDCQfm9DQ8mJgx+y/ThM="; GO_MOD="h1:yJwNngL0tCKlmRg8yireic46hRGohEbhwD/WSE0Ax3I="
def rows(name):
    path=LOCKS/name
    return verify_entries(parse_lock(path),path,FIXTURES)
def all_rows():
    result=[]
    for path in sorted(LOCKS.iterdir()): result.extend(verify_entries(parse_lock(path),path,FIXTURES))
    return result
def files(path):
    return [(p.relative_to(path).as_posix(),p.read_bytes()) for p in sorted(path.rglob("*")) if p.is_file()]
class SpecificationTests(unittest.TestCase):
    def test_01_four_locks_exactly_three_issues_each(self):
        grouped={}
        for item in all_rows(): grouped.setdefault(Path(item["file"]).name,{}).setdefault(item["status"],[]).append(item)
        self.assertEqual(set(grouped),{"go.sum","package-lock-v2.json","package-lock-v3.json","requirements.lock"})
        for name,statuses in grouped.items():
            self.assertEqual(1,len(statuses.get("mismatch",[])),name)
            self.assertEqual(1,len(statuses.get("missing",[])),name)
            self.assertEqual(1,len(statuses.get("multi_version",[])),name)
        self.assertEqual(12,sum(item["status"]!="ok" for item in all_rows()))
    def test_02_go_hard_fixture_and_dirhash_values(self):
        module=FIXTURES/"go/example.com/m@v1.0.0"
        self.assertEqual((("go.mod",b"module example.com/m\n"),("pkg.go",b"package m\n")),tuple(files(module)))
        source=files(module)
        self.assertEqual(GO_DIR,go_dir_hash("example.com/m","v1.0.0",source))
        self.assertEqual(GO_MOD,go_dir_hash("example.com/m","v1.0.0",[x for x in source if x[0]=="go.mod"]))
        item=next(x for x in rows("go.sum") if x["name"]=="example.com/m" and x["version"]=="v1.0.0")
        self.assertEqual(GO_DIR,item["declared_hash"]["dir"]); self.assertEqual(GO_MOD,item["declared_hash"]["go_mod"])
        self.assertEqual(GO_DIR,item["computed_hash"]["dir"]); self.assertEqual(GO_MOD,item["computed_hash"]["go_mod"])
    def test_03_go_module_and_go_mod_merge_without_extra_version(self):
        entries=[x for x in parse_lock(LOCKS/"go.sum") if x.name=="example.com/m"]
        self.assertEqual(1,len(entries)); self.assertEqual("v1.0.0",entries[0].version)
        self.assertNotEqual(entries[0].declared["dir"],entries[0].declared["go_mod"])
    def test_04_go_uppercase_escape_restored_before_fixture_lookup(self):
        self.assertEqual("!example.com/!mod",go_module_escape("Example.com/Mod"))
        self.assertEqual("Example.com/Mod",go_module_unescape("!example.com/!mod"))
        item=next(x for x in rows("go.sum") if x["name"]=="Example.com/Mod")
        self.assertEqual("ok",item["status"]); self.assertTrue(resolve_go_module_dir(FIXTURES,"Example.com/Mod","v1.2.3").is_dir())
    def test_05_npm_multiple_integrity_candidates_any_matches(self):
        item=next(x for x in rows("package-lock-v3.json") if x["name"]=="debug")
        self.assertEqual("ok",item["status"]); self.assertTrue(item["declared_hash"].startswith("sha256-")); self.assertTrue(item["computed_hash"].startswith("sha256-"))
    def test_06_sha256_and_md5_normal_entries(self):
        pip=rows("requirements.lock")
        req=next(x for x in pip if x["name"]=="requests"); cert=next(x for x in pip if x["name"]=="certifi")
        self.assertEqual("ok",req["status"]); self.assertTrue(req["computed_hash"].startswith("sha256:"))
        self.assertEqual("ok",cert["status"]); self.assertTrue(cert["computed_hash"].startswith("md5:"))
    def test_07_multi_version_lists_both_versions(self):
        expected={"go.sum":("example.com/multi",["v1.0.0","v2.0.0"]),"package-lock-v2.json":("multi-lib",["1.0.0","2.0.0"]),"package-lock-v3.json":("multi-lib",["1.0.0","2.0.0"]),"requirements.lock":("flask",["2.3.3","3.0.2"])}
        for lock,(name,versions) in expected.items():
            item=next(x for x in rows(lock) if x["status"]=="multi_version")
            self.assertEqual(name,item["name"],lock); self.assertEqual(versions,item["version"],lock)
    def test_08_records_have_seven_fields_and_explicit_missing_value(self):
        data=all_rows()
        self.assertTrue(all(tuple(item)==FIELDS for item in data))
        self.assertTrue(all(isinstance(item["line"],int) and item["line"]>0 for item in data))
        missing=[item for item in data if item["status"]=="missing"]
        self.assertTrue(missing)
        for item in missing:
            declared=item["declared_hash"]
            if declared is None:
                continue
            self.assertIsInstance(declared,dict)
            self.assertIn(None,declared.values())
    def test_09_algorithms_and_encodings(self):
        payload=b"encoding coverage\n"
        for algorithm in ("sha256","sha512","md5"):
            raw=hashlib.new(algorithm,payload).digest()
            self.assertEqual(raw.hex(),hash_bytes(payload,algorithm,"hex"))
            self.assertEqual(base64.b64encode(raw).decode(),hash_bytes(payload,algorithm,"base64"))
    def test_10_regenerated_locks_and_cli_are_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); packages=root/"packages"; locks=root/"locks"; shutil.copytree(FIXTURES,packages); locks.mkdir()
            self._make_npm(locks,packages); self._make_pip(locks,packages); self._make_go(locks,packages)
            generated=[]
            for path in sorted(locks.iterdir()): generated.extend(verify_entries(parse_lock(path),path,packages))
            self.assertTrue(generated); self.assertTrue(all(x["status"]=="ok" for x in generated))
            output=root/"nested/report.json"; stdout=io.StringIO()
            with redirect_stdout(stdout): code=run([str(locks)],str(output),str(packages))
            self.assertEqual(0,code); report=json.loads(output.read_text())
            self.assertEqual(summary_line(report["records"]).strip(),stdout.getvalue().strip())
            npm=next(x for x in report["records"] if x["name"]=="shared-blob" and x["file"].endswith(".json"))
            pip=next(x for x in report["records"] if x["name"]=="shared-blob" and x["file"].endswith(".lock"))
            self.assertEqual(base64.b64decode(npm["computed_hash"].split("-",1)[1]),bytes.fromhex(pip["computed_hash"].split(":",1)[1]))
    def _make_npm(self,locks,packages):
        nodes={"":{"name":"generated","version":"1.0.0"}}
        for name,version in [("left-pad","1.3.0"),("debug","4.3.4"),("shared-blob","1.0.0")]:
            path=packages/"npm"/name.replace("/","__")/f"{version}.tgz"; data=path.read_bytes()
            nodes[f"node_modules/{name}"]={"version":version,"integrity":"sha256-"+base64.b64encode(hashlib.sha256(data).digest()).decode()+" sha512-"+base64.b64encode(hashlib.sha512(data).digest()).decode()}
        (locks/"package-lock.json").write_text(json.dumps({"lockfileVersion":3,"packages":nodes}),"utf-8")
    def _make_pip(self,locks,packages):
        lines=[]
        for name,version,algorithm in [("requests","2.31.0","sha256"),("certifi","2024.2.2","md5"),("shared-blob","1.0.0","sha256")]:
            path=next((packages/"pip"/name).glob(f"{version}.*")); lines.append(f"{name}=={version} --hash={algorithm}:{hashlib.new(algorithm,path.read_bytes()).hexdigest()}")
        (locks/"requirements.lock").write_text("\n".join(lines)+"\n","utf-8")
    def _make_go(self,locks,packages):
        lines=[]
        for module,version in [("example.com/m","v1.0.0"),("Example.com/Mod","v1.2.3")]:
            source=files(resolve_go_module_dir(packages,module,version)); directory=go_dir_hash(module,version,source); mod=go_dir_hash(module,version,[x for x in source if x[0]=="go.mod"]); escaped=go_module_escape(module)
            lines += [f"{escaped}@{version} {version} {directory}",f"{escaped}@{version}/go.mod {version} {mod}"]
        (locks/"go.sum").write_text("\n".join(lines)+"\n","utf-8")
if __name__=="__main__": unittest.main()
