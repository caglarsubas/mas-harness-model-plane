"""MODEL-ADOPT-PINS-001: the llama.cpp adoption dossier (standard-library unittest; reads only; writes nothing).

The pinned values below are contracts[2] of the packet, written by the dossier generator from the run results.
"""

import datetime
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "adoption" / "llama-cpp"
PINS = json.loads(r'''{
    "archiveBytes": 38889520,
    "archiveSha256": "3f5f750e36326aea4d65c7623e7d597a33e395d65f4d76e5e0532171f252532b",
    "commit": "b1b770d90d94cad9e9ea5b993bdbc383a522fb28",
    "commitTree": "03d5ee6748f415d4069dc570764c24ff3576a0f1",
    "gateFile": "mirror_check.json",
    "gateSha256Prefix": "c808e22f",
    "licenceFiles": [
        [
            "LICENSE",
            "94f29bbed6a22c35b992c5c6ebf0e7c92f13b836b90f36f461c9cf2f0f1d010d",
            1078
        ],
        [
            "cmake/license.cmake",
            "083515dff8a9b8696e348c7c616934e53941a7db30e1b3f092576632e9a2d1d4",
            1445
        ],
        [
            "gguf-py/LICENSE",
            "ef78c7e6659e34c798194f0d344e807c722de70cbca1359ef54772661e11ca38",
            1072
        ],
        [
            "licenses/LICENSE-jsonhpp",
            "c0d068392ea65358b798b8c165103560f06e9e3b38c4ab4e2d8810a7b931af86",
            1075
        ],
        [
            "tools/ui/src/lib/vendors/big-integer/LICENSE",
            "e9b0e94f628e00b5ed98046cfa041696ff89eebbbdd54108ee350625bc6d0363",
            1234
        ],
        [
            "tools/ui/src/lib/vendors/decimal.js/LICENCE.md",
            "3108b546bcff5d346923a82f48b2d252ca722f9088076db6d145f6b67757ad6c",
            1104
        ],
        [
            "tools/ui/src/lib/vendors/nerdamer-prime/LICENSE",
            "c9f52548869a0a2e63a7100055c54cebf36b9327c8fc2da7cf9ca8dddc2f1cca",
            1073
        ],
        [
            "vendor/cpp-httplib/LICENSE",
            "4b45cbe16d7b71b89ae6127e26e0d90a029198ca5e958ad8e3d0b8bbed364d8b",
            1075
        ],
        [
            "vendor/hash/rotate-bits/LICENSE.md",
            "ca0b44aec101afb6b46f4c39b23369fa06a64fb9c0add37c2689d702156fee55",
            1088
        ],
        [
            "vendor/hash/sha256/LICENSE",
            "b81d0022ca6367918c67b57e9647d3513ee58809fd4b0ef0b3492f1356bced25",
            41
        ],
        [
            "vendor/hash/xxhash/LICENSE",
            "6ffedbc0f7878612d2b23589f1ff2ab15633e1df7963a5d9fc750ec5500c7e7a",
            1389
        ]
    ],
    "manifestGeneration": "1795189583094545",
    "manifestName": "manifests/MODEL-ADOPT-PINS-001/r06-pins-001-20261120T154611Z.json",
    "manifestSha256": "d4081819536ee48e22717c5ea7e5303663fc345bcd5717c93115b34a8400c73d",
    "object": "sha256/3f5f750e36326aea4d65c7623e7d597a33e395d65f4d76e5e0532171f252532b",
    "objectGeneration": "1795189583001229",
    "pinnedAt": "2026-11-20T15:46:11Z",
    "publishedAt": "2026-11-13T10:20:19Z",
    "tag": "v1.0.0",
    "topKeys": [
        "archive",
        "buildInputs",
        "components",
        "engine",
        "evidence",
        "gateEvidence",
        "licenceFiles",
        "licenceReview",
        "mirror",
        "notices",
        "packet",
        "pickRule",
        "quarantine",
        "quarantinePassed",
        "release",
        "schema",
        "upstreamLicence"
    ]
}''')
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"<[^<>]*>")
QUARANTINE_KEYS = {"minimumDays", "source", "decisionRef", "policyItem", "exemption"}


def load(name):
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def walk(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from walk(v, path + "." + k)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, "%s[%d]" % (path, i))
    else:
        yield path, o


def utc(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


class DossierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load("dossier.json")
        cls.sbom = load("sbom.spdx.json")

    def test_files_are_lf_strict_utf8_without_bom(self):
        for name in ("dossier.json", "LICENSES.md", "NOTICE.upstream", "sbom.spdx.json"):
            b = (DIR / name).read_bytes()
            b.decode("utf-8")
            self.assertNotIn(b"\r", b, name)
            self.assertFalse(b.startswith(b"\xef\xbb\xbf"), name)

    def test_keys_exact(self):
        self.assertEqual(sorted(self.d), PINS["topKeys"])
        self.assertEqual(self.d["schema"], "planeon.adoption-dossier/v1")
        self.assertEqual(self.d["engine"], "ggml-org/llama.cpp")

    def test_sha256_shapes_and_mirror_names(self):
        seen = 0
        for path, v in walk(self.d):
            key = path.rsplit(".", 1)[-1].split("[")[0]
            if key == "sha256" or key.endswith("Sha256"):
                self.assertRegex(v, HEX64, path)
                seen += 1
        self.assertGreaterEqual(seen, 30)
        obj = self.d["mirror"]["object"]
        self.assertEqual(obj, "sha256/" + self.d["archive"]["sha256"])

    def test_pinned_values_equal_contract(self):
        d, p = self.d, PINS
        r = d["release"]
        self.assertEqual((r["tag"], r["commit"], r["commitTree"], r["publishedAt"], r["pinnedAt"]),
                         (p["tag"], p["commit"], p["commitTree"], p["publishedAt"], p["pinnedAt"]))
        self.assertEqual((d["archive"]["sha256"], d["archive"]["bytes"]), (p["archiveSha256"], p["archiveBytes"]))
        m = d["mirror"]
        self.assertEqual((m["object"], m["generation"]), (p["object"], p["objectGeneration"]))
        self.assertEqual((m["manifest"]["name"], m["manifest"]["sha256"], m["manifest"]["generation"]),
                         (p["manifestName"], p["manifestSha256"], p["manifestGeneration"]))
        got = [[e["path"], e["sha256"], e["bytes"]] for e in d["licenceFiles"]]
        self.assertEqual(len(p["licenceFiles"]), 11)
        self.assertEqual(sorted(got), sorted(p["licenceFiles"]))

    def test_gate_evidence(self):
        g = self.d["gateEvidence"]
        self.assertEqual(g["file"], PINS["gateFile"])
        self.assertTrue(g["sha256"].startswith(PINS["gateSha256Prefix"]))
        self.assertIs(g["ok"], True)
        self.assertEqual(g["mismatches"], 0)

    def test_no_placeholder(self):
        for name in ("dossier.json", "sbom.spdx.json"):
            self.assertIsNone(PLACEHOLDER.search((DIR / name).read_text(encoding="utf-8")), name)
        for doc in (self.d, self.sbom):
            for path, v in walk(doc):
                self.assertNotIn(v, ("TBD", "TODO", ""), path)

    def test_quarantine(self):
        q = self.d["quarantine"]
        self.assertEqual(set(q), QUARANTINE_KEYS)
        self.assertIn(q["source"], ("OWNER_DECISION", "POLICY_IN_FORCE"))
        self.assertIsInstance(q["minimumDays"], int)
        self.assertNotIsInstance(q["minimumDays"], bool)
        self.assertGreater(q["minimumDays"], 0)
        self.assertEqual(q["policyItem"], "SUPPLY-QUARANTINE-001")
        r = self.d["release"]
        old_enough = utc(r["publishedAt"]) + datetime.timedelta(days=q["minimumDays"]) <= utc(r["pinnedAt"])
        if not old_enough:
            self.assertIs(q["exemption"].get("used"), True)
            self.assertTrue(q["exemption"].get("reason"))

    def test_tree(self):
        a, r = self.d["archive"], self.d["release"]
        self.assertRegex(a["recomputedTree"], HEX40)
        self.assertRegex(r["commitTree"], HEX40)
        self.assertEqual(a["recomputedTree"], r["commitTree"])

    def test_sbom_matches_dossier(self):
        self.assertEqual(self.sbom["spdxVersion"], "SPDX-2.3")
        pkgs = {p["name"]: p for p in self.sbom["packages"]}
        self.assertIn("llama.cpp", pkgs)
        sbom_components = {n: p["licenseConcluded"] for n, p in pkgs.items() if n != "llama.cpp"}
        dossier_components = {c["name"]: c["identifier"] for c in self.d["components"]}
        self.assertEqual(sbom_components, dossier_components)
        self.assertEqual(pkgs["llama.cpp"]["licenseConcluded"], self.d["upstreamLicence"]["identifier"])

    def test_no_component_rejected(self):
        for c in self.d["components"]:
            self.assertEqual(c["result"], "ACCEPTED", c["name"])
        for e in self.d["licenceFiles"]:
            self.assertIn(e["result"], ("ACCEPTED", "NOT_A_LICENCE_TEXT"), e["path"])

    def test_licence_entries_reviewed(self):
        pinned = {p: s for p, s, _ in PINS["licenceFiles"]}
        self.assertEqual(len(self.d["licenceFiles"]), 11)
        for e in self.d["licenceFiles"]:
            self.assertTrue(e["identifier"], e["path"])
            self.assertEqual(e["reviewedSha256"], pinned[e["path"]], e["path"])

    def test_gates(self):
        g = self.d["evidence"]["gates"]
        self.assertEqual(self.d["evidence"]["state"], "PLANNED_BASELINE_TARGET")
        self.assertEqual((g["G1"], g["G2"]), ("RECORDED", "RECORDED"))
        for k in ("G3", "G4", "G5", "G6", "G7", "G8"):
            self.assertEqual(g[k], "NOT_RUN", k)


if __name__ == "__main__":
    unittest.main()
