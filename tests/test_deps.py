import json

import pytest

from baitbox import deps
from baitbox.deps import collector, registry, specs
from conftest import write


class FakeHttp:
    def __init__(self, gets=None, osv=None):
        self.gets = gets or {}
        self.osv = osv or {}
        self.calls = []

    def get(self, url, max_bytes=0):
        self.calls.append(url)
        for prefix, resp in self.gets.items():
            if url == prefix:
                return resp
        if url.startswith(registry.DOWNLOADS):
            return 200, {"downloads": 10_000_000}
        return 404, None

    def post(self, url, body, max_bytes=0):
        results = []
        for q in body["queries"]:
            key = (q["package"]["name"], q.get("version"))
            results.append({"vulns": self.osv.get(key, [])})
        return 200, {"results": results}


def iso(days_ago):
    import datetime

    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def collect(root):
    c = collector.Collector(root)
    c.walk()
    return c


def test_package_lock_v3(tmp_path):
    write(tmp_path, "package.json", json.dumps({"name": "app", "dependencies": {"a": "^1.0.0", "ws-ui": "workspace:*"}}))
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/a": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/a/-/a-1.2.3.tgz"},
        "node_modules/a/node_modules/b": {"version": "2.0.0", "resolved": "https://evil.example/b.tgz"},
        "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3"},
        "node_modules/ws-ui": {"resolved": "packages/ui", "link": True},
        "packages/ui": {"name": "ws-ui", "version": "0.0.1"},
        "node_modules/g": {"version": "git+ssh://git@github.com/x/g.git#abc"},
    }}))
    c = collect(tmp_path)
    assert c.packages["a"] == {"1.2.3"} and c.packages["b"] == {"2.0.0"} and c.packages["string-width"] == {"4.2.3"}
    assert "ws-ui" in c.local and "string-width-cjs" in c.aliases
    kinds = {(s["name"], s["kind"]) for s in c.sources}
    assert ("b", "lockfile") in kinds and ("g", "git") in kinds


def test_package_lock_v1(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        "x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}},
        "z": {"version": "file:../z"},
    }}))
    c = collect(tmp_path)
    assert c.packages["x"] == {"1.0.0"} and c.packages["y"] == {"2.0.0"} and "z" in c.local


def test_pnpm_lock_v6_and_v9(tmp_path):
    write(tmp_path, "a/pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n  /@babel/core@7.24.0(supports-color@8.1.1):\n    resolution: {integrity: sha512-y}\n  /evil@1.0.0:\n    resolution: {tarball: https://evil.example/e.tgz}\n")
    write(tmp_path, "b/pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      x:\n        specifier: ^1\n        version: 1.0.0\npackages:\n  '@scope/pkg@2.0.0':\n    resolution: {integrity: sha512-z}\n  react@18.2.0:\n    resolution: {integrity: sha512-r}\nsnapshots:\n  react-dom@18.2.0(react@18.2.0):\n    dependencies:\n      react: 18.2.0\n")
    write(tmp_path, "c/pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-l}\n  /@types/node/20.1.0_abc:\n    dev: true\n")
    c = collect(tmp_path)
    assert c.packages["left-pad"] == {"1.3.0"}
    assert c.packages["@babel/core"] == {"7.24.0"}
    assert c.packages["@scope/pkg"] == {"2.0.0"} and c.packages["react-dom"] == {"18.2.0"}
    assert c.packages["lodash"] == {"4.17.21"} and c.packages["@types/node"] == {"20.1.0"}
    assert any(s["name"] == "evil" and "evil.example" in s["source"] for s in c.sources)
    assert "x" not in c.packages


def test_yarn_v1_and_berry(tmp_path):
    write(tmp_path, "a/yarn.lock", '# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.24.2"\n  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz"\n\nfoo@npm:bar@^1.0.0:\n  version "1.0.5"\n\nodd@^1.0.0:\n  version "1.0.0"\n  resolved "https://evil.example/odd.tgz"\n')
    write(tmp_path, "b/yarn.lock", '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n\n"bad@exec:./build.js":\n  version: 0.0.0\n')
    c = collect(tmp_path)
    assert c.packages["@babel/code-frame"] == {"7.24.2"}
    assert c.packages["bar"] == {"1.0.5"} and "foo" in c.aliases
    assert c.packages["lodash"] == {"4.17.21"} and "app" in c.local
    assert any(s["name"] == "bad" and s["kind"] == "exec" and s["severity"] == "high" for s in c.sources)
    assert any(s["name"] == "odd" for s in c.sources)


def test_bun_lock(tmp_path):
    write(tmp_path, "bun.lock", '{\n  "lockfileVersion": 1,\n  "packages": {\n    "react": ["react@18.3.1", "", {}, "sha512-x"],\n    "my-alias": ["real-pkg@2.0.0", "", {}, "sha512-y"],\n    "lib": ["lib@workspace:packages/lib"],\n    "gh": ["gh@github:user/repo#abc", {}],\n  }\n}\n')
    c = collect(tmp_path)
    assert c.packages["react"] == {"18.3.1"} and c.packages["real-pkg"] == {"2.0.0"}
    assert "lib" in c.local and any(s["name"] == "gh" for s in c.sources)


def test_manifest_specs(tmp_path):
    write(tmp_path, "package.json", json.dumps({
        "dependencies": {
            "a": "npm:real-a@^1", "b": "github:user/b", "c": "file:../../../etc", "d": "https://x/d.tgz", "e": "user/e#main",
            "f": "link:./local", "g": "catalog:", "h": "exec:./x.js",
        },
        "overrides": {"q": {"r": "git+https://x/r.git"}},
        "pnpm": {"overrides": {"s": "https://x/s.tgz"}},
    }))
    write(tmp_path, "local/package.json", json.dumps({"name": "f"}))
    c = collect(tmp_path)
    kinds = {(s["name"], s["kind"]) for s in c.sources}
    assert ("a", "alias") in kinds and ("b", "git") in kinds and ("c", "file") in kinds
    assert ("d", "url") in kinds and ("e", "git") in kinds and ("h", "exec") in kinds
    assert ("r", "git") in kinds and ("s", "url") in kinds
    assert "real-a" in c.packages and "g" in c.packages and "f" in c.local
    assert ("f", "link") not in kinds


@pytest.mark.parametrize("name", ["../../etc/passwd", "a b", "x?y", "", "@scope/", "A" * 300, "@Scope/x", "a/../b"])
def test_invalid_names(name):
    assert not specs.valid_name(name)


@pytest.mark.parametrize("name", ["react", "@babel/core", "JSONStream", "lodash.merge", "@a/b-c_d"])
def test_valid_names(name):
    assert specs.valid_name(name)


def test_invalid_lockfile_name_is_high(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/../../x": {"version": "1.0.0"}}}))
    r = deps.check(tmp_path, offline=True)
    assert any(f["kind"] == "invalid-name" and f["severity"] == "high" for f in r["findings"])


def test_node_modules_name_mismatch_and_extras(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/react": {"version": "18.0.0"}}}))
    write(tmp_path, "node_modules/react/package.json", json.dumps({"name": "react", "version": "18.0.0"}))
    write(tmp_path, "node_modules/lodash/package.json", json.dumps({"name": "totally-not-lodash", "version": "1.0.0"}))
    write(tmp_path, "node_modules/@s/x/package.json", json.dumps({"name": "@s/x", "version": "1.0.0"}))
    r = deps.check(tmp_path, offline=True)
    k = {f["kind"] for f in r["findings"]}
    assert "name-mismatch" in k and "not-in-lockfile" in k


def test_throwaway_package_is_high(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"tw-fake": "^2.0.0"}}))
    http = FakeHttp(gets={
        f"{registry.DOWNLOADS}/tw-fake": (200, {"downloads": 12}),
        f"{registry.REGISTRY}/tw-fake": (200, {"time": {"created": iso(6), "2.0.2": iso(6)}, "versions": {"2.0.2": {}}, "dist-tags": {"latest": "2.0.2"}, "maintainers": [{"email": "x@proton.me"}]}),
    })
    r = deps.check(tmp_path, http=http)
    p = r["packages"][0]
    assert p["severity"] == "high" and any(f["code"] == "THROWAWAY" for f in p["flags"])


def test_not_on_npm_and_private_registry(tmp_path):
    write(tmp_path, "a/package.json", json.dumps({"dependencies": {"@codentra/postcss-kinetix": "^1.0.1"}}))
    r = deps.check(tmp_path / "a", http=FakeHttp(gets={f"{registry.DOWNLOADS}/@codentra/postcss-kinetix": (404, None)}))
    assert r["packages"][0]["flags"][0]["code"] == "NOT_ON_NPM"
    write(tmp_path, "b/package.json", json.dumps({"dependencies": {"@corp/ui": "^1.0.0"}}))
    write(tmp_path, "b/.npmrc", "@corp:registry=https://npm.corp.example/\n")
    r = deps.check(tmp_path / "b", http=FakeHttp(gets={f"{registry.DOWNLOADS}/@corp/ui": (404, None)}))
    assert r["packages"][0]["flags"][0]["code"] == "PRIVATE_REGISTRY"


def test_security_placeholder_and_osv_malware(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"tw-motion-css": "^2.0.2", "chalk": "5.6.1"}}))
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/chalk": {"version": "5.6.1"}}}))
    http = FakeHttp(
        gets={
            f"{registry.DOWNLOADS}/tw-motion-css": (200, {"downloads": 500}),
            f"{registry.REGISTRY}/tw-motion-css": (200, {"time": {"created": iso(400)}, "versions": {"0.0.1-security": {}}, "dist-tags": {"latest": "0.0.1-security"}}),
            f"{registry.REGISTRY}/chalk/5.6.1": (200, {"name": "chalk", "version": "5.6.1"}),
        },
        osv={("chalk", "5.6.1"): [{"id": "MAL-2025-46969"}]},
    )
    r = deps.check(tmp_path, http=http)
    by = {p["name"]: {f["code"] for f in p["flags"]} for p in r["packages"]}
    assert "REMOVED_BY_NPM_SECURITY" in by["tw-motion-css"]
    assert "KNOWN_MALWARE" in by["chalk"]


def test_popular_version_removed_from_npm(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/debug": {"version": "4.4.2"}}}))
    http = FakeHttp(gets={f"{registry.REGISTRY}/debug/4.4.2": (404, None)})
    r = deps.check(tmp_path, http=http)
    assert any(f["code"] == "VERSION_NOT_ON_NPM" for f in r["packages"][0]["flags"])


def test_lookalike_name(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"reqeusts": "1.0.0", "axois": "1.0.0", "react-dom": "18"}}))
    http = FakeHttp(gets={
        f"{registry.DOWNLOADS}/reqeusts": (200, {"downloads": 3}), f"{registry.DOWNLOADS}/axois": (200, {"downloads": 3}),
        f"{registry.REGISTRY}/reqeusts": (200, {"time": {"created": iso(900)}, "versions": {"1": {}, "2": {}, "3": {}}, "dist-tags": {}}),
        f"{registry.REGISTRY}/axois": (200, {"time": {"created": iso(900)}, "versions": {"1": {}, "2": {}, "3": {}}, "dist-tags": {}}),
    })
    r = deps.check(tmp_path, http=http)
    names = {x["name"] for x in r["lookalikes"]}
    assert "axois" in names and "react-dom" not in names


def test_install_script_flag(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/small": {"version": "1.0.0"}}}))
    http = FakeHttp(gets={
        f"{registry.DOWNLOADS}/small": (200, {"downloads": 2000}),
        f"{registry.REGISTRY}/small": (200, {"time": {"created": iso(900), "1.0.0": iso(900)}, "versions": {"1.0.0": {"scripts": {"postinstall": "node x.js"}}, "0.9.0": {}, "0.8.0": {}}, "dist-tags": {"latest": "1.0.0"}}),
    })
    r = deps.check(tmp_path, http=http)
    assert any(f["code"] == "INSTALL_SCRIPT" and f["severity"] == "medium" for f in r["packages"][0]["flags"])


def test_http_retries_then_gives_up(monkeypatch):
    import urllib.error

    calls = []

    def boom(req, timeout=0):
        calls.append(1)
        raise urllib.error.URLError("down")

    monkeypatch.setattr(registry.urllib.request, "urlopen", boom)
    monkeypatch.setattr(registry.time, "sleep", lambda s: None)
    st, data = registry.Http(retries=3).get("https://example.invalid/x")
    assert st == 0 and len(calls) == 3


def test_offline_and_render(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"a": "1.0.0"}}))
    r = deps.check(tmp_path, offline=True)
    assert r["offline"] and any("offline" in n for n in r["notes"])
    assert "Package check" in deps.render(r)


def test_pnpm_store_orphans_are_not_flagged(tmp_path):
    write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  react@18.2.0:\n    resolution: {integrity: sha512-r}\n")
    write(tmp_path, "node_modules/.pnpm/once@1.4.0/node_modules/once/package.json", json.dumps({"name": "once", "version": "1.4.0"}))
    write(tmp_path, "node_modules/stray/package.json", json.dumps({"name": "stray", "version": "1.0.0"}))
    r = deps.check(tmp_path, offline=True)
    extras = [f["what"] for f in r["findings"] if f["kind"] == "not-in-lockfile"]
    assert extras == ["stray is in node_modules but not in any lockfile"]


def test_prepare_script_is_not_an_install_script(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({"packages": {"node_modules/p": {"version": "1.0.0"}}}))
    http = FakeHttp(gets={
        f"{registry.DOWNLOADS}/p": (200, {"downloads": 2000}),
        f"{registry.REGISTRY}/p": (200, {"time": {"created": iso(900)}, "versions": {"1.0.0": {"scripts": {"prepare": "tsc"}}, "0.9.0": {}, "0.8.0": {}}, "dist-tags": {"latest": "1.0.0"}}),
    })
    r = deps.check(tmp_path, http=http)
    assert not any(f["code"] == "INSTALL_SCRIPT" for f in r["packages"][0]["flags"])
