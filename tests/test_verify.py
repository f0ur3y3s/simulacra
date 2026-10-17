import json
from pathlib import Path

from simulacra.acceptance import verify_manifests


def write(
    path: Path, functions: dict[str, str], corpus: str = "c0", banner: str = "19.44.35229 for x64"
) -> Path:
    path.write_text(
        json.dumps({"functions": functions, "corpus_sha256": corpus, "cl_banner": banner})
    )
    return path


def test_identical_manifests_pass(tmp_path: Path) -> None:
    f = {"O2:zlib/a.c:f": "aa", "O2:zlib/a.c:g": "bb"}
    rep = verify_manifests(write(tmp_path / "a", f), write(tmp_path / "b", f))
    assert rep.ok and rep.identical == 2


def test_hash_difference_fails(tmp_path: Path) -> None:
    a = write(tmp_path / "a", {"k1": "aa", "k2": "bb"})
    b = write(tmp_path / "b", {"k1": "aa", "k2": "cc"})
    rep = verify_manifests(a, b)
    assert not rep.ok and rep.different == ["k2"]
    assert "FAIL" in rep.summary()


def test_missing_functions_or_corpus_mismatch_fail(tmp_path: Path) -> None:
    a = write(tmp_path / "a", {"k1": "aa", "k2": "bb"})
    assert not verify_manifests(a, write(tmp_path / "b", {"k1": "aa"})).ok
    assert not verify_manifests(a, write(tmp_path / "c", {"k1": "aa", "k2": "bb"}, "c1")).ok


def test_different_compilers_fail_even_with_identical_hashes(tmp_path: Path) -> None:
    f = {"k1": "aa"}
    a = write(tmp_path / "a", f)
    b = write(tmp_path / "b", f, banner="19.44.35211 for x64")
    rep = verify_manifests(a, b)
    assert not rep.ok and not rep.banner_match
