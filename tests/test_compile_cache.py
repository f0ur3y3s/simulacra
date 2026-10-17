from pathlib import Path

from mscmatch.compile import CompileRequest, CompileResult
from mscmatch.compile.cache import CompileCache
from mscmatch.compile.types import BASE_FLAGS, clean_diagnostics


def test_cache_key_covers_inputs_but_not_function_name() -> None:
    base = CompileRequest("int f(void){return 0;}", "", "f", "", ("/O2",))
    same = CompileRequest("int f(void){return 0;}", "", "other", "", ("/O2",))
    assert base.cache_key("tc") == same.cache_key("tc")
    variants = [
        CompileRequest("int f(void){return 1;}", "", "f", "", ("/O2",)),
        CompileRequest("int f(void){return 0;}", "#define X", "f", "", ("/O2",)),
        CompileRequest("int f(void){return 0;}", "", "f", "", ("/O1",)),
    ]
    keys = {v.cache_key("tc") for v in variants} | {base.cache_key("tc2")}
    assert base.cache_key("tc") not in keys and len(keys) == 4


def test_cl_args() -> None:
    req = CompileRequest("x", "ctx", flags=("/O2", "/GS-"))
    assert req.cl_args() == [*BASE_FLAGS, "/TC", "/FIctx.h", "/O2", "/GS-", "src.c"]
    assert CompileRequest("x").cl_args()[-1] == "src.c"
    assert "/FIctx.h" not in CompileRequest("x").cl_args()


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = CompileCache(tmp_path)
    assert cache.get("k") is None
    cache.put("k", CompileResult(True, "warn", b"\x01\x02", 0.5))
    hit = cache.get("k")
    assert hit is not None and hit.cached and hit.obj_bytes == b"\x01\x02" and hit.stderr == "warn"
    cache.put("err", CompileResult(False, "error C2143", b"", 0.1))
    miss = cache.get("err")
    assert miss is not None and not miss.ok and miss.obj_bytes == b""
    cache.close()


def test_timeouts_are_not_cached(tmp_path: Path) -> None:
    cache = CompileCache(tmp_path)
    cache.put("t", CompileResult(False, "", b"", 20.0, timed_out=True))
    assert cache.get("t") is None
    cache.close()


def test_clean_diagnostics_drops_filename_echo() -> None:
    out = "src.c\nsrc.c(1): error C2143: syntax error\n"
    assert clean_diagnostics(out, "") == "src.c(1): error C2143: syntax error"
