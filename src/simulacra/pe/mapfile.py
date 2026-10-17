"""MSVC linker `.map` files: function name -> RVA."""

from __future__ import annotations

import re

# ` 0001:00000010       adler32_combine_  0000000180001010 f   adler32.obj`
_MAP_LINE = re.compile(r"^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s+f\s", re.I)


def parse_map(text: str, image_base: int) -> dict[str, int]:
    """Functions (public and static) by name. The first address wins for a repeated name."""
    names: dict[str, int] = {}
    for line in text.splitlines():
        m = _MAP_LINE.match(line)
        if m:
            names.setdefault(m.group(1), int(m.group(2), 16) - image_base)
    return names
