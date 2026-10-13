"""Read a Mach-O process core by virtual address.

A core (``process save-core`` in lldb) is the complete private memory image of a process:
a list of segments, each mapping a virtual-address range to bytes in the file. This parses
the ``LC_SEGMENT_64`` table and serves bytes/pages at any vaddr, so SEAL can fault pages in
on demand during symbolic execution (see runner's snapshot restore) instead of pre-loading
anything. The file is mmap'd, so reads are lazy at the OS level too.

    core = MachOCore("/tmp/snap.core")
    core.read(0x12600a200, 8)      # -> bytes, or None if that vaddr isn't in the core
"""
from __future__ import annotations

import mmap
import struct

_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
PAGE = 0x1000


class MachOCore:
    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.segments: list[tuple[int, int, int, int]] = []   # (vmaddr, vmsize, fileoff, filesize)
        self._parse()
        self.segments.sort()

    def _parse(self):
        data = self._mm
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != _MH_MAGIC_64:
            raise ValueError(f"not a 64-bit Mach-O core (magic {magic:#x})")
        ncmds = struct.unpack_from("<I", data, 16)[0]
        p = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, p)
            if cmd == _LC_SEGMENT_64:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, p + 24)
                if vmsize and filesize:
                    self.segments.append((vmaddr, vmsize, fileoff, filesize))
            if cmdsize == 0:
                break
            p += cmdsize

    def _seg_of(self, vaddr: int):
        lo, hi = 0, len(self.segments) - 1
        while lo <= hi:
            m = (lo + hi) >> 1
            v, sz, fo, fs = self.segments[m]
            if v <= vaddr < v + sz:
                return self.segments[m]
            if vaddr < v:
                hi = m - 1
            else:
                lo = m + 1
        return None

    def contains(self, vaddr: int) -> bool:
        return self._seg_of(vaddr) is not None

    def read(self, vaddr: int, size: int) -> bytes | None:
        """Bytes at vaddr, spanning segments as needed. Returns what IS backed by the core
        (may be shorter than `size`); None if vaddr isn't in any segment."""
        out = bytearray()
        a = vaddr
        while len(out) < size:
            seg = self._seg_of(a)
            if seg is None:
                break
            v, sz, fo, fs = seg
            off = a - v
            avail = min(fs - off, sz - off)            # bytes backed in this segment from `a`
            if avail <= 0:
                break
            take = min(size - len(out), avail)
            out += self._mm[fo + off: fo + off + take]
            a += take
        return bytes(out) if out else None

    def read_page(self, vaddr: int) -> bytes | None:
        """The 4 KiB page containing vaddr, as backed by the core (None if unbacked)."""
        base = vaddr & ~(PAGE - 1)
        return self.read(base, PAGE)

    def close(self):
        try:
            self._mm.close(); self._f.close()
        except Exception:
            pass
