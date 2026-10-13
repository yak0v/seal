"""MachOCore reads bytes from a Mach-O process core by virtual address — the backing for
lazy snapshot page-in. Built against a hand-made minimal core so it needs no real process."""
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui.snapshot.core import MachOCore          # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def _make_core(path, vmaddr, payload, vmsize=None):
    """A minimal MH_CORE Mach-O with one LC_SEGMENT_64 mapping vmaddr -> payload."""
    vmsize = vmsize or len(payload)
    hdr_size, cmd_size = 32, 72
    fileoff = hdr_size + cmd_size
    header = struct.pack("<IiiIIII", MH_MAGIC_64, 0x0100000C, 0, 4, 1, cmd_size, 0) + b"\0\0\0\0"
    seg = struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, cmd_size, b"__CORE",
                      vmaddr, vmsize, fileoff, len(payload), 3, 3, 0, 0)
    with open(path, "wb") as f:
        f.write(header); f.write(seg); f.write(payload)


def test_core_reads_by_vaddr():
    vmaddr = 0x100000000
    payload = bytearray(0x1000)
    payload[0x10:0x18] = struct.pack("<Q", 0xDEADBEEFCAFEF00D)   # a marker at vmaddr+0x10
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.core")
        _make_core(p, vmaddr, bytes(payload), vmsize=0x2000)      # mapped 0x2000, only 0x1000 backed
        c = MachOCore(p)
        assert len(c.segments) == 1
        assert c.contains(vmaddr) and c.contains(vmaddr + 0xFFF)
        # exact field read
        assert struct.unpack("<Q", c.read(vmaddr + 0x10, 8))[0] == 0xDEADBEEFCAFEF00D
        # whole page comes back
        assert len(c.read_page(vmaddr + 0x123)) == 0x1000
        # vmsize extends past filesize: the unbacked tail returns nothing
        assert c.read(vmaddr + 0x1000, 8) is None
        # an address in no segment
        assert c.read(0xDEAD0000, 8) is None
        assert not c.contains(0xDEAD0000)
        c.close()
