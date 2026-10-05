"""Rebase a live-captured snapshot into a binary's file-address space.

A snapshot taken from a running process holds *runtime* addresses: the image is
loaded at an ASLR slide, so pc and every pointer into the image are `file_addr +
slide`. SEAL (via cle's Mach-O backend) loads the image at its *file* addresses,
so before seeding we subtract the slide from everything that points into the
image — pc, registers, memory-region bases, and 8-byte pointer slots inside the
captured bytes. Heap/stack addresses (outside the image) are left untouched; their
captured regions keep their own addresses, which don't collide with the image.

    snap = json.load(...)
    snap = rebase(snap, slide=0x10984000,
                  img_file_lo=0x1869d6000, img_file_hi=0x1feea7fff)

WHY IT'S LIKE THIS
------------------
cle keeps a Mach-O at its FILE addresses (``base_addr`` is ignored for that backend —
see ``engine.py``), so we can't slide the loaded image UP to meet the snapshot; we slide
the SNAPSHOT DOWN to meet the image. Only addresses that fall in the image's runtime
range are rebased; heap/stack addresses (and the bytes at them) are left exactly as
captured, because they have no counterpart in the file and must keep their own values.
``runner._build_state_from_snapshot`` calls this automatically when a snapshot carries
``image.slide`` (deriving the file range from the loaded object).

EXTENDING
---------
If a future loader DID honor a load base, you could skip rebasing entirely and load the
image at ``file_lo + slide`` instead — then pc and pointers would already line up.

PITFALLS
--------
* The image file range must be correct. Too wide and you'll rebase heap/stack pointers
  that merely look in-range; too narrow and real code pointers stay slid and the run
  dies. Heap/stack must NOT overlap ``[file_lo+slide, file_hi+slide]``.
* Pointer slots are detected structurally (any in-range 8-byte LE value); a non-pointer
  that happens to fall in-range will be rebased too — acceptable in practice but worth
  knowing if a seed behaves oddly.
"""


def rebase(snap: dict, slide: int, img_file_lo: int, img_file_hi: int) -> dict:
    lo, hi = img_file_lo + slide, img_file_hi + slide        # runtime image range
    in_img = lambda v: lo <= v <= hi
    reb = lambda v: v - slide if in_img(v) else v

    out = dict(snap)
    out["pc"] = reb(int(snap["pc"]))
    out["regs"] = {k: reb(int(v)) for k, v in snap["regs"].items()}

    mem = []
    for m in snap.get("mem", []):
        data = bytearray.fromhex(m["hex"])
        for off in range(0, len(data) - 7, 8):               # rebase in-image pointer slots
            p = int.from_bytes(data[off:off + 8], "little")
            if in_img(p):
                data[off:off + 8] = (p - slide).to_bytes(8, "little")
        mem.append({"addr": reb(int(m["addr"])), "hex": data.hex()})
    out["mem"] = mem

    sym = []
    for s in snap.get("symbolic", []):
        s = dict(s)
        if s.get("addr") is not None and in_img(int(s["addr"])):
            s["addr"] = int(s["addr"]) - slide
        sym.append(s)
    out["symbolic"] = sym
    return out
