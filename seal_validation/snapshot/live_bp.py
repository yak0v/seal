"""lldb helper: set a breakpoint in a shared-cache image by its FILE address.

Breaking by local symbol name (e.g. aa_lineto) in the live dyld shared cache is
slow/unreliable — lldb won't resolve stripped local symbols. We know the file
(cache) addresses from the extracted binary, so resolve file-addr -> runtime via
the loaded module's slide and break there.

    (lldb) command script import seal_validation/snapshot/live_bp.py
    (lldb) b main
    (lldb) run
    (lldb) seal_setbp CoreGraphics 0x186a24e80     # aa_lineto
    (lldb) continue

ROLE
----
The lldb-side companion to ``angrgui/snapshot/capture.py`` for shared-cache targets:
it turns a known FILE address (from the extracted binary / IDA) into a live breakpoint
in a dyld-shared-cache image, so you can stop exactly where SEAL will seed and then run
``seal_snapshot``. This is the mechanism we used to capture + validate CVE-2026-86950 on
this Mac's real macOS CoreGraphics.

WHY IT'S LIKE THIS
------------------
Breaking by local symbol NAME (``b aa_lineto``) in the live shared cache is slow and
unreliable — lldb won't resolve stripped local symbols, so it hangs on symbolication or
silently never binds. We already know the file (cache) address from the extracted
binary, so we resolve file-addr → runtime via the loaded module's slide
(``ResolveFileAddress`` + ``GetLoadAddress``) and set a breakpoint on the runtime address
directly. The printed ``slide`` is the same value the snapshot records for ``rebase.py``.

EXTENDING
---------
Point it at any shared-cache module: ``seal_setbp <ModuleName> <file_addr_hex>``. For a
different host/environment, the same ResolveFileAddress→GetLoadAddress trick works for
any image lldb has mapped.

PITFALLS
--------
* The module name must match what lldb lists (``image list``), and the file address must
  be from the SAME build that's mapped, or the slide — and thus the breakpoint — is wrong.
* Set the breakpoint at the true function entry if you intend to symbolize argument
  registers downstream (see ``capture.py`` PITFALLS).
"""
import lldb


def seal_setbp(debugger, command, result, internal_dict):
    parts = command.split()
    modname, fileaddr = parts[0], int(parts[1], 16)
    target = debugger.GetSelectedTarget()
    mod = None
    for m in target.module_iter():
        if m.GetFileSpec().GetFilename() == modname:
            mod = m
            break
    if mod is None:
        result.SetError("module %s not loaded" % modname)
        return
    sbaddr = mod.ResolveFileAddress(fileaddr)
    load = sbaddr.GetLoadAddress(target)
    bp = target.BreakpointCreateByAddress(load)
    sym = sbaddr.GetSymbol().GetName() if sbaddr.GetSymbol().IsValid() else "?"
    result.AppendMessage("SEAL_BP module=%s file=%#x -> load=%#x locs=%d sym=%s slide=%#x"
                         % (modname, fileaddr, load, bp.GetNumLocations(), sym, load - fileaddr))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f live_bp.seal_setbp seal_setbp")
