#!/usr/bin/env python3
"""Launch the angr bug-hunting GUI.

    python run.py                 # serve on http://127.0.0.1:8000
    python run.py --port 9000
    python run.py --binary samples/vuln   # load a binary immediately
"""
import argparse
import webbrowser

import uvicorn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--binary", default=None, help="binary to load on startup")
    ap.add_argument("--target-func", action="append", default=None,
                    help="scope analysis to this function address (hex ok); repeatable. "
                         "Needed for big arm64 dylibs where whole-binary CFG is impractical.")
    ap.add_argument("--open", action="store_true", help="open a browser tab")
    args = ap.parse_args()

    from angrgui import server
    if args.binary:
        from angrgui.server import S
        from angrgui.engine import Binary
        from angrgui.workspace import Workspace
        tf = [int(x, 0) for x in args.target_func] if args.target_func else None
        S.binary = Binary(args.binary, progress=lambda m: print("  ", m), target_funcs=tf)
        S.workspace = Workspace(args.binary)
        print(f"loaded {args.binary}" + (f" (scoped to {args.target_func})" if tf else ""))

    url = f"http://{args.host}:{args.port}"
    print(f"\n  angr GUI running at {url}\n")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(server.app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
