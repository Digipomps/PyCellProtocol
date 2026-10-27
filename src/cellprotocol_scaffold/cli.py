from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="pycell")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scaffold = subcommands.add_parser("scaffold")
    scaffold_subcommands = scaffold.add_subparsers(dest="scaffold_command", required=True)
    serve = scaffold_subcommands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--public-url", help="Public bridge origin, e.g. wss://node.example (sets PYCELL_PUBLIC_URL)")
    serve.add_argument("--allow-insecure-loopback", action="store_true", help="Allow ws:// on localhost for local tests")
    args = parser.parse_args()

    if args.command == "scaffold" and args.scaffold_command == "serve":
        try:
            import uvicorn
        except Exception as error:
            raise SystemExit("pycell scaffold serve requires optional dependencies: pip install -e '.[scaffold]'") from error

        import os

        if args.public_url:
            os.environ["PYCELL_PUBLIC_URL"] = args.public_url
        if args.allow_insecure_loopback:
            os.environ["PYCELL_ALLOW_INSECURE_LOOPBACK"] = "1"
        uvicorn.run("cellprotocol_scaffold.app:create_app", factory=True, host=args.host, port=args.port)
