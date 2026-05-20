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
    args = parser.parse_args()

    if args.command == "scaffold" and args.scaffold_command == "serve":
        try:
            import uvicorn
        except Exception as error:
            raise SystemExit("pycell scaffold serve requires optional dependencies: pip install -e '.[scaffold]'") from error

        uvicorn.run("cellprotocol_scaffold.app:create_app", factory=True, host=args.host, port=args.port)
