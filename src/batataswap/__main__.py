"""Ponto de entrada: `python -m batataswap`."""

import argparse
import sys

from batataswap import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="batataswap", description="Memória compartilhada entre contas Claude."
    )
    parser.add_argument("--version", action="version", version=f"batataswap {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="comando")
    subparsers.add_parser("serve", help="sobe o servidor (ainda não implementado)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    if args.command == "serve":
        print("ainda não implementado", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
