"""``python3 -m admin`` — run the admin web app or set its login password.

    python3 -m admin set-password         # set/replace the admin login password
    python3 -m admin serve [--port 8780]  # serve on 127.0.0.1 (loopback only)

The server refuses to start until a password has been set (fail closed — there
are no default credentials). ``serve`` imports FastAPI/uvicorn lazily, so
``set-password`` works on a plain stdlib Python before the deps are installed.
"""

from __future__ import annotations

import logging
import os

import argparse
import getpass
import sys

from . import auth, settings


def _set_password(args) -> None:
    pw = getpass.getpass("New admin password: ")
    if not pw:
        raise SystemExit("password must not be empty")
    if pw != getpass.getpass("Confirm password: "):
        raise SystemExit("passwords did not match")
    settings.write_password_hash(auth.hash_password(pw))
    settings.rotate_session_secret()  # a password change logs out existing sessions
    print(f"admin password set ({settings.password_hash_file()}); existing sessions invalidated "
          "(restart the admin to apply).")


def _serve(args) -> None:
    if settings.read_password_hash() is None:
        raise SystemExit("no admin password set — run: python3 -m admin set-password")
    from .server import create_app  # lazy: pulls in FastAPI/uvicorn
    import uvicorn

    # Loopback by default (mirroring the broker); reach it remotely over a tailnet /
    # SSH tunnel. TOOLSTACK_ADMIN_HOST overrides it ONLY for the in-container case, where
    # the boundary becomes Docker's publish-to-127.0.0.1 mapping. See settings.admin_host.
    uvicorn.run(create_app(), host=settings.admin_host(), port=args.port)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=os.environ.get("TOOLSTACK_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="admin")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("set-password", help="set/replace the admin login password")
    p.set_defaults(func=_set_password)

    p = sub.add_parser("serve", help="serve the admin web app on 127.0.0.1")
    p.add_argument("--port", type=int, default=8780)
    p.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
