"""Privileged network-egress guard for the Linux bubblewrap tool sandbox.

Run as root through a locked-down ``sudo`` rule, invoked only by the toolyard's
``BwrapRunner``. It confines ONE tool's outbound network with a per-tool cgroup v2 plus an
nftables rule: the tool may answer the broker (established connections) and, when it has an
egress allowlist, reach the broker's loopback egress proxy on a single port -- every other
outbound packet is dropped. This is the Linux counterpart of the macOS Seatbelt profile's
network confinement, and it is cgroup-scoped so the rest of the host is untouched.

Subcommands (both keyed by a validated ``--tool`` id):

``run [--proxy-port P] -- <argv...>``
    Create the tool's cgroup and install its nft rule, join the cgroup, drop privileges,
    and ``exec`` <argv> (the bwrap-wrapped tool). The join happens *before* the exec, so the
    tool is inside the confined cgroup before it can send a packet. On any failure before the
    exec it tears the setup back down and exits non-zero.
``teardown -- <ignored>``
    Kill anything left in the tool's cgroup, remove its nft rule, and remove the cgroup.
    Idempotent, so it is safe to call for a tool that never fully started.

Privilege containment: the tool always runs as the *invoking* user, taken from ``SUDO_UID`` /
``SUDO_GID`` (never from an argument), and the helper refuses to run as anything but root
dropping to a non-root user. A caller therefore cannot use it to gain privilege -- it only
ever lands back at the unprivileged user the broker already runs as. Root is confined to this
one small helper; the broker itself stays unprivileged.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess

CGROUP_ROOT = "/sys/fs/cgroup"
PARENT = "toolyard"                       # tool cgroups live at /sys/fs/cgroup/toolyard/<id>
_CGROUP_LEVEL = 2                         # depth of the leaf below the cgroup root (toolyard/<id>)
_TOOL_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_NFT = "/usr/sbin/nft"


def _tool_id(value: str) -> str:
    if not _TOOL_RE.fullmatch(value):
        raise SystemExit(f"netguard: invalid tool id {value!r}")
    return value


def _cgroup_dir(tool_id: str) -> str:
    return f"{CGROUP_ROOT}/{PARENT}/{tool_id}"


def _table(tool_id: str) -> str:
    # one nft table per tool, named in nft's identifier charset (alnum + underscore).
    return "toolyard_" + re.sub(r"[^a-z0-9_]", "_", tool_id)


def _ruleset(tool_id: str, proxy_port: int | None) -> str:
    """The per-tool nft ruleset. Allow the tool's established traffic (so it can serve the
    broker) and, when given, new outbound only to the loopback egress proxy port; drop every
    other IPv4/IPv6 packet from the cgroup. With no proxy port the tool gets no new outbound
    at all (the deny-all-egress default)."""
    cg = f"{PARENT}/{tool_id}"
    rules = [f'socket cgroupv2 level {_CGROUP_LEVEL} "{cg}" ct state established,related accept']
    if proxy_port is not None:
        rules.append(f'socket cgroupv2 level {_CGROUP_LEVEL} "{cg}" ip daddr 127.0.0.1 '
                     f"tcp dport {proxy_port} accept")
    rules.append(f'socket cgroupv2 level {_CGROUP_LEVEL} "{cg}" meta nfproto ipv4 drop')
    rules.append(f'socket cgroupv2 level {_CGROUP_LEVEL} "{cg}" meta nfproto ipv6 drop')
    body = "\n    ".join(rules)
    return (f"table inet {_table(tool_id)} {{\n"
            f"  chain out {{\n"
            f"    type filter hook output priority 0; policy accept;\n"
            f"    {body}\n"
            f"  }}\n"
            f"}}\n")


def _restore_dumpable() -> None:
    """Re-mark the process dumpable after dropping from root. ``setuid`` away from root clears
    the dumpable flag, which leaves ``/proc/self/uid_map`` (and ``setgroups``) owned by root and
    unwritable -- so the ``bwrap`` we exec next fails its user-namespace setup with "setting up
    uid map: Permission denied". Restoring dumpability lets the unprivileged userns write its
    id maps. (Dumpable resets to 1 across a normal execve, but only after the map write bwrap's
    child needs, so we set it here explicitly first.)"""
    import ctypes

    PR_SET_DUMPABLE = 4
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


def _teardown(tool_id: str) -> None:
    cg = _cgroup_dir(tool_id)
    try:  # kill anything still in the cgroup so the rmdir below can succeed
        with open(os.path.join(cg, "cgroup.kill"), "w") as f:
            f.write("1")
    except OSError:
        pass
    subprocess.run([_NFT, "delete", "table", "inet", _table(tool_id)],
                   capture_output=True, text=True)  # ignore "No such file" if never created
    try:
        os.rmdir(cg)
    except OSError:
        pass


def _run(tool_id: str, proxy_port: int | None, argv: list[str]) -> None:
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        raise SystemExit("netguard: must be invoked via sudo by a non-root user "
                         "(SUDO_UID/SUDO_GID not set)")
    if os.geteuid() != 0 or uid == 0 or gid == 0:
        raise SystemExit("netguard: refuses to run except as root dropping to a non-root user")
    cg = _cgroup_dir(tool_id)
    try:
        os.makedirs(cg, exist_ok=True)
        # Drop any leftover table from a prior run first so a reused id gets a clean ruleset
        # (a bare "table" block in nft -f appends to an existing table rather than replacing it).
        subprocess.run([_NFT, "delete", "table", "inet", _table(tool_id)],
                       capture_output=True, text=True)
        subprocess.run([_NFT, "-f", "-"], input=_ruleset(tool_id, proxy_port),
                       text=True, check=True, capture_output=True)
        with open(os.path.join(cg, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))     # join the confined cgroup BEFORE dropping priv / exec
    except BaseException:
        _teardown(tool_id)
        raise
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)                        # drop root; the tool runs as the broker's own user
    _restore_dumpable()                   # so the bwrap we exec can set up its user namespace
    os.execvp(argv[0], argv)             # replaces this process -- never returns on success


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="toolyard.netguard")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "teardown"):
        sp = sub.add_parser(name)
        sp.add_argument("--tool", required=True, type=_tool_id)
        if name == "run":
            sp.add_argument("--proxy-port", type=int, default=None)
        sp.add_argument("rest", nargs=argparse.REMAINDER)   # the "-- <argv>" tail
    ns = p.parse_args(argv)
    if ns.cmd == "run":
        if ns.proxy_port is not None and not (0 < ns.proxy_port < 65536):
            raise SystemExit(f"netguard: invalid --proxy-port {ns.proxy_port}")
        tail = ns.rest[1:] if ns.rest and ns.rest[0] == "--" else ns.rest
        if not tail:
            raise SystemExit("netguard run: missing '-- <argv>' to exec")
        _run(ns.tool, ns.proxy_port, tail)
    else:
        _teardown(ns.tool)


if __name__ == "__main__":
    main()
