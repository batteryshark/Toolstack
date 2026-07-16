"""Sandbox policy: the backend-neutral contract the native tool runners enforce.

Today the toolyard runs a tool with `ProcessRunner` (no isolation) or `DockerRunner`
(a container). The next runners are OS-native process sandboxes -- `sandbox-exec`
(Seatbelt) on macOS, and bubblewrap + Landlock + seccomp on Linux -- so a tool is
confined without a container runtime or a VM. Both of those backends need the same
two backend-neutral inputs, and that is all this module defines:

  * an EGRESS policy: deny outbound by default; a tool reaches the network only
    through a broker-owned loopback proxy, and only for the hosts on its allowlist.
    The OS sandbox blocks every other outbound path; the proxy enforces the host
    allow/deny. Keeping the destination policy here (not baked into an OS profile)
    is what lets both platforms share one policy engine.
  * RESOURCE caps: memory / cpu / pids ceilings. Enforced with cgroups v2 on Linux
    (first-class) and best-effort rlimits on macOS (there is no cgroups; a hard cap
    on macOS is the microVM upgrade tier's job, not Seatbelt's).

Both backends are implemented against this seam -- `SeatbeltRunner` (macOS) and
`BwrapRunner` (Linux, via the privileged `netguard` cgroup+nftables helper). `SandboxPolicy`
is what a runner receives to confine a tool, whatever the OS underneath; today both enforce
the egress policy (filesystem/syscall confinement is the next tightening). Constructing any
of these with no arguments yields the safe baseline: no outbound network, no caps set.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EgressPolicy:
    """Outbound-network policy: deny-by-default with an explicit host allowlist.

    An empty allowlist means no outbound at all (the safe default). A host on the
    list is reachable only via the broker's loopback egress proxy; the OS sandbox
    blocks direct sockets regardless, so a tool that bypasses the proxy simply gets
    no network (fail-closed)."""

    allow: tuple[str, ...] = ()

    @property
    def denies_all(self) -> bool:
        """True when nothing is allowed out -- the OS backend can then cut network
        entirely rather than stand up a loopback path to the proxy."""
        return not self.allow


@dataclass(frozen=True)
class ResourceCaps:
    """Per-tool resource ceilings. `None` means "no cap set" for that dimension.

    memory_mb: address-space / RSS ceiling, in MiB.
    cpu:       CPU allowance as a fraction of one core (1.0 == one full core).
    pids:      max processes/threads the tool may spawn.
    Enforced by cgroups v2 on Linux; best-effort rlimits on macOS."""

    memory_mb: int | None = None
    cpu: float | None = None
    pids: int | None = None

    def __post_init__(self) -> None:
        # Reject nonsense at construction so a bad cap fails here, not opaquely inside
        # a cgroup write or a setrlimit call at tool-start time.
        for name, value in (("memory_mb", self.memory_mb), ("pids", self.pids), ("cpu", self.cpu)):
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be positive, got {value!r}")


@dataclass(frozen=True)
class SandboxPolicy:
    """What a native runner receives to confine one tool: an egress policy and resource
    caps. Backend-neutral -- the Seatbelt and bubblewrap runners translate it into a
    Seatbelt profile / bwrap + Landlock args + cgroup limits respectively. The no-arg
    default is the safe baseline (deny-all egress, no caps); a tool opts into more."""

    egress: EgressPolicy = field(default_factory=EgressPolicy)
    resources: ResourceCaps = field(default_factory=ResourceCaps)
