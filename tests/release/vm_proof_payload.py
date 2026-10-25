"""Fixed stdlib guest receiver/worker. Also used locally to validate a git archive.

Only guest_main executes actions. Importing this module does not touch a host.
The reviewed source, never an input file's Python, is sent as python3 -c via QGA.
"""
import base64
import hashlib
import io
import json
import os
import pwd
import grp
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MEMBERS = 10000
CHUNK = 256 * 1024
RUN_RE = r"vmproof-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}"
LABEL = "toolstack.vmproof"
KINDS = ("onebox", "echo-api", "echo-mcp")
CONTAINER_KINDS = (*KINDS, "process-sps", "serve")
PROCESS_FIXTURE = "tests/integration/process_sps.py"
PROCESS_CHECKS = (
    "host boot identity preflight", "verified TLS ping", "unknown CA rejected",
    "independent credentials", "channel publication excludes SPS credentials",
    "SDK refresh string and safe boolean", "SPS credential rejected by channel",
    "channel credential rejected by SPS", "restart new boot", "registrations lost",
    "actual first recovery incomplete", "incomplete boot unacknowledged",
    "actual second recovery complete", "same boot retry", "new TLS retrieval",
    "persisted change affects next SDK refresh", "same live tool identity",
    "vault encrypted", "logs and audit exclude all fake values and credentials",
)
CURRENT_JOB = None
CHILD_SEQUENCE = 0
DOCKERFILES = {"onebox": "deploy/docker/Dockerfile", "echo-api": "tools/echo_api/Dockerfile", "echo-mcp": "tools/echo_mcp/Dockerfile"}


def require(test, message):
    if not test:
        raise ValueError(message)


def validate_archive(data, commit, digest):
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{64}", digest), "source identity")
    require(0 < len(data) <= MAX_ARCHIVE and hashlib.sha256(data).hexdigest() == digest, "archive checksum/size")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        require(archive.pax_headers.get("comment") == commit, "git archive commit metadata")
        names, expanded = set(), 0
        for member in archive:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            require(name and not path.is_absolute() and all(p not in ("", ".", "..") for p in name.split("/")), "archive path")
            require(not any(p in (".git", ".worktrees", ".env") for p in path.parts), "private/history archive path")
            require(name not in names and len(names) < MAX_MEMBERS, "archive duplicates/count")
            require(member.isfile() or member.isdir(), "archive link/special file")
            if name == PROCESS_FIXTURE:
                require(member.isfile() and 0 < member.size <= 65536, "process-SPS fixture regular/size")
            require(not member.issparse() and member.size >= 0, "archive sparse/size")
            expanded += member.size
            require(expanded <= MAX_EXPANDED, "archive expansion")
            names.add(name)
        require(all(p in names for p in DOCKERFILES.values()), "missing Dockerfiles")
        require(PROCESS_FIXTURE in names, "missing process-SPS fixture")
    return sorted(names)


def safe_directory(path):
    require(str(path).startswith("/"), "absolute directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).parts[1:]:
            require(part not in (".", ".."), "directory traversal")
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return os.fstat(fd)
    finally:
        os.close(fd)


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        raise


def read_private(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(), "private regular file")
        data = source.read(limit + 1)
        require(len(data) <= limit, "private file bound")
        return data


def process_identity(pid):
    text = Path("/proc/%d/stat" % pid).read_text()
    return {"pid": pid, "start": int(text[text.rfind(")") + 1:].split()[19]),
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


def clean_env(root):
    if root.name == "src":
        root = root.parent
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"), "DOCKER_CONFIG": str(root / "docker-config"),
            "XDG_CONFIG_HOME": str(root / "config"), "XDG_STATE_HOME": str(root / "state"),
            "XDG_CACHE_HOME": str(root / "cache"), "XDG_DATA_HOME": str(root / "data"),
            "XDG_RUNTIME_DIR": str(root / "runtime"), "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "UV_CONCURRENT_BUILDS": "1", "UV_CONCURRENT_INSTALLS": "1"}


def bounded(argv, root, seconds=30):
    """No shell, no inherited credentials; cap both streams, never print stderr."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, cwd=root, env=clean_env(root), close_fds=True)
    identity = process_identity(child.pid)
    sel = selectors.DefaultSelector()
    outputs = [bytearray(), bytearray()]
    deadline = time.monotonic() + seconds
    try:
        if CURRENT_JOB is not None:
            global CHILD_SEQUENCE
            CHILD_SEQUENCE += 1
            job_root = root.parent if root.name == "src" else root
            private_write(job_root / "jobs" / (CURRENT_JOB + "-child-" + str(CHILD_SEQUENCE)), json.dumps(identity).encode())
        for stream, data in zip((child.stdout, child.stderr), outputs):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, data)
        while sel.get_map() or child.poll() is None:
            require(time.monotonic() < deadline, "guest command timeout")
            for key, _ in sel.select(0.2):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    sel.unregister(key.fileobj)
                else:
                    key.data.extend(data)
                    require(sum(map(len, outputs)) <= 65536, "guest output limit")
        require(child.wait(timeout=1) == 0, "guest command failed")
        return bytes(outputs[0]).decode("utf-8")
    finally:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if child.poll() is not None:
                break
            try:
                require(process_identity(child.pid) == identity, "guest child identity changed")
                child.send_signal(sig)
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        sel.close()
        child.stdout.close()
        child.stderr.close()


def root_for(run):
    require(re.fullmatch(RUN_RE, run), "run id")
    return Path("/var/tmp/toolstack-proof-" + run)


def verify_root(root, run):
    info = safe_directory(root)
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "root ownership/mode")
    marker = json.loads(read_private(root / "owner"))
    require(marker == {"run": run, "dev": info.st_dev, "ino": info.st_ino}, "root identity")
    return marker


def initialize(root, run, commit, digest, size):
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{64}", digest), "payload identity")
    require(0 < int(size) <= MAX_ARCHIVE, "payload size")
    safe_directory(root.parent)
    root.mkdir(mode=0o700)  # absent-only, no exist_ok
    info = root.stat()
    marker = {"run": run, "dev": info.st_dev, "ino": info.st_ino}
    private_write(root / "owner", json.dumps(marker).encode())
    private_write(root / "payload-meta", json.dumps({"commit": commit, "sha256": digest, "size": int(size)}).encode())
    private_write(root / "payload.tar", b"")
    for name in ("home", "tmp", "config", "state", "cache", "data", "runtime", "docker-config", "jobs"):
        (root / name).mkdir(mode=0o700)
    for name in ("home", "tmp", "config", "state", "cache", "runtime"):
        (root / "data" / name).mkdir(mode=0o700)
    return marker


def receive_chunk(root, offset, digest, encoded):
    require(len(encoded) <= (CHUNK * 4 // 3 + 8), "chunk input bound")
    data = base64.b64decode(encoded, validate=True)
    require(0 < len(data) <= CHUNK and hashlib.sha256(data).hexdigest() == digest, "chunk checksum")
    meta = json.loads(read_private(root / "payload-meta"))
    fd = os.open(root / "payload.tar", os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+b") as target:
        info = os.fstat(target.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == int(offset), "chunk offset/file")
        require(int(offset) + len(data) <= meta["size"], "chunk total")
        target.seek(0, os.SEEK_END)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    return {"offset": int(offset) + len(data)}


def extract(root):
    meta = json.loads(read_private(root / "payload-meta"))
    data = read_private(root / "payload.tar", MAX_ARCHIVE)
    require(len(data) == meta["size"], "payload incomplete")
    names = validate_archive(data, meta["commit"], meta["sha256"])
    destination = root / "src"
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        # Never extractall: no links/specials, no ownership/mode restoration.
        for member in archive:
            path = destination / member.name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            safe_directory(path.parent)
            if member.isdir():
                path.mkdir(mode=0o700, exist_ok=True)
            else:
                private_write(path, archive.extractfile(member).read())
                if member.mode & 0o111:
                    path.chmod(0o700)
    # Source-only/offline writable-path evidence; not systemd installation.
    for unit in ("toolstack-admin.service", "toolstack-sps.service"):
        text = (destination / "deploy" / unit).read_text()
        require(all(s in text for s in ("NoNewPrivileges=true", "StateDirectory=toolstack", "LogsDirectory=toolstack")), "unit contract")
    return {"commit": meta["commit"], "sha256": meta["sha256"], "members": len(names)}


def tag_for(run, kind):
    require(kind in KINDS, "image kind")
    return "toolstack-vmproof" + ("" if kind == "onebox" else "-" + kind) + ":" + run


def inspect_image(root, run, kind):
    tag = tag_for(run, kind)
    text = bounded(("docker", "image", "inspect", "--format", '{{.Id}}\t{{json .RepoTags}}\t{{json .Config.Labels}}', tag), root)
    image, tags, labels = text.strip().split("\t")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) and json.loads(tags) == [tag]
            and json.loads(labels).get(LABEL) == run, "image ownership")
    return {"image": image, "tag": tag, "label": run}


def build(root, run, kind):
    tag = tag_for(run, kind)
    # All existing IDs/tags are recorded before any build, and a colliding run tag
    # refuses. No daemon config/ENV inspection and no base-image deletion.
    existing = bounded(("docker", "image", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Repository}}:{{.Tag}}"), root)
    require(not any(row.endswith("\t" + tag) for row in existing.splitlines()), "preexisting run tag")
    private_write(root / ("before-" + kind), existing.encode())
    bounded(("docker", "build", "--quiet", "--label", LABEL + "=" + run,
             "-f", DOCKERFILES[kind], "-t", tag, "."), root / "src", 1200)
    result = inspect_image(root, run, kind)
    require(result["image"] not in {r.split("\t")[0] for r in existing.splitlines()}, "preexisting image id")
    private_write(root / ("image-" + kind), json.dumps(result).encode())
    return result


ONEBOX_CHECK = (
    "import sps,toolstack_forwarder,admin,shutil,pathlib; "
    "assert shutil.which('admin')=='/usr/local/bin/admin'; "
    "assert pathlib.Path('/app/tools/echo_api/toolyard.toml').is_file(); "
    "assert pathlib.Path('/app/tools/echo_mcp/toolyard.toml').is_file(); "
    "from admin import auth,settings; "
    "settings.write_password_hash(auth.hash_password('vm-proof-fake-only')); "
    "settings.rotate_session_secret(); assert settings.read_password_hash() is not None"
)
ECHO_CHECK = "import sps.tool_sdk,pathlib,tomllib; p=pathlib.Path('/app/toolyard.toml'); assert p.is_file(); assert tomllib.loads(p.read_text())['id']"


def create(root, run, kind):
    require(kind in CONTAINER_KINDS, "container kind")
    image_kind = "onebox" if kind in ("serve", "process-sps") else kind
    if kind == "process-sps":
        verify_root(root, run)
        script = root / "src" / PROCESS_FIXTURE
        safe_directory(script.parent)
        read_private(script)  # regular, no-follow, single-link, owned, bounded
        data_info = safe_directory(root / "data")
        require(data_info.st_uid == os.getuid() and stat.S_IMODE(data_info.st_mode) == 0o700, "private data root")
        require(not os.path.lexists(root / "data/process-sps"), "process-SPS root must be absent")
    recorded = json.loads(read_private(root / ("image-" + image_kind)))
    require(inspect_image(root, run, image_kind) == recorded, "recorded image changed")
    argv = ["docker", "create", "--name", "toolstack-" + run + "-" + kind,
            "--label", LABEL + "=" + run, "--restart", "no", "--network", "bridge" if kind == "serve" else "none"]
    if image_kind == "onebox":
        argv += ["--mount", "type=bind,src=" + str(root / "data") + ",dst=/data"]
        for key, value in {"HOME": "/data/home", "TMPDIR": "/data/tmp", "XDG_CONFIG_HOME": "/data/config",
                           "XDG_STATE_HOME": "/data/state", "XDG_CACHE_HOME": "/data/cache", "XDG_DATA_HOME": "/data",
                           "XDG_RUNTIME_DIR": "/data/runtime", "TOOLSTACK_SPS_SKIP": "0" if kind == "process-sps" else "1", "TOOLSTACK_SPS_ENV": "/data/no-sps.env"}.items():
            argv += ["-e", key + "=" + value]
    else:
        for key in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"):
            argv += ["-e", key + "=/tmp"]  # private disposable container filesystem
    if kind == "serve":
        argv += ["-p", "127.0.0.1::8780", recorded["image"]]
    elif kind == "process-sps":
        argv += ["--mount", "type=bind,src=" + str(script) + ",dst=/proof/process_sps.py,readonly",
                 "-e", "PYTHONPATH=/app", "--entrypoint", "python3", recorded["image"],
                 "/proof/process_sps.py", "--root", "/data/process-sps"]
    else:
        argv += ["--entrypoint", "python3", recorded["image"], "-c", ONEBOX_CHECK if kind == "onebox" else ECHO_CHECK]
    cid = bounded(tuple(argv), root).strip()
    require(re.fullmatch(r"[0-9a-f]{64}", cid), "full container id")
    result = {"container": cid, "kind": kind, "label": run}
    private_write(root / ("container-" + kind), json.dumps(result).encode())
    return result


def validate_process_result(result):
    require(isinstance(result, dict) and result.get("status") == "PASS"
            and result.get("cleanup") == "reaped", "process-SPS status/cleanup")
    require(result.get("checks") == list(PROCESS_CHECKS), "process-SPS required checks")
    require(isinstance(result.get("platform"), str) and result["platform"].startswith("Linux-")
            and isinstance(result.get("python"), str) and re.fullmatch(r"3\.[0-9]+\.[0-9]+", result["python"])
            and result.get("cryptography") == "50.0.2", "process-SPS Linux/runtime evidence")
    records = result.get("processes")
    require(isinstance(records, list) and len(records) == 4, "process-SPS process evidence")
    by_label = {}
    for record in records:
        require(isinstance(record, dict) and record.get("label") in ("sps", "sps-restart", "runner spawn", "tool")
                and record["label"] not in by_label and type(record.get("pid")) is int and record["pid"] > 1
                and isinstance(record.get("identity"), str) and bool(record["identity"]), "process-SPS identity")
        by_label[record["label"]] = record
    spawn, tool = by_label["runner spawn"], by_label["tool"]
    require(spawn.get("cleanup") == "reaped and absent" and spawn["pid"] == tool["pid"]
            and spawn["identity"] == tool["identity"] and isinstance(spawn.get("boot"), str)
            and bool(spawn["boot"]) and spawn["boot"] == tool.get("boot")
            and len({r["pid"] for r in records}) == 3, "process-SPS positive process cleanup")
    boots = result.get("boots")
    require(isinstance(boots, list) and len(boots) == 2 and all(isinstance(b, str) and b for b in boots)
            and boots[0] != boots[1], "process-SPS restart evidence")
    return result


def start_container(root, run, kind, cid):
    require(kind in CONTAINER_KINDS and re.fullmatch(r"[0-9a-f]{64}", cid), "container start kind/id")
    recorded = json.loads(read_private(root / ("container-" + kind)))
    require(recorded == {"container": cid, "kind": kind, "label": run}, "container record")
    identity = bounded(("docker", "inspect", "--format", '{{.Id}}\t{{index .Config.Labels "toolstack.vmproof"}}', cid), root).strip()
    require(identity == cid + "\t" + run, "container ownership")
    if kind != "serve":
        output = bounded(("docker", "start", "-a", cid), root, 135 if kind == "process-sps" else 90)
        code = bounded(("docker", "inspect", "--format", "{{.State.ExitCode}}", cid), root).strip()
        require(code == "0", "content/bootstrap assertions failed")
        if kind == "process-sps":
            return {"checked": kind, "exit": 0, "proof": validate_process_result(json.loads(output))}
        return {"checked": kind, "exit": 0}
    cmd = bounded(("docker", "inspect", "--format", "{{json .Config.Cmd}}", cid), root)
    require(json.loads(cmd) == ["/usr/local/bin/admin", "serve", "--port", "8780"], "image actual CMD")
    bounded(("docker", "start", cid), root)
    address = bounded(("docker", "port", cid, "8780/tcp"), root).strip()
    require(re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", address), "loopback publish")
    port = int(address.rsplit(":", 1)[1])
    require(1024 <= port <= 65535, "dynamic port")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with opener.open("http://" + address + "/login", timeout=2) as response:
                require(response.status == 200 and b"password" in response.read(65536).lower(), "admin login response")
                return {"checked": "serve", "port": port, "http": 200, "cmd": json.loads(cmd)}
        except OSError:
            time.sleep(1)
    raise ValueError("admin readiness deadline")


INVENTORY_GIT = {
    "git-root": ("root", ("rev-parse", "--show-toplevel")),
    "git-head": ("head", ("rev-parse", "HEAD")),
    "git-branch": ("branch", ("rev-parse", "--abbrev-ref", "HEAD")),
    "git-status": ("status", ("status", "--porcelain=v1", "-uall")),
    "git-submodules": ("submodules", ("submodule", "status")),
}
INVENTORY_STEPS = ("serviceprops", "serviceprops-sps", "statowner", *INVENTORY_GIT)
INVENTORY_REASONS = ("command-failed", "invalid-metadata", "owner-unknown", "unsafe-directory", "transport-unknown")


def inventory_path(value):
    return (isinstance(value, str) and len(value) <= 1024 and value.startswith("/")
            and value != "/" and all(p not in ("", ".", "..") for p in value[1:].split("/"))
            and all(32 <= ord(c) < 127 for c in value) and "\\" not in value)


def inventory_owner(value):
    return isinstance(value, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value) is not None


def inventory_error(value):
    """Strict wire schema: never forward arbitrary exception text or extra fields."""
    return (isinstance(value, dict) and set(value) == {"error", "step", "reason", "metadata"}
            and value["error"] == "inventory-failed" and value["step"] in INVENTORY_STEPS
            and value["reason"] in INVENTORY_REASONS and isinstance(value["metadata"], dict)
            and set(value["metadata"]) <= {"path", "owner"}
            and all((inventory_path(v) if k == "path" else inventory_owner(v))
                    for k, v in value["metadata"].items()))


class InventoryFailure(ValueError):
    def __init__(self, step, reason, result):
        self.envelope = {"error": "inventory-failed", "step": step, "reason": reason,
                         "metadata": {k: v for k, v in result.items() if
                                      (k == "path" and inventory_path(v)) or
                                      (k == "owner" and inventory_owner(v))}}
        super().__init__("inventory-failed")


def service_properties(text):
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in {"User", "Group", "WorkingDirectory"} and key not in fields,
                "service properties")
        fields[key] = value
    require(set(fields) == {"User", "Group", "WorkingDirectory"}, "service properties")
    return fields


def inventory_directory_identity(info):
    require(stat.S_ISDIR(info.st_mode), "ordinary directory")
    return dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                dev=info.st_dev, ino=info.st_ino)


def inventory(checkout, step=None, result=None):
    # The controller checkpoints before EACH fixed step. The single-call form is
    # for local fake-boundary tests only, not the live driver's admission sequence.
    if step is None:
        result = {}
        for stage in INVENTORY_STEPS:
            result = inventory(checkout, stage, result)
        return result
    require(step in INVENTORY_STEPS and isinstance(result, dict), "inventory step")
    result = dict(result)
    reason = "invalid-metadata"
    try:
        if step in ("serviceprops", "serviceprops-sps"):
            unit = "toolstack-admin.service" if step == "serviceprops" else "toolstack-sps.service"
            reason = "command-failed"
            try:
                text = bounded(("systemctl", "show", "-p", "User,Group,WorkingDirectory", unit), Path("/"), 5)
            except Exception:
                if step == "serviceprops-sps":
                    result["sps"] = {"state": "unknown-or-absent"}
                    return result
                raise
            reason = "invalid-metadata"
            props = service_properties(text)
            if step == "serviceprops-sps":
                result["sps"] = {"state": "unknown-or-absent"}
                if inventory_path(props["WorkingDirectory"]) and inventory_owner(props["User"]):
                    require(not props["Group"] or inventory_owner(props["Group"]), "group")
                    result["sps"] = dict(props, state="known")
                return result
            require(inventory_path(props["WorkingDirectory"]), "admin directory")
            require(not props["User"] or inventory_owner(props["User"]), "admin user")
            require(not props["Group"] or inventory_owner(props["Group"]), "admin group")
            result.update(path=props["WorkingDirectory"], service=props)
            require(checkout == "discover" or checkout == result["path"], "explicit checkout mismatch")
            return result
        require(inventory_path(result.get("path")), "identity")
        path = Path(result["path"])
        if step == "statowner":
            reason = "unsafe-directory"
            identity = inventory_directory_identity(safe_directory(path))
            reason = "owner-unknown"
            require(identity["uid"] > 0, "nonroot owner")
            account = pwd.getpwuid(identity["uid"])
            group = grp.getgrgid(identity["gid"])
            owner = account.pw_name
            require(inventory_owner(owner) and inventory_owner(group.gr_name), "known owner/group")
            require(account.pw_uid == identity["uid"] and pwd.getpwnam(owner).pw_uid == identity["uid"]
                    and group.gr_gid == identity["gid"] and grp.getgrnam(group.gr_name).gr_gid == identity["gid"],
                    "owner/group resolution mismatch")
            result.update(owner=owner, group=group.gr_name)
            reason = "command-failed"
            text = bounded(("stat", "-c", "%U:%G %a %n", "--", str(path)), Path("/"), 5).strip()
            reason = "invalid-metadata"
            expected = f"{owner}:{group.gr_name} {identity['mode']:o} {path}"
            require(text == expected, "stat identity mismatch")
            reason = "unsafe-directory"
            require(inventory_directory_identity(safe_directory(path)) == identity, "directory changed")
            result.update(identity)
            return result
        require(inventory_owner(result.get("owner")), "owner")
        owner = result["owner"]
        reason = "unsafe-directory"
        identity = inventory_directory_identity(safe_directory(path))
        require(identity == {key: result[key] for key in identity}, "directory changed")
        reason = "command-failed"
        key, args = INVENTORY_GIT[step]
        text = bounded(("sudo", "-n", "-u", owner, "--", "git", "--no-optional-locks",
                        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                        "-C", str(path), *args), Path("/"), 5)
        reason = "invalid-metadata"
        if key == "head":
            require(re.fullmatch(r"[0-9a-f]{40}", text.strip()), "head")
        if key == "root":
            require(text.strip() == str(path), "root mismatch")
        result[key] = text
        return result
    except Exception:
        raise InventoryFailure(step, reason, result) from None


def cleanup_mount(fd):
    # st_dev alone misses same-device bind mounts. Unknown is a refusal.
    text = Path('/proc/self/fdinfo/' + str(fd)).read_text()
    values = [line.split()[1] for line in text.splitlines() if line.startswith('mnt_id:')]
    require(len(values) == 1 and values[0].isdigit(), 'unknown mount identity')
    return values[0]


def cleanup_root(root, run, dev, ino, *, remove=False):
    """Cleanup-only metadata walk and fd-relative removal; never read source data."""
    allowed = {'owner', 'payload-meta', 'payload.tar', 'src', 'home', 'tmp', 'config',
               'state', 'cache', 'data', 'runtime', 'docker-config', 'jobs'}
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    rootfd = None
    owner = None
    try:
        for part in root.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        rootfd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(rootfd)
        require((info.st_dev, info.st_ino) == (dev, ino) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'cleanup root identity')
        mount = cleanup_mount(rootfd)
        require(cleanup_mount(parent) == mount, 'mounted cleanup root')
        def identity(info):
            base = (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink)
            return base + ((info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                           if stat.S_ISREG(info.st_mode) else ())
        root_identity = identity(info)
        def same(fd, name, expected):
            require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == expected,
                    'cleanup entry changed')
        owner = os.open('owner', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rootfd)
        oi = os.fstat(owner)
        require(stat.S_ISREG(oi.st_mode) and oi.st_uid == os.getuid() and oi.st_nlink == 1
                and stat.S_IMODE(oi.st_mode) == 0o600 and oi.st_dev == dev
                and cleanup_mount(owner) == mount, 'cleanup owner file')
        marker = json.loads(os.read(owner, 4097))
        require(marker == {'run': run, 'dev': dev, 'ino': ino}, 'cleanup owner marker')
        owner_identity = identity(oi)
        def marker_still_owned():
            require(identity(os.fstat(owner)) == owner_identity, 'cleanup owner changed')
            same(rootfd, 'owner', owner_identity)
        marker_still_owned()
        count = [0]
        def scan(fd, depth=0):
            require(depth < 64, 'cleanup depth bound')
            names = set(os.listdir(fd))
            if depth == 0:
                require(names == allowed, 'cleanup top entries')
            tree = {}
            for name in sorted(names):
                count[0] += 1
                require(count[0] <= 100000, 'cleanup entry bound')
                si = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(si.st_uid == os.getuid() and si.st_dev == dev
                        and (stat.S_ISDIR(si.st_mode) or stat.S_ISREG(si.st_mode)),
                        'foreign/special cleanup entry')
                require(stat.S_ISDIR(si.st_mode) or si.st_nlink == 1, 'hardlinked cleanup file')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if stat.S_ISDIR(si.st_mode):
                    flags |= os.O_DIRECTORY
                entry = os.open(name, flags, dir_fd=fd)
                try:
                    require(identity(os.fstat(entry)) == identity(si) and cleanup_mount(entry) == mount,
                            'cleanup entry identity/mount')
                    subtree = scan(entry, depth + 1) if stat.S_ISDIR(si.st_mode) else None
                    same(fd, name, identity(si))
                    tree[name] = (identity(si), subtree)
                finally:
                    os.close(entry)
            require(set(os.listdir(fd)) == names, 'cleanup entries changed')
            return tree
        tree = scan(rootfd)
        marker_still_owned()
        def erase(fd, tree, top=False):
            require(set(os.listdir(fd)) == set(tree), 'cleanup entries changed')
            names = [name for name in tree if name != 'owner'] + ['owner'] if top else list(tree)
            for name in names:
                expected, subtree = tree[name]
                marker_still_owned()
                same(fd, name, expected)
                if subtree is None:
                    os.unlink(name, dir_fd=fd)
                else:
                    entry = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        require(identity(os.fstat(entry)) == expected and cleanup_mount(entry) == mount,
                                'cleanup directory changed')
                        erase(entry, subtree)
                        # Directory link count changes as its children are removed.
                        current = os.fstat(entry)
                        require(identity(current)[:4] == expected[:4], 'cleanup directory changed')
                        same(fd, name, identity(current))
                        marker_still_owned()
                        os.rmdir(name, dir_fd=fd)
                    finally:
                        os.close(entry)
        same(parent, root.name, root_identity)
        if remove:
            erase(rootfd, tree, top=True)
            current = os.fstat(rootfd)
            require(identity(current)[:4] == root_identity[:4], 'cleanup root changed')
            same(parent, root.name, identity(current))
            os.rmdir(root.name, dir_fd=parent)
            return {'removed': str(root)}
        return marker
    finally:
        if owner is not None:
            os.close(owner)
        if rootfd is not None:
            os.close(rootfd)
        os.close(parent)


def dispatch(run, action, args, stdin):
    global CURRENT_JOB
    root = root_for(run)
    if action in ('cleanup-check', 'cleanup-remove'):
        require(len(args) == 2, 'cleanup identity arguments')
        return cleanup_root(root, run, int(args[0]), int(args[1]), remove=action == 'cleanup-remove')
    if action == "inventory":
        require(len(args) == 3, "inventory arguments")
        return inventory(args[0], args[1], json.loads(args[2]))
    if action == "init":
        require(len(args) == 3, "init arguments")
        return initialize(root, run, *args)
    marker = verify_root(root, run)
    if action == "chunk":
        require(len(args) == 2, "chunk arguments")
        return receive_chunk(root, *args, stdin)
    if action == "extract":
        require(not args, "extract arguments")
        return extract(root)
    if action == "identity":
        require(len(args) == 2 and re.fullmatch(r"build-(onebox|echo-api|echo-mcp)|(create|start)-(onebox|echo-api|echo-mcp|serve|process-sps)", args[0]), "job identity args")
        path = root / "jobs" / args[0]
        if not path.exists():
            return {"pending": True}
        record = json.loads(read_private(path))
        require(record["pid"] == int(args[1]), "QGA job PID mismatch")
        return record
    if action == "remove":
        require(len(args) == 2 and marker["dev"] == int(args[0]) and marker["ino"] == int(args[1]), "remove root identity")
        require(shutil.rmtree.avoids_symlink_attacks, "safe removal unavailable")
        shutil.rmtree(root)
        return {"removed": str(root)}
    require(action in ("build", "create", "start") and args
            and args[0] in (KINDS if action == "build" else CONTAINER_KINDS), "fixed guest action")
    job = action + "-" + args[0]
    # An absent-only job identity is the retry barrier and survives fast exit.
    private_write(root / "jobs" / job, json.dumps(process_identity(os.getpid())).encode())
    CURRENT_JOB = job
    if action == "build":
        require(len(args) == 1 and args[0] in KINDS, "build arguments")
        return build(root, run, args[0])
    if action == "create":
        require(len(args) == 1, "create arguments")
        return create(root, run, args[0])
    require(len(args) == 2 and re.fullmatch(r"[0-9a-f]{64}", args[1]), "start arguments")
    return start_container(root, run, args[0], args[1])


def guest_main():
    os.umask(0o077)
    try:
        run, action, *args = sys.argv[1:]
        # Bounded stdin only for chunks; never eval/exec input or source content.
        stdin = sys.stdin.buffer.read(CHUNK * 4 // 3 + 9) if action == "chunk" else b""
        print(json.dumps(dispatch(run, action, args, stdin)))
    except InventoryFailure as failure:
        print(json.dumps(failure.envelope))
        return 1
    except Exception:
        # No exception text: subprocess/config errors might contain credentials.
        print('{"error":"guest-proof-failed"}')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(guest_main())
