"""Human reviewed advice and reversible holding inside a user owned project.

This is a file relocation aid, not malware containment. Stop project writers before
holding/restoring; concurrent mutation by another process using this account is
outside this helper's trust boundary. Windows locks guard ancestor replacement;
POSIX moves use no-follow directory descriptors.
Windows requires a private ACL-protected project and holding directory. Owner
checks do not verify DACL write grants. Shared writable roots are unsupported;
writers with project access are outside the integrity guarantee.
"""
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .models import Run, utc_now
from .store import Store

MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024


@lru_cache(maxsize=1)
def _winapi():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [pointer]
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  pointer, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD]
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, pointer]
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, pointer]
    security.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                             pointer, pointer, pointer, pointer, pointer]
    security.ConvertSidToStringSidW.argtypes = [pointer, pointer]
    return kernel, security


def _sid_string(sid) -> str:
    kernel, security = _winapi()
    output = wintypes.LPWSTR()
    if not security.ConvertSidToStringSidW(sid, ctypes.byref(output)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return output.value
    finally:
        kernel.LocalFree(ctypes.cast(output, ctypes.c_void_p))


def _current_owner() -> str:
    if os.name != "nt":
        return str(os.geteuid())
    kernel, security = _winapi()
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        length = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        return _sid_string(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        kernel.CloseHandle(token)


def _owner(path: Path) -> str:
    if os.name != "nt":
        return str(path.lstat().st_uid)
    kernel, security = _winapi()
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    code = security.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(owner),
                                          None, None, None, ctypes.byref(descriptor))
    if code:
        raise ctypes.WinError(code)
    try:
        return _sid_string(owner)
    finally:
        kernel.LocalFree(descriptor)


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _absolute(path: Path) -> Path:
    path = Path(path)
    if ".." in path.parts:
        raise ValueError("Parent traversal is forbidden")
    if os.name == "nt" and (str(path).startswith("\\\\") or any(":" in part for part in path.parts[1:])):
        raise ValueError("Network paths and alternate data streams are forbidden")
    return Path(os.path.abspath(path))


def _owned(path: Path):
    if _reparse(path) or _owner(path) != _current_owner():
        raise ValueError("Path is redirected or not owned by the current user")
    if os.name != "nt" and path.lstat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Project response paths must not be writable by other users")


def _win_open(path: Path, access: int = 0, share: int = 3):
    kernel, _ = _winapi()
    handle = kernel.CreateFileW(str(path), access, share, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = (wintypes.DWORD * 2)()
    if not kernel.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)):
        kernel.CloseHandle(handle)
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes[0] & 0x400:
        kernel.CloseHandle(handle)
        raise ValueError("Reparse paths are forbidden")
    return handle


@contextmanager
def _locked_dirs(root: Path, *directories: Path):
    """Hold existing ancestor handles; never follow symlinks during the walk."""
    paths = {root, *root.parents}
    for directory in directories:
        if directory != root and root not in directory.parents:
            raise ValueError("Directory is outside the project root")
        paths.update((directory, *directory.parents))
    descriptors = {}
    with ExitStack() as stack:
        for path in sorted(paths, key=lambda item: len(item.parts)):
            if _reparse(path) or not path.is_dir():
                raise ValueError("Project ancestors must be real directories")
            if os.name == "nt":
                handle = _win_open(path)
                stack.callback(_winapi()[0].CloseHandle, handle)
            else:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                descriptor = os.open(str(path) if path == path.parent else path.name, flags,
                                     dir_fd=descriptors.get(path.parent))
                descriptors[path] = descriptor
                stack.callback(os.close, descriptor)
            if path == root or root in path.parents:
                _owned(path)
        yield descriptors


@contextmanager
def _file(path: Path, descriptors: dict, movable: bool = False):
    _owned(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Only regular files may be used in project responses")
    if os.name == "nt":
        import msvcrt
        handle = _win_open(path, 0x80000000 | (0x10000 if movable else 0), 1)
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            _winapi()[0].CloseHandle(handle)
            raise
    else:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptors[path.parent])
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Only regular files without additional hard links can be held")
        yield stream


def _digest(stream) -> str:
    before = os.fstat(stream.fileno())
    if before.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact exceeds the 1 GiB holding limit")
    digest = hashlib.sha256()
    total = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        total += len(block)
        if total > MAX_ARTIFACT_BYTES:
            raise ValueError("Artifact exceeds the holding limit")
        digest.update(block)
    after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Artifact changed during digest verification")
    return digest.hexdigest()


def _move(stream, source: Path, destination: Path, descriptors: dict):
    if os.path.lexists(destination):
        raise ValueError("Destination already exists")
    if os.name == "nt":
        import msvcrt

        class RenameInfo(ctypes.Structure):
            _fields_ = [("replace", wintypes.DWORD), ("root", wintypes.HANDLE),
                        ("length", wintypes.DWORD), ("name", wintypes.WCHAR * 1)]

        encoded = str(destination).encode("utf-16-le")
        buffer = ctypes.create_string_buffer(RenameInfo.name.offset + len(encoded) + 2)
        info = RenameInfo.from_buffer(buffer)
        info.replace, info.root, info.length = 0, None, len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.name.offset, encoded, len(encoded))
        if not _winapi()[0].SetFileInformationByHandle(
            msvcrt.get_osfhandle(stream.fileno()), 3, buffer, len(buffer)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        source_fd, destination_fd = descriptors[source.parent], descriptors[destination.parent]
        identity = os.fstat(stream.fileno())
        current = os.stat(source.name, dir_fd=source_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError("Source identity changed")
        os.link(source.name, destination.name, src_dir_fd=source_fd,
                dst_dir_fd=destination_fd, follow_symlinks=False)
        linked = os.stat(destination.name, dir_fd=destination_fd, follow_symlinks=False)
        if (linked.st_dev, linked.st_ino) != (identity.st_dev, identity.st_ino):
            os.unlink(destination.name, dir_fd=destination_fd)
            raise ValueError("Source identity changed during relocation")
        os.unlink(source.name, dir_fd=source_fd)


def _root(root: Path) -> Path:
    root = _absolute(root)
    if root == Path(root.anchor) or not root.is_dir():
        raise ValueError("Select an existing project directory below a filesystem root")
    return root


def _project_file(root: Path, artifact: Path) -> Path:
    artifact = Path(artifact)
    artifact = _absolute(artifact if artifact.is_absolute() else root / artifact)
    if root not in artifact.parents or ".vulntrail-hold" in artifact.relative_to(root).parts:
        raise ValueError("Artifact must be outside holding metadata and strictly below the project root")
    return artifact


def _approval(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Approval must be an exact lowercase SHA256 digest")
    return value


def _identity(root: Path) -> dict:
    info = root.stat()
    return {"root": str(root), "owner": _current_owner(), "device": info.st_dev, "inode": info.st_ino}


def _mkdir(path: Path, descriptors: dict):
    if os.name == "nt":
        path.mkdir(mode=0o700)
    else:
        os.mkdir(path.name, mode=0o700, dir_fd=descriptors[path.parent])


def _create(path: Path, descriptors: dict):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path if os.name == "nt" else path.name, flags, mode=0o600,
                   **({} if os.name == "nt" else {"dir_fd": descriptors[path.parent]}))


def _unlink(path: Path, descriptors: dict):
    if os.name == "nt":
        path.unlink()
    else:
        os.unlink(path.name, dir_fd=descriptors[path.parent])


def _write_json(path: Path, value: dict, descriptors: dict, initial: bool = False):
    temporary = path if initial else path.with_name(str(uuid.uuid4()) + ".json")
    with os.fdopen(_create(temporary, descriptors), "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    if not initial:
        if os.name == "nt":
            os.replace(temporary, path)
        else:
            descriptor = descriptors[path.parent]
            os.replace(temporary.name, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)


def _read_json(path: Path, descriptors: dict) -> dict:
    with _file(path, descriptors) as stream:
        content = stream.read(65537)
    if len(content) > 65536:
        raise ValueError("Holding metadata exceeds its size limit")
    try:
        value = json.loads(content)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid holding metadata") from error
    if not isinstance(value, dict):
        raise ValueError("Holding metadata must be an object")
    return value


@contextmanager
def _holding(root: Path, descriptors: dict, create: bool = False):
    directory = root / ".vulntrail-hold"
    created = not os.path.lexists(directory)
    if created:
        if not create:
            raise ValueError("No holding records exist for this project")
        _mkdir(directory, descriptors)
    with _locked_dirs(root, directory) as holding_descriptors:
        combined = {**descriptors, **holding_descriptors}
        marker = directory / "owner.json"
        identity = _identity(root)
        if created:
            _write_json(marker, identity, combined, initial=True)
        elif not marker.is_file() or _read_json(marker, combined) != identity:
            raise ValueError("Holding directory ownership cannot be proven")
        yield directory, combined


@contextmanager
def _operation_lock(directory: Path, descriptors: dict):
    path = directory / ".operation.lock"
    try:
        descriptor = _create(path, descriptors)
    except FileExistsError as error:
        raise ValueError("A response operation is busy or has an unrecovered lock") from error
    identity = os.fstat(descriptor)
    os.close(descriptor)
    try:
        yield
    finally:
        current = path.lstat()
        if _reparse(path) or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError("Response lock identity changed")
        _unlink(path, descriptors)


def _summary(record: dict) -> dict:
    return {key: record[key] for key in ("hold_id", "relative_path", "sha256", "status")}


def hold_artifact(root: Path, artifact: Path, approved_sha256: str, store: Store) -> dict:
    root, approved_sha256 = _root(root), _approval(approved_sha256)
    artifact = _project_file(root, artifact)
    with _locked_dirs(root, artifact.parent) as descriptors:
        with _file(artifact, descriptors, movable=True) as stream:
            if _digest(stream) != approved_sha256:
                raise ValueError("Artifact digest does not match the individual approval")
            with _holding(root, descriptors, create=True) as (directory, holding_descriptors):
                with _operation_lock(directory, holding_descriptors):
                    hold_id = str(uuid.uuid4())
                    stage = directory / hold_id
                    _mkdir(stage, holding_descriptors)
                    with _locked_dirs(root, stage) as stage_descriptors:
                        combined = {**holding_descriptors, **stage_descriptors}
                        record = {"root_identity": _identity(root), "hold_id": hold_id,
                                  "relative_path": artifact.relative_to(root).as_posix(),
                                  "sha256": approved_sha256, "status": "prepared",
                                  "created_at": utc_now(), "restored_at": None}
                        manifest = stage / "manifest.json"
                        _write_json(manifest, record, combined, initial=True)
                        store.audit("artifact_hold_requested", _summary(record))
                        _move(stream, artifact, stage / "artifact", combined)
                        record["status"] = "held"
                        _write_json(manifest, record, combined)
                        store.audit("artifact_held", _summary(record))
                        return _summary(record)


def restore_artifact(root: Path, hold_id: str, approved_sha256: str, store: Store) -> dict:
    root, approved_sha256 = _root(root), _approval(approved_sha256)
    if not isinstance(hold_id, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", hold_id
    ):
        raise ValueError("Invalid holding identifier")
    with _locked_dirs(root) as descriptors:
        with _holding(root, descriptors) as (directory, holding_descriptors):
            with _operation_lock(directory, holding_descriptors):
                stage = directory / hold_id
                with _locked_dirs(root, stage) as stage_descriptors:
                    combined = {**holding_descriptors, **stage_descriptors}
                    manifest = stage / "manifest.json"
                    record = _read_json(manifest, combined)
                    if (record.get("root_identity") != _identity(root) or record.get("hold_id") != hold_id
                            or record.get("sha256") != approved_sha256
                            or record.get("status") not in ("held", "prepared")):
                        raise ValueError("Holding record differs from the selected project and approval")
                    if not isinstance(record.get("relative_path"), str):
                        raise ValueError("Invalid restoration path")
                    destination = _project_file(root, Path(record["relative_path"]))
                    with _locked_dirs(root, destination.parent) as destination_descriptors:
                        combined.update(destination_descriptors)
                        with _file(stage / "artifact", combined, movable=True) as stream:
                            if _digest(stream) != approved_sha256:
                                raise ValueError("Held artifact digest differs from the approval")
                            store.audit("artifact_restore_requested", _summary(record))
                            _move(stream, stage / "artifact", destination, combined)
                            record.update(status="restored", restored_at=utc_now())
                            _write_json(manifest, record, combined)
                            store.audit("artifact_restored", _summary(record))
                            return _summary(record)


def plan_response(run: Run) -> dict:
    run = Run.from_dict(run.to_dict())
    actions = []
    for finding in sorted(run.findings, key=lambda item: (item.priority, item.fingerprint)):
        advice = (
            f"Review the publisher's advisory and dependency constraints, then consider upgrading "
            f"{finding.package} from {finding.version} to a supported release containing the "
            f"reported fix ({finding.fixed_version})."
            if finding.fixed_version else
            f"Review the publisher's advisory for {finding.package} {finding.version}; "
            "the imported evidence supplies no fixed version. Assess a supported update or "
            "temporary project isolation with its owner."
        )
        actions.append({
            "fingerprint": finding.fingerprint, "vulnerability_id": finding.vulnerability_id,
            "package": finding.package, "priority": finding.priority, "advice": advice,
            "verification": "Verify the upgrade with the project's tests, record the deployed "
                            "version, and rescan with comparable coverage and current advisory data.",
            "references": list(finding.urls),
        })
    return {
        "run_id": run.id, "target": run.target, "actions": actions,
        "limitations": f"This {run.status} scan does not establish exploitability or security. "
                       "Review coverage, advisory-data freshness and findings with the project owner. "
                       "Holding a project file can break dependent applications; restoration requires "
                       "the same individually approved digest.",
        "warnings": list(run.warnings),
    }
