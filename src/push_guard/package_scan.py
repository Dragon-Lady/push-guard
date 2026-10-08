"""Bounded, read-only inspection of built Python distributions."""

from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .guard import (
    PushGuardInspectionError,
    SecretFinding,
    _scan_line_for_blocked_terms,
    load_blocked_terms,
    load_explicit_blocked_terms,
    load_private_path_patterns,
    path_matches_private,
    scan_text_for_secrets,
)


MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


def scan_distribution(
    archive: str | Path,
    repo: str | Path = ".",
    *,
    require_explicit_terms: bool = False,
    privacy_only: bool = False,
) -> list[SecretFinding]:
    """Scan sdist/wheel payloads without extracting files or making network calls.

    Text and member paths are inspected. Binary payloads are not decoded; their
    names, sizes, and archive types are still checked. Oversized or malformed
    archives fail closed, as do missing private terms when explicitly required.
    """
    explicit_terms = load_explicit_blocked_terms(repo)
    if require_explicit_terms and not explicit_terms:
        raise PushGuardInspectionError(
            "private blocked terms are required for this release scan"
        )
    terms = load_blocked_terms(repo)
    private_paths = load_private_path_patterns(repo)
    archive_path = Path(archive)
    findings: list[SecretFinding] = []
    seen: set[str] = set()
    total_bytes = 0

    def inspect_name(name: str) -> str:
        normalized = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or normalized.is_absolute()
            or ".." in normalized.parts
            or name in seen
        ):
            raise PushGuardInspectionError("unsafe or duplicate distribution member")
        seen.add(name)
        if len(seen) > MAX_MEMBERS:
            raise PushGuardInspectionError("distribution has too many members")
        path_hits = _scan_line_for_blocked_terms(name, name, 0, terms)
        safe_name = "<redacted member>" if path_hits else name
        if path_hits:
            findings.append(SecretFinding(
                "personal.blocked_term", safe_name, 0,
                "Local identity or private blocked term in distribution path", "<redacted>",
            ))
        if path_matches_private(name, private_paths):
            findings.append(SecretFinding(
                "private_path.match", safe_name, 0,
                "Private/internal path in distribution", "<redacted>",
            ))
        return safe_name

    def inspect(name: str, declared_size: int, stream: BinaryIO) -> None:
        nonlocal total_bytes
        safe_name = inspect_name(name)
        if declared_size < 0 or declared_size > MAX_MEMBER_BYTES:
            raise PushGuardInspectionError("distribution member exceeds scan limit")
        total_bytes += declared_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise PushGuardInspectionError("distribution exceeds total scan limit")

        data = stream.read(declared_size + 1)
        if len(data) != declared_size:
            raise PushGuardInspectionError("distribution member size mismatch")
        if b"\0" in data[:4096]:
            return
        text = data.decode("utf-8-sig", errors="replace")
        if not privacy_only:
            findings.extend(scan_text_for_secrets(text, path=safe_name))
        for line_number, line in enumerate(text.splitlines(), start=1):
            findings.extend(_scan_line_for_blocked_terms(
                line, safe_name, line_number, terms
            ))

    try:
        if archive_path.name.endswith(".whl"):
            with zipfile.ZipFile(archive_path) as package:
                for member in package.infolist():
                    if member.is_dir():
                        inspect_name(member.filename)
                        continue
                    mode = member.external_attr >> 16
                    if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                        raise PushGuardInspectionError("non-regular distribution member")
                    with package.open(member) as stream:
                        inspect(member.filename, member.file_size, stream)
        elif archive_path.name.endswith(".tar.gz"):
            with tarfile.open(archive_path, mode="r:gz") as package:
                for member in package:
                    if member.isdir():
                        inspect_name(member.name)
                        continue
                    if not member.isfile():
                        raise PushGuardInspectionError("non-regular distribution member")
                    stream = package.extractfile(member)
                    if stream is None:
                        raise PushGuardInspectionError("unreadable distribution member")
                    with stream:
                        inspect(member.name, member.size, stream)
        else:
            raise PushGuardInspectionError("expected a wheel or .tar.gz source archive")
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        if isinstance(exc, PushGuardInspectionError):
            raise
        raise PushGuardInspectionError("could not inspect distribution archive") from exc
    return list(dict.fromkeys(findings))
