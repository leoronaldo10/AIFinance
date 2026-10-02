#!/usr/bin/env python3
"""Extract a release with fixed runtime-readable modes (Python 3.6+).

Install this reviewed helper beside release.sh, outside uploaded releases. Never
apply archive owners, timestamps, ACLs, or permission bits other than executable.
"""
import collections
import os
import shutil
import signal
import stat
import sys
import tarfile


MAX_BYTES = 2 * 1024 ** 3
MAX_MEMBERS = 200000
DISK_RESERVE = 1024 ** 3
MAX_HEADER_BYTES = 64 * 1024
MAX_METADATA_BYTES = 16 * 1024 ** 2
MAX_ADDRESS_SPACE = 128 * 1024 ** 2
CPU_SOFT_SECONDS = 30
CPU_HARD_SECONDS = 35


class ResourceLimitError(Exception):
    pass


def enforce_resource_limits():
    """Called only by the extractor process, before parsing any upload bytes."""
    try:
        import resource

        def lower_limit(kind, soft, hard):
            previous_soft, previous_hard = resource.getrlimit(kind)
            if previous_soft != resource.RLIM_INFINITY:
                soft = min(soft, previous_soft)
            if previous_hard != resource.RLIM_INFINITY:
                hard = min(hard, previous_hard)
            resource.setrlimit(kind, (min(soft, hard), hard))

        def cpu_exceeded(signum, frame):
            raise ResourceLimitError('Extraction CPU limit exceeded')

        signal.signal(signal.SIGXCPU, cpu_exceeded)
        lower_limit(resource.RLIMIT_CORE, 0, 0)
        lower_limit(resource.RLIMIT_AS, MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE)
        lower_limit(resource.RLIMIT_CPU, CPU_SOFT_SECONDS, CPU_HARD_SECONDS)
        lower_limit(resource.RLIMIT_FSIZE, MAX_BYTES, MAX_BYTES)
    except (ImportError, AttributeError, ValueError, OSError):
        raise ResourceLimitError('Required extraction resource limits are unavailable')


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # tarfile processes PAX/GNU headers BEFORE yielding a member. Check their
        # claimed size here, before its read/decode can allocate that much memory.
        archive.release_header_count = getattr(archive, 'release_header_count', 0) + 1
        if archive.release_header_count > MAX_MEMBERS * 2 + 128:
            raise ResourceLimitError('Too many archive headers')
        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                         tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            if self.size < 0 or self.size > MAX_HEADER_BYTES:
                raise ResourceLimitError('Archive extension header exceeds metadata limit')
            archive.release_metadata_bytes = getattr(archive, 'release_metadata_bytes', 0) + self.size
            if archive.release_metadata_bytes > MAX_METADATA_BYTES:
                raise ResourceLimitError('Archive metadata total exceeds limit')
        return super(BoundedTarInfo, self)._proc_member(archive)

    def _reject_sparse(self, *args):
        raise ValueError('Unsafe archive type: sparse file')

    _proc_sparse = _reject_sparse
    _proc_gnusparse_00 = _reject_sparse
    _proc_gnusparse_01 = _reject_sparse
    _proc_gnusparse_10 = _reject_sparse


def member_path(name):
    if not name or name.startswith('/') or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe archive path')
    parts = name.split('/')
    if '..' in parts:
        raise ValueError('Unsafe archive path')
    return '/'.join(part for part in parts if part not in ('', '.'))


def validate_link(name, target, entries):
    # Resolve against the complete archive tree, including chains and .. AFTER
    # symlink expansion. normpath/realpath before extraction cannot do this safely.
    pending = collections.deque(name.split('/')[:-1] + target.split('/'))
    resolved = []
    followed = 0
    while pending:
        part = pending.popleft()
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('Unsafe archive link: escapes release')
            resolved.pop()
            continue
        resolved.append(part)
        entry = entries.get('/'.join(resolved))
        if entry is None:
            raise ValueError('Unsafe archive link: missing target')
        kind, member = entry
        if kind == 'link':
            followed += 1
            if followed > 40:
                raise ValueError('Unsafe archive link: cycle or excessive chain')
            resolved.pop()
            pending.extendleft(reversed(member.linkname.split('/')))
        elif kind != 'dir' and pending:
            raise ValueError('Unsafe archive link: non-directory ancestor')


def extract_release(archive, destination):
    destination = os.path.abspath(destination)
    if not stat.S_ISDIR(os.lstat(destination).st_mode) or os.listdir(destination):
        raise ValueError('Extraction requires an empty, real staging directory')
    # Keep partially extracted content private; expose it only after completion.
    os.chmod(destination, 0o700)
    with tarfile.open(archive, 'r:gz', tarinfo=BoundedTarInfo) as source:
        entries = {'': ('dir', None)}
        explicit = set()
        size = 0
        for index, member in enumerate(source):
            if index >= MAX_MEMBERS:
                raise ValueError('Too many archive members')
            name = member_path(member.name)
            if member.isdir():
                kind = 'dir'
            elif member.isfile() and not member.issparse():
                kind = 'file'
            elif member.issym():
                kind = 'link'
                target = member.linkname
                if not target or target.startswith('/') or '\\' in target or '\x00' in target:
                    raise ValueError('Unsafe archive link')
            else:
                raise ValueError('Unsafe archive type')
            if not name and kind != 'dir':
                raise ValueError('Unsafe archive root')
            if name in explicit or (name in entries and (kind != 'dir' or entries[name][0] != 'dir')):
                raise ValueError('Duplicate or conflicting archive path')
            explicit.add(name)
            entries[name] = (kind, member)
            parts = name.split('/')
            for depth in range(1, len(parts)):
                parent = '/'.join(parts[:depth])
                if parent in entries and entries[parent][0] != 'dir':
                    raise ValueError('Unsafe archive path: non-directory ancestor')
                entries.setdefault(parent, ('dir', None))
            if member.size < 0:
                raise ValueError('Invalid archive member size')
            size += member.size
            if size > MAX_BYTES:
                raise ValueError('Oversized release')
        if shutil.disk_usage(destination).free < size + DISK_RESERVE:
            raise ValueError('Insufficient disk reserve')
        for name, (kind, member) in entries.items():
            if kind == 'link':
                validate_link(name, member.linkname, entries)

        # No writes occur until ALL members and link chains have been validated.
        directories = sorted(name for name, (kind, _) in entries.items() if name and kind == 'dir')
        for name in directories:
            target = os.path.join(destination, name)
            os.mkdir(target, 0o700)
            os.chmod(target, 0o755)
        for name, (kind, member) in entries.items():
            if kind != 'file':
                continue
            target = os.path.join(destination, name)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as output, source.extractfile(member) as data:
                shutil.copyfileobj(data, output, length=64 * 1024)
                os.fchmod(output.fileno(), 0o755 if member.mode & 0o111 else 0o644)
        for name, (kind, member) in entries.items():
            if kind == 'link':
                os.symlink(member.linkname, os.path.join(destination, name))
    # mktemp -d starts at 0700. The separate service UID needs search permission.
    os.chmod(destination, 0o755)


def main():
    if len(sys.argv) != 3:
        sys.exit('Usage: extract-release.py ARCHIVE EMPTY_STAGE_DIRECTORY')
    try:
        enforce_resource_limits()
        extract_release(sys.argv[1], sys.argv[2])
    except (ResourceLimitError, MemoryError, RecursionError):
        sys.exit('Release extraction refused: resource limit exceeded or unavailable')
    except (ValueError, OSError, tarfile.TarError, EOFError):
        # Do not echo archive-controlled member names or metadata into logs.
        sys.exit('Release extraction refused: unsafe or invalid archive or destination')


if __name__ == '__main__':
    main()
