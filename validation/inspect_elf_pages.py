"""Read ELF headers as data. Never mmap, dlopen, relocate, or execute payloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct


def inspect(path, page_sizes):
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
            raise ValueError(f'{path}: expected little-endian ELF64')
        elf = struct.unpack('<16sHHIQQQIHHHHHH', header)
        if elf[1] != 3 or elf[2] != 183 or elf[9] != 56:
            raise ValueError(f'{path}: expected AArch64 ET_DYN, 56-byte phdr')
        if elf[5] > size or elf[10] * 56 > size - elf[5]:
            raise ValueError(f'{path}: invalid program header bounds')
        stream.seek(elf[5])
        headers = [struct.unpack('<IIQQQQQQ', stream.read(56))
                   for _ in range(elf[10])]
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    loads = []
    for index, (kind, flags, offset, vaddr, _, filesz, memsz, align) in enumerate(headers):
        if kind != 1:
            continue
        if (filesz > memsz or offset > size or filesz > size - offset or
                vaddr + memsz > 2**64 - 1):
            raise ValueError(f'{path}: invalid PT_LOAD[{index}] bounds')
        if align > 1 and (align & (align - 1) or (vaddr - offset) % align):
            raise ValueError(f'{path}: invalid PT_LOAD[{index}] alignment')
        loads.append(dict(index=index, flags=flags, offset=offset, vaddr=vaddr,
                          filesz=filesz, memsz=memsz, align=align))
    if not loads or not any(p['memsz'] for p in loads):
        raise ValueError(f'{path}: empty load image')
    plans = {}
    for page in page_sizes:
        end = max(p['vaddr'] + p['memsz'] for p in loads)
        image_size = (end + page - 1) // page * page
        # Intersect virtual page intervals, not file-offset intervals.
        conflicts = []
        for rx in loads:
            for rw in loads:
                if not (rx['flags'] & 1 and rw['flags'] & 2 and
                        rx['memsz'] and rw['memsz']):
                    continue
                first = max(rx['vaddr'] // page, rw['vaddr'] // page)
                last = min((rx['vaddr'] + rx['memsz'] - 1) // page,
                           (rw['vaddr'] + rw['memsz'] - 1) // page)
                if first <= last:
                    conflicts.append(dict(rx_index=rx['index'], rw_index=rw['index'],
                                          start=first * page, end=(last + 1) * page))
        plans[str(page)] = dict(image_size=image_size, wx_conflicts=conflicts,
                                layout_compatible=not conflicts)
    return dict(path=str(path), file_size=size, sha256=digest,
                phnum=elf[10], loader_phnum_supported=elf[10] <= 16,
                loads=loads, page_plans=plans)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', type=Path, nargs='+')
    parser.add_argument('--page-size', type=int, action='append')
    args = parser.parse_args()
    pages = args.page_size or [4096, 16384, 65536]
    if any(p <= 0 or p & (p - 1) for p in pages):
        parser.error('page sizes must be positive powers of two')
    host = os.sysconf('SC_PAGE_SIZE')
    results = [inspect(path, pages) for path in args.paths]
    print(json.dumps(dict(host_page_size=host, libraries=results), indent=2))
    return int(any(not lib['loader_phnum_supported'] or
                   any(not plan['layout_compatible'] for plan in lib['page_plans'].values())
                   for lib in results))


if __name__ == '__main__':
    raise SystemExit(main())
