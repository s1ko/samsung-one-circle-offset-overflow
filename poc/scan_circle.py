import struct
import sys

U64_MAX = (1 << 64) - 1


def u16(b, p):
    return struct.unpack_from('<H', b, p)[0]


def u32(b, p):
    return struct.unpack_from('<I', b, p)[0]


def i32(b, p):
    return struct.unpack_from('<i', b, p)[0]


def u64(b, p):
    return struct.unpack_from('<Q', b, p)[0]


def field(b, table, index):
    vtable = table - i32(b, table)
    slot = 4 + 2 * index
    if slot >= u16(b, vtable):
        return None
    off = u16(b, vtable + slot)
    return table + off if off else None


def scan(b):
    if len(b) < 8 or b[4:8] != b'CIR0':
        raise ValueError('not a Circle flatbuffer (missing CIR0 identifier)')
    model = u32(b, 0)
    vec_field = field(b, model, 4)
    if vec_field is None:
        return []
    vec = vec_field + u32(b, vec_field)
    hits = []
    for i in range(u32(b, vec)):
        elem = vec + 4 + 4 * i
        table = elem + u32(b, elem)
        f_off = field(b, table, 1)
        f_size = field(b, table, 2)
        off = u64(b, f_off) if f_off else 0
        size = u64(b, f_size) if f_size else 0
        reasons = []
        if off > 1:
            if off >= len(b):
                reasons.append('offset past end of file')
            if off > U64_MAX - size:
                reasons.append('offset + size wraps uint64')
            elif off + size > len(b):
                reasons.append('offset + size past end of file')
            if not reasons:
                reasons.append('note: extended buffer in a %d byte file' % len(b))
        if reasons:
            hits.append((i, off, size, reasons))
    return hits


def main():
    status = 0
    for path in sys.argv[1:]:
        with open(path, 'rb') as fh:
            data = fh.read()
        try:
            hits = scan(data)
        except (ValueError, struct.error) as exc:
            print('%s: unparseable (%s)' % (path, type(exc).__name__))
            status = max(status, 2)
            continue
        if not hits:
            print('%s: ok' % path)
            continue
        for i, off, size, reasons in hits:
            if reasons[0].startswith('note:'):
                print('%s: buffers[%d] offset=0x%x size=0x%x: %s' % (path, i, off, size, reasons[0]))
                continue
            status = max(status, 1)
            print('%s: SUSPECT buffers[%d] offset=0x%016x size=0x%x file=0x%x: %s'
                  % (path, i, off, size, len(data), '; '.join(reasons)))
    sys.exit(status)


if __name__ == '__main__':
    main()
