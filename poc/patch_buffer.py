import struct
import sys

OFFSET_FIELD = 0x58
SIZE_FIELD = 0x60


def main():
    if len(sys.argv) != 5:
        sys.exit('usage: patch_buffer.py <in.circle> <out.circle> <offset> <size>')
    src, dst, offset, size = sys.argv[1:]
    with open(src, 'rb') as fh:
        data = bytearray(fh.read())
    struct.pack_into('<QQ', data, OFFSET_FIELD, int(offset, 0), int(size, 0))
    with open(dst, 'wb') as fh:
        fh.write(data)


if __name__ == '__main__':
    main()
