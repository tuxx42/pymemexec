import sys
import ctypes
import resource
import logging
# import struct
from io import BytesIO
from elftools.elf.elffile import ELFFile

libc = ctypes.CDLL("libc.so.6")
c_NULL = ctypes.c_void_p(0)

MAP_SHARED = 0x01
MAP_PRIVATE = 0x02
MAP_TYPE = 0xf
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x20

PROT_EXEC = 0x1
PROT_WRITE = 0x2
PROT_READ = 0x4


class ElfBinary(ELFFile):
    elffile = None
    bits64 = False
    etype = None
    entry = None
    page_size = None

    etype_desc = {
        'ET_REL':   'relocatable file',
        'ET_EXEC':  'executable file',
        'ET_DYN':   'dynamically linked',
        'ET_CORE':  'core file'
    }

    def __init__(self, stream):
        ELFFile.__init__(self, BytesIO(stream))
        EI_CLASS = self.header.e_ident.EI_CLASS

        self.page_size = resource.getpagesize()
        self.bits64 = bool(EI_CLASS == 'ELFCLASS64')
        self.etype = self.header.e_type
        self.entry = self.header.e_entry

    def prot_str(self, prot):
        perms = (
            (PROT_READ, 'r'),
            (PROT_WRITE, 'w'),
            (PROT_EXEC, 'x')
        )

        return ''.join(
            c if prot & p else '-' for p, c in perms
        )

    def __mmap_64(self, start, size, prot, flags):
        mmap_ptr = libc.mmap
        mmap_ptr.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_int32,
            ctypes.c_int32,
            ctypes.c_int32,
            ctypes.c_uint64
        ]
        mmap_ptr.restype = ctypes.c_uint64

        logger.debug('mmap {} bytes at 0x{:08} ({}) '.format(
            size, start, self.prot_str(prot)
        ))

        return mmap_ptr(
            ctypes.c_void_p(start),
            ctypes.c_uint64(size),
            ctypes.c_int32(prot),
            ctypes.c_int32(flags),
            ctypes.c_int32(-1),
            ctypes.c_uint64(0)
        )

    def __memmove_64(self, start, offset, size):
        self.stream.seek(offset)
        buf = self.stream.read(size)

        memmove_ptr = libc.memmove
        memmove_ptr.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64
        ]
        memmove_ptr.restype = ctypes.c_void_p

        logger.debug('memmove 0x{:08X} bytes from 0x{:08X} to 0x{:08X}'.format(
            size, start, offset
        ))
        memmove_ptr(
            ctypes.c_void_p(start),
            ctypes.c_char_p(buf),
            ctypes.c_uint64(size)
        )

    def __memset_64(self, start, val, size):
        memset_ptr = libc.memset
        memset_ptr.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int32,
            ctypes.c_uint64
        ]
        memset_ptr.restype = ctypes.c_void_p

        c_start = ctypes.c_char_p(start)
        c_val = ctypes.c_int32(val)
        c_size = ctypes.c_uint64(size)

        logger.debug('memset 0x{:08X}-0x{:08X} to 0x{:02X}'.format(
            start, start+size, val
        ))
        memset_ptr(c_start, c_val, c_size)

    def __mprotect_64(self, start, size, prot):
        mprotect_ptr = libc.mprotect
        mprotect_ptr.restype = ctypes.c_int32
        mprotect_ptr.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_int32
        ]

        logger.debug('mprotect 0x{:08X} {}'.format(
            start, self.prot_str(prot)
        ))
        mprotect_ptr(
            ctypes.c_void_p(start),
            ctypes.c_uint64(size),
            ctypes.c_int32(prot)
        )

    def mmap_executable(self, start, size, offset, prot=None):
        page_addr_aligned = int(start / self.page_size) * self.page_size
        delta = start - page_addr_aligned
        page_size = size + delta

        map_prot = PROT_READ | PROT_WRITE | PROT_EXEC
        flags = MAP_ANONYMOUS | MAP_PRIVATE
        if start:
            flags |= MAP_FIXED

        # allocate memory block
        addr = self.__mmap_64(page_addr_aligned, page_size, map_prot, flags)
        if addr != page_addr_aligned:
            logging.error("unable to alloc addr. Unsupported, bailing!")

        # copy data
        self.__memmove_64(start, offset, size)

        # set perms
        if not prot:
            prot = PROT_READ | PROT_WRITE | PROT_EXEC

        self.__mprotect_64(start, size, prot)

    def mmap_dynamic(self, start, size, offset, prot=None):
        page_addr_aligned = int(start / self.page_size) * self.page_size
        delta = start - page_addr_aligned
        page_size = size + delta

        if not prot:
            prot = PROT_READ | PROT_WRITE | PROT_EXEC
        flags = MAP_ANONYMOUS | MAP_PRIVATE

        # allocate memory block
        start = self.__mmap_64(page_addr_aligned, page_size, prot, flags)
        if self.entry == -1:
            self.entry = start

        if start < 0:
            raise 'failed to mmap'

        # copy data
        self.__memmove_64(start, offset, size)

    def mmap(self, start, size, offset, prot=None):
        if self.etype == 'ET_EXEC':
            self.mmap_executable(start, size, offset, prot)
        if self.etype == 'ET_DYN':
            self.mmap_dynamic(start, size, offset, prot)

    def elf_info(self):
        EI_DATA = self.header.e_ident.EI_DATA
        return 'ELF {}-bits ({}) {} entry@{:08X}'.format(
            64 if self.bits64 else 32,
            'LSB' if EI_DATA == 'ELFDATA2LSB' else 'MSB',
            self.etype_desc.get(self.etype),
            self.entry
        )

    def map_segments(self):
        logger.info('mapping segments')
        # self.entry = -1
        for segment in self.iter_segments():
            if segment.header.p_type != 'PT_LOAD':
                continue

            start = segment.header.p_vaddr
            size = segment.header.p_memsz
            offset = segment.header.p_offset

            prot = segment.header.p_flags
            logger.info('segment 0x{:08X} len:0x{:08X} {}'.format(
                start, size, self.prot_str(prot))
            )

            self.mmap(start, size, offset, prot)

        for section in self.iter_sections():
            self.__mprotect_64(
                section.header.sh_addr,
                section.header.sh_size,
                section.header.sh_flags
            )
            if section.header.sh_type == 'SHT_NOBITS':
                logger.info('.bss {:08x}-{:08x}'.format(
                    section.header.sh_addr,
                    section.header.sh_addr + section.header.sh_size)
                )
                # bss section, zero out bits
                self.__memset_64(
                    section.header.sh_addr, 0, section.header.sh_size
                )

    def execute(self):
        ctypes.cast(self.entry, ctypes.CFUNCTYPE(None))()

    def jump_main(self):
        for section in elffile.iter_sections():
            try:
                for symbol in section.iter_symbols():
                    if symbol.name == 'main':
                        elffile.entry = symbol.entry.st_value
                        logger.info('main sym @0x{:08}'.format(elffile.entry))
                        break
            except AttributeError:
                pass

        logger.info('attempting to call 0x{:08X} good luck bitches'.format(
            elffile.entry)
        )
        self.execute()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__file__)

    with open(sys.argv[1], 'rb') as f:
        buf = f.read()

    elffile = ElfBinary(buf)

    logger.info(elffile.elf_info())
    elffile.map_segments()

    # logging.debug('original entry point {:08X}'.format(elffile.entry))
    logger.info('searching for entry point...')
    elffile.jump_main()
