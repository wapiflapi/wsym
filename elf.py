#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ctypes
from ctypes import *
from functools import wraps

class PrintableStructureMixIn(object):
    def show(self):
        print(self)
        for field_name, field_type in self._fields_:
            value = getattr(self, field_name)
            if isinstance(value, int):
                value = hex(value)
            print("%15s: %s" % (field_name, value))

class CopyableStructureMixIn(object):
    def copy(self):
        new = type(self)()
        ctypes.pointer(new)[0] = self
        return new

class BigEndianStructure(ctypes.BigEndianStructure,
                         PrintableStructureMixIn,
                         CopyableStructureMixIn):
    pass

class LittleEndianStructure(ctypes.LittleEndianStructure,
                            PrintableStructureMixIn,
                            CopyableStructureMixIn):
    pass

def build_structure(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        name = ''.join(w[0].upper() + w[1:] for w in f.__name__.split('_'))
        return type("%s%d%s" % (name, self.wordsize, self.endianess),
                    (self.structure, ),
                    {"_fields_": f(self, *args, **kwargs)})
    return wrapper

def select_class(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        return f(self, *args, **kwargs)[self.ei_class]
    return wrapper

class ELFFactory(object):

    def __init__(self, ei_class, ei_data):
        if ei_class not in (ELFCLASS32, ELFCLASS64):
            raise ValueError("Unknown ei_class=%d" % ei_class)
        if ei_data not in (ELFDATA2LSB, ELFDATA2MSB):
            raise ValueError("Unknown ei_data=%d" % ei_data)

        self.ei_class = ei_class
        self.ei_data = ei_data

        if self.ei_class == ELFCLASS32:
            self.wordsize = 32
        elif self.ei_class == ELFCLASS64:
            self.wordsize = 64

        if self.ei_data == ELFDATA2LSB:
            self.structure = LittleEndianStructure
            self.endianess = "LSB"
        elif self.ei_data == ELFDATA2MSB:
            self.structure = BigEndianStructure
            self.endianess = "MSB"

    @build_structure
    @select_class
    def elf_ehdr(self):
        return {
            ELFCLASS32: [
                ("e_ident",         c_ubyte * 16),
                ("e_type",          c_uint16),
                ("e_machine",       c_uint16),
                ("e_version",       c_uint32),
                ("e_entry",         c_uint32),
                ("e_phoff",         c_uint32),
                ("e_shoff",         c_uint32),
                ("e_flags",         c_uint32),
                ("e_ehsize",        c_uint16),
                ("e_phentsize",     c_uint16),
                ("e_phnum",         c_uint16),
                ("e_shentsize",     c_uint16),
                ("e_shnum",         c_uint16),
                ("e_shstrndx",      c_uint16),
                ],
            ELFCLASS64: [
                ("e_ident",         c_ubyte * 16),
                ("e_type",          c_uint16),
                ("e_machine",       c_uint16),
                ("e_version",       c_uint32),
                ("e_entry",         c_uint64),
                ("e_phoff",         c_uint64),
                ("e_shoff",         c_uint64),
                ("e_flags",         c_uint32),
                ("e_ehsize",        c_uint16),
                ("e_phentsize",     c_uint16),
                ("e_phnum",         c_uint16),
                ("e_shentsize",     c_uint16),
                ("e_shnum",         c_uint16),
                ("e_shstrndx",      c_uint16),
                ]
            }

    @build_structure
    @select_class
    def elf_phdr(self):
        return {
            ELFCLASS32: [
                ("p_type",          c_uint32),
                ("p_offset",        c_uint32),
                ("p_vaddr",         c_uint32),
                ("p_paddr",         c_uint32),
                ("p_filesz",        c_uint32),
                ("p_memsz",         c_uint32),
                ("p_flags",         c_uint32),
                ("p_align",         c_uint32),
                ],
            ELFCLASS64: [
                ("p_type",          c_uint32),
                ("p_flags",         c_uint32),
                ("p_offset",        c_uint64),
                ("p_vaddr",         c_uint64),
                ("p_paddr",         c_uint64),
                ("p_filesz",        c_uint64),
                ("p_memsz",         c_uint64),
                ("p_align",         c_uint64),
                ]
            }

    @build_structure
    @select_class
    def elf_shdr(self):
        return {
            ELFCLASS32: [
                ("sh_name",         c_uint32),
                ("sh_type",         c_uint32),
                ("sh_flags",        c_uint32),
                ("sh_addr",         c_uint32),
                ("sh_offset",       c_uint32),
                ("sh_size",         c_uint32),
                ("sh_link",         c_uint32),
                ("sh_info",         c_uint32),
                ("sh_addralign",    c_uint32),
                ("sh_entsize",      c_uint32),
                ],
            ELFCLASS64: [
                ("sh_name",         c_uint32),
                ("sh_type",         c_uint32),
                ("sh_flags",        c_uint64),
                ("sh_addr",         c_uint64),
                ("sh_offset",       c_uint64),
                ("sh_size",         c_uint64),
                ("sh_link",         c_uint32),
                ("sh_info",         c_uint32),
                ("sh_addralign",    c_uint64),
                ("sh_entsize",      c_uint64),
                ]
            }

    @build_structure
    @select_class
    def elf_sym(self):
        return {
            ELFCLASS32: [
                ("st_name",         c_uint32),
                ("st_value",        c_uint32),
                ("st_size",         c_uint32),
                ("st_info",         c_ubyte),
                ("st_other",        c_ubyte),
                ("st_shndx",        c_uint16),
                ],
            ELFCLASS64: [
                ("st_name",         c_uint32),
                ("st_info",         c_ubyte),
                ("st_other",        c_ubyte),
                ("st_shndx",        c_uint16),
                ("st_value",        c_uint64),
                ("st_size",         c_uint64),
                ]
            }


class ELFFile(ELFFactory):

    def __init__(self, data):

        if data[:4] != b"\x7fELF":
            raise ValueError("Data is not an elf image.")

        self.data = data

        ei_class, ei_data = data[4:6]
        super().__init__(ei_class, ei_data)

        self.ehdr = self.elf_ehdr().from_buffer(self.data)

        self.phdrs = (self.elf_phdr() * self.ehdr.e_phnum).from_buffer(
            self.data, self.ehdr.e_phoff)

        self.shdrs = (self.elf_shdr() * self.ehdr.e_shnum).from_buffer(
            self.data, self.ehdr.e_shoff)

    def shstr(self, shndx):

        strtab = self.shdrs[self.ehdr.e_shstrndx]
        offset = strtab.sh_offset + shndx
        end = self.data.find(b"\x00", offset)

        if end < 0:
            raise KeyError(shndx)

        return self.data[offset:end+1]

EI_NIDENT = (16)
EI_MAG0 = 0
ELFMAG0 = 0x7f
EI_MAG1 = 1
ELFMAG1 = 'E'
EI_MAG2 = 2
ELFMAG2 = 'L'
EI_MAG3 = 3
ELFMAG3 = 'F'
ELFMAG = "\177ELF"
SELFMAG = 4
EI_CLASS = 4
ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASSNUM = 3
EI_DATA = 5
ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2
ELFDATANUM = 3
EI_VERSION = 6
EI_OSABI = 7
ELFOSABI_NONE = 0
ELFOSABI_SYSV = 0
ELFOSABI_HPUX = 1
ELFOSABI_NETBSD = 2
ELFOSABI_GNU = 3
ELFOSABI_LINUX = ELFOSABI_GNU
ELFOSABI_SOLARIS = 6
ELFOSABI_AIX = 7
ELFOSABI_IRIX = 8
ELFOSABI_FREEBSD = 9
ELFOSABI_TRU64 = 10
ELFOSABI_MODESTO = 11
ELFOSABI_OPENBSD = 12
ELFOSABI_ARM_AEABI = 64
ELFOSABI_ARM = 97
ELFOSABI_STANDALONE = 255
EI_ABIVERSION = 8
EI_PAD = 9
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_NUM = 5
ET_LOOS = 0xfe00
ET_HIOS = 0xfeff
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff
EM_NONE = 0
EM_M32 = 1
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_860 = 7
EM_MIPS = 8
EM_S370 = 9
EM_MIPS_RS3_LE = 10
EM_PARISC = 15
EM_VPP500 = 17
EM_SPARC32PLUS = 18
EM_960 = 19
EM_PPC = 20
EM_PPC64 = 21
EM_S390 = 22
EM_V800 = 36
EM_FR20 = 37
EM_RH32 = 38
EM_RCE = 39
EM_ARM = 40
EM_FAKE_ALPHA = 41
EM_SH = 42
EM_SPARCV9 = 43
EM_TRICORE = 44
EM_ARC = 45
EM_H8_300 = 46
EM_H8_300H = 47
EM_H8S = 48
EM_H8_500 = 49
EM_IA_64 = 50
EM_MIPS_X = 51
EM_COLDFIRE = 52
EM_68HC12 = 53
EM_MMA = 54
EM_PCP = 55
EM_NCPU = 56
EM_NDR1 = 57
EM_STARCORE = 58
EM_ME16 = 59
EM_ST100 = 60
EM_TINYJ = 61
EM_X86_64 = 62
EM_PDSP = 63
EM_FX66 = 66
EM_ST9PLUS = 67
EM_ST7 = 68
EM_68HC16 = 69
EM_68HC11 = 70
EM_68HC08 = 71
EM_68HC05 = 72
EM_SVX = 73
EM_ST19 = 74
EM_VAX = 75
EM_CRIS = 76
EM_JAVELIN = 77
EM_FIREPATH = 78
EM_ZSP = 79
EM_MMIX = 80
EM_HUANY = 81
EM_PRISM = 82
EM_AVR = 83
EM_FR30 = 84
EM_D10V = 85
EM_D30V = 86
EM_V850 = 87
EM_M32R = 88
EM_MN10300 = 89
EM_MN10200 = 90
EM_PJ = 91
EM_OPENRISC = 92
EM_ARC_A5 = 93
EM_XTENSA = 94
EM_AARCH64 = 183
EM_TILEPRO = 188
EM_MICROBLAZE = 189
EM_TILEGX = 191
EM_NUM = 192
EM_ALPHA = 0x9026
EV_NONE = 0
EV_CURRENT = 1
EV_NUM = 2
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_BEFORE = 0xff00
SHN_AFTER = 0xff01
SHN_HIPROC = 0xff1f
SHN_LOOS = 0xff20
SHN_HIOS = 0xff3f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_XINDEX = 0xffff
SHN_HIRESERVE = 0xffff
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP = 17
SHT_SYMTAB_SHNDX = 18
SHT_NUM = 19
SHT_LOOS = 0x60000000
SHT_GNU_ATTRIBUTES = 0x6ffffff5
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_LIBLIST = 0x6ffffff7
SHT_CHECKSUM = 0x6ffffff8
SHT_LOSUNW = 0x6ffffffa
SHT_SUNW_move = 0x6ffffffa
SHT_SUNW_COMDAT = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff
SHT_HISUNW = 0x6fffffff
SHT_HIOS = 0x6fffffff
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0x8fffffff
SHF_WRITE = (1 << 0)
SHF_ALLOC = (1 << 1)
SHF_EXECINSTR = (1 << 2)
SHF_MERGE = (1 << 4)
SHF_STRINGS = (1 << 5)
SHF_INFO_LINK = (1 << 6)
SHF_LINK_ORDER = (1 << 7)
SHF_OS_NONCONFORMING = (1 << 8)
SHF_GROUP = (1 << 9)
SHF_TLS = (1 << 10)
SHF_MASKOS = 0x0ff00000
SHF_MASKPROC = 0xf0000000
SHF_ORDERED = (1 << 30)
SHF_EXCLUDE = (1 << 31)
GRP_COMDAT = 0x1
SYMINFO_BT_SELF = 0xffff
SYMINFO_BT_PARENT = 0xfffe
SYMINFO_BT_LOWRESERVE = 0xff00
SYMINFO_FLG_DIRECT = 0x0001
SYMINFO_FLG_PASSTHRU = 0x0002
SYMINFO_FLG_COPY = 0x0004
SYMINFO_FLG_LAZYLOAD = 0x0008
SYMINFO_NONE = 0
SYMINFO_CURRENT = 1
SYMINFO_NUM = 2
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_NUM = 3
STB_LOOS = 10
STB_GNU_UNIQUE = 10
STB_HIOS = 12
STB_LOPROC = 13
STB_HIPROC = 15
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_NUM = 7
STT_LOOS = 10
STT_GNU_IFUNC = 10
STT_HIOS = 12
STT_LOPROC = 13
STT_HIPROC = 15
STN_UNDEF = 0
STV_DEFAULT = 0
STV_INTERNAL = 1
STV_HIDDEN = 2
STV_PROTECTED = 3
PN_XNUM = 0xffff
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_NUM = 8
PT_LOOS = 0x60000000
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552
PT_LOSUNW = 0x6ffffffa
PT_SUNWBSS = 0x6ffffffa
PT_SUNWSTACK = 0x6ffffffb
PT_HISUNW = 0x6fffffff
PT_HIOS = 0x6fffffff
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PF_X = (1 << 0)
PF_W = (1 << 1)
PF_R = (1 << 2)
PF_MASKOS = 0x0ff00000
PF_MASKPROC = 0xf0000000
NT_PRSTATUS = 1
NT_FPREGSET = 2
NT_PRPSINFO = 3
NT_PRXREG = 4
NT_TASKSTRUCT = 4
NT_PLATFORM = 5
NT_AUXV = 6
NT_GWINDOWS = 7
NT_ASRS = 8
NT_PSTATUS = 10
NT_PSINFO = 13
NT_PRCRED = 14
NT_UTSNAME = 15
NT_LWPSTATUS = 16
NT_LWPSINFO = 17
NT_PRFPXREG = 20
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_PRXFPREG = 0x46e62b7f
NT_PPC_VMX = 0x100
NT_PPC_SPE = 0x101
NT_PPC_VSX = 0x102
NT_386_TLS = 0x200
NT_386_IOPERM = 0x201
NT_X86_XSTATE = 0x202
NT_S390_HIGH_GPRS = 0x300
NT_S390_TIMER = 0x301
NT_S390_TODCMP = 0x302
NT_S390_TODPREG = 0x303
NT_S390_CTRS = 0x304
NT_S390_PREFIX = 0x305
NT_S390_LAST_BREAK = 0x306
NT_S390_SYSTEM_CALL = 0x307
NT_S390_TDB = 0x308
NT_ARM_VFP = 0x400
NT_ARM_TLS = 0x401
NT_ARM_HW_BREAK = 0x402
NT_ARM_HW_WATCH = 0x403
NT_VERSION = 1
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH = 29
DT_FLAGS = 30
DT_ENCODING = 32
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_NUM = 34
DT_LOOS = 0x6000000d
DT_HIOS = 0x6ffff000
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7fffffff
DT_VALRNGLO = 0x6ffffd00
DT_GNU_PRELINKED = 0x6ffffdf5
DT_GNU_CONFLICTSZ = 0x6ffffdf6
DT_GNU_LIBLISTSZ = 0x6ffffdf7
DT_CHECKSUM = 0x6ffffdf8
DT_PLTPADSZ = 0x6ffffdf9
DT_MOVEENT = 0x6ffffdfa
DT_MOVESZ = 0x6ffffdfb
DT_FEATURE_1 = 0x6ffffdfc
DT_POSFLAG_1 = 0x6ffffdfd
DT_SYMINSZ = 0x6ffffdfe
DT_SYMINENT = 0x6ffffdff
DT_VALRNGHI = 0x6ffffdff
DT_VALNUM = 12
DT_ADDRRNGLO = 0x6ffffe00
DT_GNU_HASH = 0x6ffffef5
DT_TLSDESC_PLT = 0x6ffffef6
DT_TLSDESC_GOT = 0x6ffffef7
DT_GNU_CONFLICT = 0x6ffffef8
DT_GNU_LIBLIST = 0x6ffffef9
DT_CONFIG = 0x6ffffefa
DT_DEPAUDIT = 0x6ffffefb
DT_AUDIT = 0x6ffffefc
DT_PLTPAD = 0x6ffffefd
DT_MOVETAB = 0x6ffffefe
DT_SYMINFO = 0x6ffffeff
DT_ADDRRNGHI = 0x6ffffeff
DT_ADDRNUM = 11
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd
DT_VERNEED = 0x6ffffffe
DT_VERNEEDNUM = 0x6fffffff
DT_VERSIONTAGNUM = 16
DT_AUXILIARY = 0x7ffffffd
DT_FILTER = 0x7fffffff
DT_EXTRANUM = 3
DF_ORIGIN = 0x00000001
DF_SYMBOLIC = 0x00000002
DF_TEXTREL = 0x00000004
DF_BIND_NOW = 0x00000008
DF_STATIC_TLS = 0x00000010
DF_1_NOW = 0x00000001
DF_1_GLOBAL = 0x00000002
DF_1_GROUP = 0x00000004
DF_1_NODELETE = 0x00000008
DF_1_LOADFLTR = 0x00000010
DF_1_INITFIRST = 0x00000020
DF_1_NOOPEN = 0x00000040
DF_1_ORIGIN = 0x00000080
DF_1_DIRECT = 0x00000100
DF_1_TRANS = 0x00000200
DF_1_INTERPOSE = 0x00000400
DF_1_NODEFLIB = 0x00000800
DF_1_NODUMP = 0x00001000
DF_1_CONFALT = 0x00002000
DF_1_ENDFILTEE = 0x00004000
DF_1_DISPRELDNE = 0x00008000
DF_1_DISPRELPND = 0x00010000
DF_1_NODIRECT = 0x00020000
DF_1_IGNMULDEF = 0x00040000
DF_1_NOKSYMS = 0x00080000
DF_1_NOHDR = 0x00100000
DF_1_EDITED = 0x00200000
DF_1_NORELOC = 0x00400000
DF_1_SYMINTPOSE = 0x00800000
DF_1_GLOBAUDIT = 0x01000000
DF_1_SINGLETON = 0x02000000
DTF_1_PARINIT = 0x00000001
DTF_1_CONFEXP = 0x00000002
DF_P1_LAZYLOAD = 0x00000001
DF_P1_GROUPPERM = 0x00000002
VER_DEF_NONE = 0
VER_DEF_CURRENT = 1
VER_DEF_NUM = 2
VER_FLG_BASE = 0x1
VER_FLG_WEAK = 0x2
VER_NDX_LOCAL = 0
VER_NDX_GLOBAL = 1
VER_NDX_LORESERVE = 0xff00
VER_NDX_ELIMINATE = 0xff01
VER_NEED_NONE = 0
VER_NEED_CURRENT = 1
VER_NEED_NUM = 2
VER_FLG_WEAK = 0x2
ELF_NOTE_SOLARIS = "SUNW Solaris"
ELF_NOTE_GNU = "GNU"
ELF_NOTE_PAGESIZE_HINT = 1
NT_GNU_ABI_TAG = 1
ELF_NOTE_ABI = NT_GNU_ABI_TAG
ELF_NOTE_OS_LINUX = 0
ELF_NOTE_OS_GNU = 1
ELF_NOTE_OS_SOLARIS2 = 2
ELF_NOTE_OS_FREEBSD = 3
NT_GNU_HWCAP = 2
NT_GNU_BUILD_ID = 3
NT_GNU_GOLD_VERSION = 4
