#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ctypes
import argparse

from ctypes import sizeof, pointer

import elf

def add_symbols(elff, symbols):

    #
    # THE PLAN:
    #
    #  - Keep the exiting file structure but create our own sections.
    #  - add our data (symtab + symstrtab + shstrtab)
    #  - Add our sections (ghosts + symtabhdr + strtabhdr + shstrtabhdr)
    #    at the end of the file.
    #  - Hijack e_shoff and point it to our sections.
    #

    shstrtab = b""

    shdr_t = elff.elf_shdr()
    shdrs = []

    # Add null section.
    nullhdr = shdr_t()
    shstrtab += b"\x00"
    shdrs.append(nullhdr)


    # Build a ghost section for each segment.
    # We need ghosts to handle binary whith no sections.
    nbg = 0
    for phdr in elff.phdrs:

        if phdr.p_type != elf.PT_LOAD:
            continue

        shdr = shdr_t()
        shdr.sh_name = len(shstrtab)
        shstrtab += bytes("GHOST%d_%.*x\x00" % (
                nbg, elff.wordsize // 4, phdr.p_vaddr), "utf8")
        shdr.sh_type = elf.SHT_NOBITS
        shdr.sh_flags = elf.SHF_ALLOC
        if phdr.p_flags & elf.PF_X:
            shdr.sh_flags |= elf.SHF_EXECINSTR
        if phdr.p_flags & elf.PF_W:
            shdr.sh_flags |= elf.SHF_WRITE
        shdr.sh_addr = phdr.p_vaddr
        shdr.sh_offset = phdr.p_offset
        shdr.sh_size = phdr.p_memsz
        shdr.sh_link = 0
        shdr.sh_info = 0
        shdr.sh_addralign = 1 # Probably fine.
        shdr.sh_entsize = 0
        shdrs.append(shdr)
        nbg += 1


    # If there are shdr's in the original binary
    # we try to keep them. We do *not* need to
    # rewrite the original symtab.

    shoffset = len(shdrs)
    for shdr in elff.shdrs:

        shdr = shdr.copy()

        try:
            name = bytes(elff.shstr(shdr.sh_name))
        except KeyError:
            name = b"corrupt\x00"

        shdr.sh_name = len(shstrtab)
        shstrtab += name

        shdr.sh_link += shoffset

        if shdr.sh_flags & elf.SHF_INFO_LINK:
            shdr.sh_info += shoffset

        shdrs.append(shdr)

    symstrtab = b""


    # Collect symbols:

    sym_t = elff.elf_sym()
    symtab = []

    nullsym = sym_t()
    nullsym.st_name = len(symstrtab)
    symstrtab += b"\x00"
    symtab.append(nullsym)

    for name, addr, size in symbols:
        for shndx, shdr in enumerate(shdrs):
            if shdr.sh_addr <= addr < shdr.sh_addr + shdr.sh_size:
                break
        else:
            print("ignored (bad addr): %#x %s" % (addr, name))
            continue

        sym = sym_t()
        sym.st_name = len(symstrtab)
        symstrtab += bytes(name, "utf8") + b"\x00"
        sym.st_value = addr
        sym.st_size = size
        sym.st_info = (1 << 4) | 2 # GLOBAL FUNC
        sym.st_other = 0
        sym.st_shndx = shndx
        symtab.append(sym)


    # Add symtab
    symtabhdr = shdr_t()

    symtabhdr.sh_name = len(shstrtab)
    shstrtab += b".wsymtab\x00"
    symtabhdr.sh_type = elf.SHT_SYMTAB
    symtabhdr.sh_flags = 0
    symtabhdr.sh_addr = 0
    symtabhdr.sh_offset = len(elff.data)
    symtabhdr.sh_size = len(symtab) * sizeof(sym_t)
    symtabhdr.sh_link = len(shdrs) + 1 # list + [us, STRTAB]
    symtabhdr.sh_info = 0 # ?
    symtabhdr.sh_addralign = 1
    symtabhdr.sh_entsize = sizeof(sym_t)

    shdrs.append(symtabhdr)

    # Add symstrtab
    symstrtabhdr = shdr_t()

    symstrtabhdr.sh_name = len(shstrtab)
    shstrtab += b".strtab\x00"
    symstrtabhdr.sh_type = elf.SHT_STRTAB
    symstrtabhdr.sh_flags = 0
    symstrtabhdr.sh_addr = 0
    symstrtabhdr.sh_offset = len(elff.data) + symtabhdr.sh_size
    symstrtabhdr.sh_size = len(symstrtab)
    symstrtabhdr.sh_link = 0
    symstrtabhdr.sh_info = 0
    symstrtabhdr.sh_addralign = 1
    symstrtabhdr.sh_entsize = 0

    shdrs.append(symstrtabhdr)

    # Add shstrtab
    shstrtabhdr = shdr_t()

    shstrtabhdr.sh_name = len(shstrtab)
    shstrtab += b".shstrtab\x00"
    shstrtabhdr.sh_type = elf.SHT_STRTAB
    shstrtabhdr.sh_flags = 0
    shstrtabhdr.sh_addr = 0
    shstrtabhdr.sh_offset = len(elff.data) + symtabhdr.sh_size + symstrtabhdr.sh_size
    shstrtabhdr.sh_size = len(shstrtab)
    shstrtabhdr.sh_link = 0
    shstrtabhdr.sh_info = 0
    shstrtabhdr.sh_addralign = 1
    shstrtabhdr.sh_entsize = 0

    shdrs.append(shstrtabhdr)


    # We have all the elements,
    # build the new file.

    newdata = bytearray(len(elff.data)
                        + symtabhdr.sh_size
                        + symstrtabhdr.sh_size
                        + shstrtabhdr.sh_size
                        + sizeof(shdr_t) * len(shdrs))

    offset = len(elff.data)
    newdata[0:offset] = elff.data

    for sym in symtab:
        newdata[offset:offset+sizeof(sym)] = sym
        offset += sizeof(sym)

    newdata[offset:offset+len(symstrtab)] = symstrtab
    offset += len(symstrtab)
    newdata[offset:offset+len(shstrtab)] = shstrtab
    offset += len(shstrtab)

    shoff = offset

    for shdr in shdrs:
        newdata[offset:offset+sizeof(shdr)] = shdr
        offset += sizeof(shdr)

    newelf = elf.ELFFile(newdata)

    # Don't forget to link everythin back to ehdr:
    newelf.ehdr.e_shoff = shoff
    newelf.ehdr.e_shentsize = ctypes.sizeof(shdr_t)
    newelf.ehdr.e_shnum = len(shdrs)
    newelf.ehdr.e_shstrndx = len(shdrs) - 1

    return newelf


class FileParser(object):

    def __init__(self, path):
        self.file = argparse.FileType("r")(path)

    def log(self, msg, *args, **kwargs):
        print("%s: %s" % (self.__class__.__name__, msg), *args, **kwargs)


class FlatParser(FileParser):

    def get_symbols(self, target, verbose=False):

        symbols = []

        for line in self.file:
            if line.startswith("#"):
                continue
            splited = line.split()
            if len(splited) == 3:
                addr, name, size = splited
            elif len(splted) == 2:
                addr, name = splited
                size = "0"
            else:
                continue

            addr = int(addr, 16)
            size = int(size, 16)

            if verbose:
                self.log("%15s = %#x,\tsize=%d" % (
                        name, addr, size))

            symbols.append((name, addr, size))

        return symbols


class NMParser(FileParser):

    def get_symbols(self, target, verbose=False):

        symbols = []

        for line in self.file:
            if line.startswith("#"):
                continue
            splited = line.split()
            if len(splited) != 3:
                continue

            name, addr = splited[2], int(splited[0], 16)

            if verbose:
                self.log("%15s = %#x,\tsize=%d" % (
                        name, addr, 0))

            symbols.append((name, addr, 0))

        return symbols

class IDAParser(FileParser):

    def get_symbols(self, target, verbose=False):

        # OK, IDA is weird, it uses section-relative addres.
        # UNLESS there are no sections, then it uses segments.
        # No way to know... Lets guess.

        for line in self.file:
            if line.split() == ["Start", "Length", "Name", "Class"]:
                break

        sections = []
        for line in self.file:
            splited = line.split()
            if len(splited) != 4:
                break

            start_, _, _, name = splited
            start, _ = start_.split(":")
            name = bytes(name, "utf8") + b"\x00"
            sections.append([int(start, 16), name])

        # Ok, this is where we guess, kinda.
        # Lets check if all those sections exit,
        # otherwise we'll consider they are segments.

        i = 0
        for shndx, shdr in enumerate(target.shdrs):
            if i == len(sections):
                break
            if target.shstr(shdr.sh_name) == sections[i][1]:
                sections[i][1] = shndx
                i += 1

        if i == len(sections):
            translations = {}
            for i, shndx in sections:
                translations[i] = target.shdrs[shndx].sh_addr
        else:
            self.log("Couldnt match %s as a section. Assuming segments." % (sections[i], ))
            translations = {}
            for i, _ in sections:
                translations[i] = target.phdrs[i+1].p_vaddr

        # OK, done guessing.

        for line in self.file:
            if line.split() == ["Address", "Publics", "by", "Value"]:
                break
        next(self.file) # burn empty line.

        symbols = []

        for line in self.file:
            splited = line.split()
            if len(splited) != 2:
                break

            segment_offset, name = splited
            segment, offset = segment_offset.split(":")

            segment = int(segment, 16)
            offset = int(offset, 16)

            addr = translations[segment] + offset

            if verbose:
                self.log("%15s = %#x:%x + %#x = %#x,\tsize=%d" % (
                        name, segment, translations[segment], offset, addr, 0))

            symbols.append((name, addr, 0))

        return symbols


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=argparse.FileType("rb"))
    parser.add_argument("output", type=argparse.FileType("wb"))

    parser.add_argument("-v", "--verbose", action="store_true")

    parser.set_defaults(symbols=[])
    parser.add_argument("-f", "--flat", help="flat map format. (addr, name, [size])",
                        type=FlatParser, dest="symbols", action="append")
    parser.add_argument("-i", "--ida", help="IDA .map format.",
                        type=IDAParser, dest="symbols", action="append")
    parser.add_argument("-n", "--nm", help="nm format.",
                        type=NMParser, dest="symbols", action="append")

    args = parser.parse_args()

    elff = elf.ELFFile(bytearray(args.input.read()))

    symbols = []
    for parser in args.symbols:
        symbols += parser.get_symbols(elff, verbose=args.verbose)

    if not symbols:
        print("Warning: No symbols are being added. "
              "I'll still try though, even if its pointless.")

    newelf = add_symbols(elff, symbols)
    args.output.write(newelf.data)
