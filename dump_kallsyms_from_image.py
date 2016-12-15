#!/usr/bin/env python
import sys
import struct
import re

KERNEL_BASE = 0xffffffc000080000

#The size of the QWORD in a 64-bit architecture
QWORD_SIZE = struct.calcsize("Q")

#The size of the DWORD in a 32-bit architecture
DWORD_SIZE = struct.calcsize("I")

#The size of the WORD in a 32-bit architecture
WORD_SIZE = struct.calcsize("H")

#The alignment of labels in the resulting kernel file
LABEL_ALIGN = 0x100

#The minimal number of repeating addresses pointing to the kernel's text start address
#which are used as a heuristic in order to find the beginning of the kernel's symbol
#table. Since usually there are at least two symbols pointing to the beginning of the
#text segment ("stext", "_text"), the minimal number for the heuristic is 2.
KALLSYMS_ADDRESSES_MIN_HEURISTIC = 1

def read_qword(kernel_data, offset):
    '''
    Reads a DWORD from the given offset within the kernel data
    '''
    return struct.unpack("<Q", kernel_data[offset : offset + QWORD_SIZE])[0]

def read_dword(kernel_data, offset):
    '''
    Reads a DWORD from the given offset within the kernel data
    '''
    return struct.unpack("<I", kernel_data[offset : offset + DWORD_SIZE])[0]

def read_word(kernel_data, offset):
    '''
    Reads a WORD from the given offset within the kernel data
    '''
    return struct.unpack("<H", kernel_data[offset : offset + WORD_SIZE])[0]

def read_byte(kernel_data, offset):
    '''
    Reads an unsigned byte from the given offset within the kernel data
    '''
    return struct.unpack("<B", kernel_data[offset : offset + 1])[0]

def read_c_string(kernel_data, offset):
    '''
    Reads a NUL-delimited C-string from the given offset
    '''
    current_offset = offset
    result_str = ""
    while kernel_data[current_offset] != '\x00':
        result_str += kernel_data[current_offset]
        current_offset += 1
    return result_str

def label_align(address):
    '''
    Aligns the given value to the closest label output boundry
    '''
    return address & ~(LABEL_ALIGN-1)

def find_kallsyms_addresses(kernel_data, kernel_text_start):
    '''
    Searching for the beginning of the kernel's symbol table
    Returns the offset of the kernel's symbol table, or -1 if the symbol table could not be found
    '''
    kallsyms_off = -1
    for i in xrange(len(kernel_data) / 8):
        find = 1
        for j in xrange(10000):
            off = i * 8 + j * 8
            value = struct.unpack("<Q", kernel_data[off:off+8])[0]

            if value < KERNEL_BASE:
                find = 0
                break

        if find == 1:
            kallsyms_off = i * 8
            break

    return kallsyms_off

def get_kernel_symbol_table(kernel_data, kernel_text_start):
    '''
    Retrieves the kernel's symbol table from the given kernel file
    '''

    #Getting the beginning and end of the kallsyms_addresses table
    kallsyms_addresses_off = find_kallsyms_addresses(kernel_data, kernel_text_start)
    print "kallsym Offset: %016lx" % (kallsyms_addresses_off + kernel_text_start)

    kallsyms_addresses_end_off = kernel_data.find(struct.pack("<Q", 0), kallsyms_addresses_off)
    print "kallsym End Offset: %016lx" % (kallsyms_addresses_end_off + kernel_text_start)

    num_symbols = (kallsyms_addresses_end_off - kallsyms_addresses_off) / QWORD_SIZE
    #Making sure that kallsyms_num_syms matches the table size
    kallsyms_num_syms_off = label_align(kallsyms_addresses_end_off + LABEL_ALIGN)
    kallsyms_num_syms = read_qword(kernel_data, kallsyms_num_syms_off)
    if kallsyms_num_syms != num_symbols:
        print "[-] Actual symbol table size: %d, read symbol table size: %d" % (num_symbols, kallsyms_num_syms)
        return None
    print "kallsym Num: %d" % (kallsyms_num_syms)

    #Calculating the location of the markers table
    kallsyms_names_off = label_align(kallsyms_num_syms_off + LABEL_ALIGN)
    print "kallsym Names Offset: %016lx" % (kallsyms_names_off + kernel_text_start)

    current_offset = kallsyms_names_off
    for i in range(0, num_symbols):
        current_offset += read_byte(kernel_data, current_offset) + 1
    kallsyms_markers_off = label_align(current_offset + LABEL_ALIGN)

    print "kallsym Marker Offset: %016lx" % (kallsyms_markers_off + kernel_text_start)
    #Reading the token table
    '''
    Not sure if this can be a universal solution
    '''
    kallsyms_token_table_off = label_align(kernel_data.find(struct.pack("<Q", 0), kallsyms_markers_off + 8)+LABEL_ALIGN)
    print "kallsym Token Table Offset: %016lx" % (kallsyms_token_table_off + kernel_text_start)

    current_offset = kallsyms_token_table_off
    for i in range(0, 256):
        token_str = read_c_string(kernel_data, current_offset)
        current_offset += len(token_str) + 1

    kallsyms_token_index_off = label_align(current_offset + LABEL_ALIGN)
    print "kallsym Token Index Offset: %016lx" % (kallsyms_token_index_off + kernel_text_start)

    #Creating the token table
    token_table = []
    for i in range(0, 256):
        index = read_word(kernel_data, kallsyms_token_index_off + i * WORD_SIZE)
        token_table.append(read_c_string(kernel_data, kallsyms_token_table_off + index))

    #Decompressing the symbol table using the token table
    offset = kallsyms_names_off
    symbol_table = []
    for i in range(0, num_symbols):
        num_tokens = read_byte(kernel_data, offset)
        offset += 1
        symbol_name = ""
        for j in range(num_tokens, 0, -1):
            token_table_idx = read_byte(kernel_data, offset)
            symbol_name += token_table[token_table_idx]
            offset += 1

        symbol_address = read_qword(kernel_data, kallsyms_addresses_off + i * QWORD_SIZE)
        symbol_table.append((symbol_address, symbol_name[0], symbol_name[1:]))

    return symbol_table

def main():
    #Verifying the arguments
    if len(sys.argv) < 2:
        print "USAGE: %s: <KERNEL_FILE> [optional: <0xKERNEL_TEXT_START>]" % sys.argv[0]
        return
    kernel_data = open(sys.argv[1], "rb").read()

    off = struct.unpack("<Q", kernel_data[8:16])[0]
    kernel_text_start = 0xffffffc000000000 + off
    print "Text Offset: %016lx" % kernel_text_start

    #Getting the kernel symbol table
    symbol_table = get_kernel_symbol_table(kernel_data, kernel_text_start)
    fp = open("kallsyms","wb")
    for symbol in symbol_table:
            print "%016X %s %s" % symbol
            fp.write("%016X %s %s\n" % symbol)
    fp.close()

if __name__ == "__main__":
    main()
