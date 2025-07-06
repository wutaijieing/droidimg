import os
import struct
import sys

# 常量定义
R_AARCH64_RELATIVE = 0x403
R_AARCH64_ABS = 0x101
ARCH_BITS = 64
PATH_MAX = 260
CONT_THRESHOLD = 50
GAP_THRESHOLD = 5

# 虚拟地址表
va_kern_text = [0] * ARCH_BITS
va_min_addr = [0] * ARCH_BITS

# 结构体定义
rela_entry_struct = struct.Struct('<QQQ')  # offset, info, sym
elf64_sym_struct = struct.Struct('<IBBHQQ')  # st_name, st_info, st_other, st_shndx, st_value, st_size

def alloc_kern_buf(infile):
    with open(infile, 'rb') as f:
        data = f.read()
    kern_size = len(data)
    kern_mmap_size = (kern_size + 0xfff) & (~0xfff)
    kern_buf = bytearray(kern_mmap_size)
    kern_buf[:kern_size] = data
    print(f"kern_buf @ {hex(id(kern_buf))}, mmap_size = {kern_mmap_size}")
    return kern_buf, kern_size, kern_mmap_size

def parse_rela_sect_smart(kern_buf, kern_mmap_size, va_bits):
    cont = 0
    entry_size = rela_entry_struct.size
    p = 0
    while p + entry_size <= kern_mmap_size:
        offset, info, sym = rela_entry_struct.unpack_from(kern_buf, p)
        if info == R_AARCH64_RELATIVE or info == R_AARCH64_ABS:
            if offset >= va_min_addr[va_bits] and sym >= va_min_addr[va_bits]:
                cont += 1
        elif (info & 0xfff) == 0x101:
            cont += 1
        else:
            cont = 0

        if cont == CONT_THRESHOLD:
            rela_start = p - (CONT_THRESHOLD - 1) * entry_size
            # 不要在这里print
            while p + entry_size <= kern_mmap_size:
                offset, info, sym = rela_entry_struct.unpack_from(kern_buf, p)
                if info not in [R_AARCH64_RELATIVE, R_AARCH64_ABS] and (info & 0xfff) != 0x101:
                    p1 = p
                    gap = 0
                    while p1 + entry_size <= kern_mmap_size and gap < GAP_THRESHOLD:
                        n_offset, n_info, n_sym = rela_entry_struct.unpack_from(kern_buf, p1)
                        if n_info in [R_AARCH64_RELATIVE, R_AARCH64_ABS] or (n_info & 0xfff) == 0x101:
                            break
                        p1 += entry_size
                        gap += 1
                    if gap >= GAP_THRESHOLD:
                        break
                    p = p1
                p += entry_size
            rela_end = p
            # 不要在这里print
            return rela_start, rela_end
        p += entry_size if cont else 8
    print("Failed to locate .rela section. Bail out.")
    sys.exit(-1)

def relocate_kernel(kern_buf, rela_start, rela_end, va_bits):
    entry_size = rela_entry_struct.size
    count = 0
    p = rela_start
    KERNEL_SLIDE = 0
    while p < rela_end:
        offset, info, sym = rela_entry_struct.unpack_from(kern_buf, p)
        mem_va = offset + KERNEL_SLIDE
        buf_off = mem_va - va_kern_text[va_bits]
        if info == R_AARCH64_RELATIVE:
            new_addr = sym + KERNEL_SLIDE
            if buf_off + 8 > len(kern_buf) or buf_off < 0:
                print(f"WARNING: rel: VA={hex(mem_va)} buf_off={hex(buf_off)} OOB!")
            else:
                kern_buf[buf_off:buf_off+8] = struct.pack('<Q', new_addr)
        elif (info & 0xffffffff) == R_AARCH64_ABS:
            sym_idx = ((info >> 32) & 0xffffffff)
            symtab_offset = rela_end + 24 * sym_idx
            st_name, st_info, st_other, st_shndx, st_value, st_size = elf64_sym_struct.unpack_from(kern_buf, symtab_offset)
            if st_shndx:
                real_stext = st_value
                if st_shndx != 0xfffffff1:
                    real_stext += KERNEL_SLIDE
                if buf_off + 8 > len(kern_buf) or buf_off < 0:
                    print(f"WARNING: abs: VA={hex(mem_va)} buf_off={hex(buf_off)} OOB!")
                else:
                    kern_buf[buf_off:buf_off+8] = struct.pack('<Q', real_stext + sym)
        p += entry_size
        count += 1
    print(f"{count} entries processed")

def write_outfile(outfile, kern_buf, kern_size):
    with open(outfile, 'wb') as f:
        f.write(kern_buf[:kern_size])
    return 0

def main():
    va_kern_text[39] = 0xffffff8008080000
    va_min_addr[39] = 0xffffff8000000000
    va_kern_text[48] = 0xFFFF000008080000
    va_min_addr[48] = 0xFFFF000000000000

    if len(sys.argv) not in [3, 4]:
        print("Usage: python fix_kaslr_arm64_bin.py <infile> <outfile> [va_bits]")
        print("By default, va_bits = 39")
        sys.exit(-1)

    infile = sys.argv[1]
    outfile = sys.argv[2]
    va_bits = 39
    if len(sys.argv) == 4:
        va_bits = int(sys.argv[3])
        if va_bits < 0 or va_bits >= ARCH_BITS or va_kern_text[va_bits] == 0 or va_min_addr[va_bits] == 0:
            print("Invalid or unsupported va_bits!")
            sys.exit(-1)

    print(f"Original kernel: {infile}, output file: {outfile}")

    kern_buf, kern_size, kern_mmap_size = alloc_kern_buf(infile)
    rela_start, rela_end = parse_rela_sect_smart(kern_buf, kern_mmap_size, va_bits)

    #print(f"kern_buf @ {hex(id(kern_buf))}, mmap_size = {kern_mmap_size}")
    print(f"rela_start = 0x{va_kern_text[va_bits] + rela_start:X}")
    print(f"rela_start(+0x498) = 0x{va_kern_text[va_bits] + rela_start + 0x498:X}")
    print(f"rela_end = 0x{va_kern_text[va_bits] + rela_end:X}")
    print(f"rela_start (file offset) = 0x{rela_start:X}")
    print(f"rela_end   (file offset) = 0x{rela_end:X}")

    relocate_kernel(kern_buf, rela_start, rela_end, va_bits)
    write_outfile(outfile, kern_buf, kern_size)

if __name__ == "__main__":
    main()