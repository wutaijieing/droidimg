/*
 * fix_kaslr_arm64_win32.c
 *
 * Win32 (Windows x64) port of fix_kaslr_arm64.c.
 *
 * Purpose (unchanged): repair a KASLR-enabled arm64 Android `vmlinux` image by
 * locating the `.rela` relocation table inside the image and refilling the
 * zeroed relocation entries (R_AARCH64_RELATIVE / R_AARCH64_ABS) with their
 * original addresses, then writing the repaired image out.
 *
 * The algorithm is a line-for-line equivalent of the original POSIX version.
 * Only the platform layer (file I/O, memory allocation, error reporting and a
 * handful of portability details) has been remapped to the Win32 API:
 *
 *   POSIX                         ->  Win32
 *   ------------------------------------------------------------------
 *   stat()                        ->  GetFileSizeEx()
 *   open(O_RDONLY)                ->  CreateFileA(GENERIC_READ)
 *   read()                        ->  ReadFile()      (looped until full)
 *   open(O_CREAT|O_RDWR)          ->  CreateFileA(CREATE_ALWAYS, GENERIC_WRITE)
 *   write()                       ->  WriteFile()     (looped until full)
 *   mmap(MAP_ANONYMOUS)           ->  VirtualAlloc(MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
 *   munmap()                      ->  VirtualFree(MEM_RELEASE)
 *   perror()                      ->  GetLastError() + FormatMessageA()
 *
 * The buffer allocated by mmap(MAP_SHARED | MAP_ANONYMOUS) was:
 *   - sized to the 4 KiB page-rounded `kern_mmap_size` (NOT `kern_size`), and
 *   - guaranteed zero-filled.
 * VirtualAlloc() with MEM_COMMIT reproduces both properties exactly, which is
 * required because the `.rela` scanner reads full 24-byte entries up to the
 * `kern_mmap_size` upper bound (potentially past `kern_size`).
 */

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* MSVC does not provide ssize_t; derive it from its own SSIZE_T. The header
 * include is intentionally placed after <windows.h>. MinGW (also _WIN32) has
 * ssize_t available through <sys/types.h>. */
#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#elif defined(_WIN32)
#include <sys/types.h>
#endif

#ifdef __linux__
#include <linux/limits.h>
#else
#include <limits.h>
#endif

/* MSVC does not define PATH_MAX; provide a sane fallback. */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Cross-compiler "always inline" specifier.
 * gcc/clang keep the original attribute; MSVC uses __forceinline. */
#if defined(_MSC_VER)
#define ALWAYS_INLINE  __forceinline
#define MAYBE_UNUSED
#else
#define ALWAYS_INLINE  inline __attribute__((always_inline))
#define MAYBE_UNUSED   __attribute__((unused))
#endif

/* KERNEL_TEXT / MIN_ADDR index the va_bits tables. */
#define KERNEL_TEXT   (va_kern_text[va_bits])
#define MIN_ADDR      (va_min_addr[va_bits])

/* Kernel-VA <-> local-buffer pointer translation.
 * NOTE: on Win64 (LLP64) `unsigned long` is only 32-bit, so the pointer must be
 * carried through uintptr_t (which is 64-bit) to preserve the original
 * semantics without truncation. */
#define KERN_VA(p)         (void *)((uintptr_t)(p) - (uintptr_t)kern_buf + (uintptr_t)KERNEL_TEXT)
#define LOCAL_VA(p)        (void *)((uintptr_t)(p) - (uintptr_t)KERNEL_TEXT + (uintptr_t)kern_buf)

#define IN_RANGE(p, b, l)  (((uint8_t *)(p) >= (uint8_t *)(b)) && ((uint8_t *)(p) < ((uint8_t *)(b) + (ssize_t)(l))))

#define R_AARCH64_RELATIVE  (0x403)
#define R_AARCH64_ABS       (0x101)

#define ARCH_BITS   (64)

uint8_t     *kern_buf;
size_t      kern_size;
size_t      kern_mmap_size;

char        infile[PATH_MAX];
char        outfile[PATH_MAX];

int va_bits = 39;

size_t va_kern_text[ARCH_BITS] = {0};
size_t va_min_addr[ARCH_BITS] = {0};


struct rela_entry_t {
    uint64_t    offset;
    uint64_t    info;
    uint64_t    sym;
};

struct Elf64_Sym {
    uint32_t    st_name;
    uint8_t     st_info;
    uint8_t     st_other;
    uint16_t    st_shndx;
    uint64_t    st_value;
    uint64_t    st_size;
};

struct rela_entry_t     *rela_start;
struct rela_entry_t     *rela_end;

/* ------------------------------------------------------------------------- */
/* Win32 helpers                                                             */
/* ------------------------------------------------------------------------- */
#if defined(_WIN32)

/* Report the last Win32 error with a human readable message (replaces perror). */
static void print_windows_error(const char *msg)
{
    DWORD err = GetLastError();
    LPSTR buf = NULL;
    DWORD len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf,
        0,
        NULL);

    if (len && buf) {
        printf("%s: [%lu] %s", msg, (unsigned long)err, buf);
    } else {
        printf("%s: error %lu\n", msg, (unsigned long)err);
    }

    if (buf) {
        LocalFree(buf);
    }
}

/* Bounded, always-terminated string copy (replaces the warning-prone strncpy,
 * which MSVC flags via C4996/C6054). */
static void safe_copy(char *dst, const char *src, size_t n)
{
    size_t i = 0;

    if (n == 0) {
        return;
    }

    for (i = 0; i + 1 < n && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

#endif /* _WIN32 */

/* ------------------------------------------------------------------------- */
/* Dead-code helpers (compiled but not called, kept for source fidelity).    */
/* ------------------------------------------------------------------------- */
static ALWAYS_INLINE MAYBE_UNUSED int32_t
extract_signed_bitfield (uint32_t insn, unsigned width, unsigned offset)
{
    unsigned shift_l = sizeof (int32_t) * 8 - (offset + width);
    unsigned shift_r = sizeof (int32_t) * 8 - width;

    return ((int32_t) insn << shift_l) >> shift_r;
}

static ALWAYS_INLINE MAYBE_UNUSED int
parse_insn_adrp(uint32_t insn, ssize_t *offset)
{
    uint32_t immlo = (insn >> 29) & 0x3;
    int32_t immhi = extract_signed_bitfield(insn, 19, 5) << 2;

    *offset = (immhi | immlo) * 4096;

    return 0;
}

static ALWAYS_INLINE MAYBE_UNUSED int
parse_insn_add(uint32_t insn, uint32_t *inc)
{
    *inc = (insn >> 10) & 0xfff;

    return 0;
}


/*
 * Allocate and populate the kernel image buffer.
 *
 * Equivalent of the original:
 *   kern_mmap_size = page-round-up(kern_size)
 *   kern_buf = mmap(NULL, kern_mmap_size, RW, MAP_SHARED|MAP_ANONYMOUS)  [zeroed]
 *   read(fd, kern_buf, kern_size)
 */
static ALWAYS_INLINE int alloc_kern_buf()
{
#if defined(_WIN32)
    HANDLE          hFile;
    LARGE_INTEGER   liSize;
    DWORD           bytesRead = 0;
    uint8_t        *dst;
    size_t          remaining;

    hFile = CreateFileA(infile,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        print_windows_error("CreateFile(infile) failed");
        return -1;
    }

    if (!GetFileSizeEx(hFile, &liSize)) {
        print_windows_error("GetFileSizeEx failed");
        CloseHandle(hFile);
        return -1;
    }

    kern_size = (size_t)liSize.QuadPart;
    kern_mmap_size = (kern_size + (size_t)0xfff) & ~((size_t)0xfff);

    /* MEM_COMMIT guarantees zero-filled, writable memory (like MAP_ANONYMOUS). */
    kern_buf = (uint8_t *)VirtualAlloc(NULL,
                                       kern_mmap_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (kern_buf == NULL) {
        print_windows_error("VirtualAlloc failed");
        CloseHandle(hFile);
        return -1;
    }
    printf("kern_buf @ %p, mmap_size = %llu\n",
           (void *)kern_buf, (unsigned long long)kern_mmap_size);

    /* Loop until the whole file has been read (handles DWORD-sized chunks). */
    dst = kern_buf;
    remaining = kern_size;
    while (remaining > 0) {
        DWORD to_read = (remaining > 0x80000000u) ? 0x80000000u : (DWORD)remaining;

        if (!ReadFile(hFile, dst, to_read, &bytesRead, NULL)) {
            print_windows_error("ReadFile failed");
            CloseHandle(hFile);
            return -1;
        }
        if (bytesRead == 0) {
            break; /* unexpected EOF */
        }
        dst += bytesRead;
        remaining -= bytesRead;
    }

    CloseHandle(hFile);
    return 0;
#else
    struct stat st;
    int fd;

    if (stat(infile, &st) == -1) {
        perror("stat failed");
        return -1;
    }

    kern_size = (size_t)st.st_size;
    kern_mmap_size = (kern_size + 0xfff) & (~0xfff);

    kern_buf = (uint8_t *)mmap(NULL, kern_mmap_size,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (kern_buf == (void *)-1) {
        perror("mmap failed");
        return -1;
    }
    printf("kern_buf @ %p, mmap_size = %llu\n",
           (void *)kern_buf, (unsigned long long)kern_mmap_size);

    fd = open(infile, O_RDONLY);
    if (fd == -1) {
        perror("open failed");
        return -1;
    }

    read(fd, kern_buf, kern_size);

    close(fd);
    return 0;
#endif
}

/* Calculates critical locations
 * - rela_entry
 * - rela_end;
 */
static ALWAYS_INLINE int parse_rela_sect_smart()
{
    #define CONT_THRESHOLD  50
    #define GAP_THRESHOLD   5
    struct rela_entry_t *p;
    int cont = 0;

    p = (struct rela_entry_t *)kern_buf;
    for (;;) {
    if ((size_t)p - (size_t)kern_buf >= kern_mmap_size) {
        printf("Failed to locate .rela section. Bail out.\n");
        exit(-1);
    }
#if defined(FK_SAFE_BOUND)
    /* OPT-IN ONLY (default build is a strictly faithful port).
     * The upstream scan upper bound only guarantees that p itself is before
     * the buffer end, yet each iteration reads a full 24-byte entry. When a
     * file contains no .rela table the scan walks all the way to the end and
     * the last entries read past the allocation (upstream SIGSEGVs here).
     * Enabling -DFK_SAFE_BOUND makes it bail out with the message the author
     * already wrote for this case, instead of crashing. */
    if ((size_t)p - (size_t)kern_buf + sizeof(struct rela_entry_t) > kern_mmap_size) {
        printf("Failed to locate .rela section. Bail out.\n");
        exit(-1);
    }
#endif

        if (p->info == R_AARCH64_RELATIVE ||
            p->info == R_AARCH64_ABS) {
            if (p->offset >= MIN_ADDR &&
                p->sym >= MIN_ADDR) {
                cont++;
            }
        }
        else if ((p->info & 0xfff) == 0x101) {
            cont++;
        }
        else {
            cont = 0;
        }

        if (cont == CONT_THRESHOLD) {
            rela_start = p - (CONT_THRESHOLD - 1);
            printf("rela_start = %p\n", KERN_VA(p));

            for (;;) {
                struct rela_entry_t *p1;

                while (p->info == R_AARCH64_RELATIVE ||
                       p->info == R_AARCH64_ABS ||
                       (p->info & 0xfff) == 0x101) {
                    p++;
                }

                p1 = p;
                while ((p1 - p) < GAP_THRESHOLD) {
                    if (p1->info == R_AARCH64_RELATIVE ||
                        p1->info == R_AARCH64_ABS ||
                        (p1->info & 0xfff) == 0x101) {
                        break;
                    }
                    p1++;
                }

                if ((p1 - p) >= GAP_THRESHOLD) {
                    break;
                }
                else {
                    p = p1;
                }
            }
            printf("p->info = 0x%llx\n", (unsigned long long)p->info);
            rela_end = p;
            printf("rela_end = %p\n", KERN_VA(p));

            return 0;
        }

        if (cont) {
            p++;
        }
        else {
            p = (struct rela_entry_t*)((size_t)p + sizeof(void *));
        }
    }

    return -1;
}

static ALWAYS_INLINE int relocate_kernel()
{
    #define KERNEL_SLIDE        (0)

    struct rela_entry_t *rela_entry = rela_start;
    int64_t     sym_offset;
    uint64_t    sym_info;
    size_t      sym_addr;

    int count = 0;

    while (rela_entry < rela_end)
    {
        sym_offset = rela_entry->offset;
        sym_info = rela_entry->info;
        sym_addr = rela_entry->sym;

        size_t *p = (size_t *)(sym_offset + KERNEL_SLIDE);

        if (sym_info == R_AARCH64_RELATIVE) {
            size_t new_addr = sym_addr + KERNEL_SLIDE;
            // printf("<%p>\n", (void *)new_addr);
            *(size_t *)LOCAL_VA(p) = new_addr;
        }
        else if ((uint32_t)sym_info == R_AARCH64_ABS) {
            struct Elf64_Sym *elf64_sym;

            elf64_sym = (struct Elf64_Sym *)((size_t)rela_end + 24 * ((sym_info >> 32) & 0xffffffff));
            if (elf64_sym->st_shndx) {
                size_t real_stext = elf64_sym->st_value;
                if ((int64_t)elf64_sym->st_shndx != -15) {
                    real_stext += KERNEL_SLIDE;
                }
                // printf("[%p]\n", (void *)(real_stext + sym_addr));
                *(size_t *)LOCAL_VA(p) = real_stext + sym_addr;
            }
        }

        rela_entry++;
        count++;
    }

    printf("%d entries processed\n", count);

    return 0;
}

static ALWAYS_INLINE int write_outfile()
{
#if defined(_WIN32)
    HANDLE          hFile;
    DWORD           bytesWritten = 0;
    const uint8_t  *src;
    size_t          remaining;

    hFile = CreateFileA(outfile,
                        GENERIC_WRITE,
                        0,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        print_windows_error("CreateFile(outfile) failed");
        return -1;
    }

    /* Loop until the whole kern_size bytes have been written. */
    src = kern_buf;
    remaining = kern_size;
    while (remaining > 0) {
        DWORD to_write = (remaining > 0x80000000u) ? 0x80000000u : (DWORD)remaining;

        if (!WriteFile(hFile, src, to_write, &bytesWritten, NULL)) {
            print_windows_error("WriteFile failed");
            CloseHandle(hFile);
            return -1;
        }
        if (bytesWritten == 0) {
            break;
        }
        src += bytesWritten;
        remaining -= bytesWritten;
    }

    CloseHandle(hFile);
    return 0;
#else
    int fd;

    fd = open(outfile, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("outfile");
        return -1;
    }

    write(fd, kern_buf, kern_size);
    close(fd);

    return 0;
#endif
}

int main(int argc, char **argv)
{
    /* initialize va */
    va_kern_text[39] = 0xffffff8008080000UL;
    va_min_addr[39]  = 0xffffff8000000000UL;
    va_kern_text[48] = 0xFFFF000008080000UL;
    va_min_addr[48]  = 0xFFFF000000000000UL;

    if (argc != 3 && argc != 4) {
        printf("Usage: fix_kaslr_arm64 <infile> <outfile> [va_bits]\n");
        printf("By default, va_bits = 39\n");
        return -1;
    }

    if (argc == 4) {
        va_bits = (int)strtol(argv[3], NULL, 10);
        if (va_bits < 0 || va_bits >= ARCH_BITS) {
            printf("Invalid va_bits!\n");
            return -1;
        }

        if (va_kern_text[va_bits] == 0 ||
            va_min_addr[va_bits] == 0) {
            printf("Unsupported va_bits!\n");
            return -1;
        }
    }

#if defined(_WIN32)
    safe_copy(infile, argv[1], PATH_MAX);
    safe_copy(outfile, argv[2], PATH_MAX);
#else
    strncpy(infile, argv[1], PATH_MAX);
    strncpy(outfile, argv[2], PATH_MAX);
#endif

    printf("Original kernel: %s, output file: %s\n", infile, outfile);

    if (alloc_kern_buf()) {
        return -1;
    }

    if (parse_rela_sect_smart()) {
        return -1;
    }

    if (relocate_kernel()) {
        return -1;
    }

    if (write_outfile()) {
        return -1;
    }

#if defined(_WIN32)
    VirtualFree(kern_buf, 0, MEM_RELEASE);
#else
    munmap(kern_buf, kern_mmap_size);
#endif

    return 0;
}
