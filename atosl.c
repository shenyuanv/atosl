/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>

#include <dwarf.h>
#include <libdwarf.h>

#include "atosl.h"
#include "subprograms.h"
#include "common.h"

#define VERSION ATOSL_VERSION

#define DWARF_ASSERT(ret, err) \
    do { \
        if (ret == DW_DLV_ERROR) { \
            fatal("dwarf_errmsg: %s", dwarf_errmsg(err)); \
        } \
    } while (0);

/* Objective-C method list structure constants */
#define OBJC_METHOD_LIST_HEADER_SIZE 8  /* entsizeAndFlags (4) + count (4) */
#define OBJC_METHOD_T_FIELD_SIZE 4      /* Size of each 32-bit field in method_t */
#define OBJC_METHOD_T_MIN_SIZE 12       /* Minimum size: name(4) + types(4) + imp(4) */
#define OBJC_METHOD_T_NAME_OFFSET 0     /* Offset of name field in method_t */
#define OBJC_METHOD_T_TYPES_OFFSET 4    /* Offset of types field in method_t */
#define OBJC_METHOD_T_IMP_OFFSET 8      /* Offset of imp field in method_t */

/* Objective-C method parsing limits and constants */
#define OBJC_METHOD_ARRAY_INITIAL_SIZE 200      /* Initial allocation size for method array */
#define OBJC_METHOD_ARRAY_REALLOC_INCREMENT 100 /* Reallocation increment */
#define OBJC_METHOD_ARRAY_MAX_SIZE 200          /* Maximum methods to parse per list */
#define OBJC_METHOD_ENTSIZE_MAX 100             /* Maximum valid entsize value */
#define OBJC_METHOD_COUNT_MAX 1000              /* Maximum valid method count */
#define OBJC_DEBUG_METHOD_DUMP_LIMIT 3          /* Number of methods to dump raw bytes for */
#define OBJC_DEBUG_METHOD_OUTPUT_LIMIT 10       /* Number of methods to output in debug */
#define OBJC_SEL_POINTER_SIZE 8                 /* Size of SEL pointer (64-bit) */
#define OBJC_ADDRESS_RANGE_CHECK 0x20000        /* 128KB range for address validation */
#define OBJC_METHNAME_BOUNDS_TOLERANCE 100      /* Tolerance for bounds checking */
#define OBJC_DEBUG_NEARBY_SYMBOLS_WINDOW 10     /* Number of nearby symbols to show in debug */

extern char *
cplus_demangle (const char *mangled, int options);

typedef unsigned long Dwarf_Word;

Dwarf_Unsigned
_dwarf_decode_u_leb128(Dwarf_Small * leb128,
    Dwarf_Word * leb128_length);
#define DECODE_LEB128_UWORD(ptr, value)               \
    do {                                              \
        Dwarf_Word uleblen;                           \
        value = _dwarf_decode_u_leb128(ptr,&uleblen); \
        ptr += uleblen;                               \
    } while (0)

static int debug = 0;

static const char *shortopts = "vl:o:A:gcC:VhD";
static struct option longopts[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"load-address", required_argument, NULL, 'l'},
    {"no-demangle", no_argument, NULL, 'D'},
    {"dsym", required_argument, NULL, 'o'},
    {"arch", required_argument, NULL, 'A'},
    {"globals", no_argument, NULL, 'g'},
    {"no-cache", no_argument, NULL, 'c'},
    {"cache-dir", required_argument, NULL, 'C'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static struct {
    const char *name;
    cpu_type_t type;
    cpu_subtype_t subtype;
} arch_str_to_type[] = {
    {"i386", CPU_TYPE_I386, CPU_SUBTYPE_X86_ALL},
    {"armv6",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6},
    {"armv7",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7},
    {"armv7s", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S},
    {"arm64",  CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL},
    {"arm64e",  CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E}
};

struct symbol_t {
    const char *name;
    union {
        struct nlist_t sym32;
        struct nlist_64 sym64;
    } sym;
    Dwarf_Addr addr;
    uint8_t n_type;
    uint8_t n_sect;
    int thumb:1;
};

struct function_t {
    const char *name;
    Dwarf_Addr addr;
};

/* Various addresses, parsed from the cmdline or the mach-o sections */
static struct {
    Dwarf_Addr load_address;
    int use_globals;
    int use_cache;
    const char *dsym_filename;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    const char *cache_dir;
    int should_demangle;
} options = {
    .load_address = LONG_MAX,
    .use_globals = 0,
    .use_cache = 1,
    .cpu_type = CPU_TYPE_ARM,
    .cpu_subtype = CPU_SUBTYPE_ARM_V7S,
    .should_demangle = 1,
};

typedef int dwarf_mach_handle;

struct dwarf_section_t;
struct dwarf_section_t {
    struct section_t mach_section;
    struct dwarf_section_t *next;
};

struct dwarf_section_64_t;
struct dwarf_section_64_t {
    struct section_64_t mach_section;
    struct dwarf_section_64_t *next;
};

static struct {
    /* Symbols from symtab */
    struct symbol_t *symlist;
    uint32_t nsymbols;
    struct dwarf_subprogram_t *subprograms;

    Dwarf_Addr intended_addr;
    Dwarf_Addr linkedit_addr;

    struct fat_arch_t arch;

    uint8_t uuid[UUID_LEN];
    uint8_t is_64;
    uint8_t is_dwarf;
    
    /* Objective-C method name section */
    Dwarf_Addr objc_methname_addr;
    Dwarf_Addr objc_methname_size;
    Dwarf_Addr objc_methname_offset;
    
    /* Objective-C selector references section */
    Dwarf_Addr objc_selrefs_addr;
    Dwarf_Addr objc_selrefs_size;
    Dwarf_Addr objc_selrefs_offset;
    
    /* Objective-C method list section */
    Dwarf_Addr objc_methlist_addr;
    Dwarf_Addr objc_methlist_size;
    Dwarf_Addr objc_methlist_offset;
    
    /* Objective-C method implementations mapped to names */
    struct objc_method_t {
        const char *name;
        Dwarf_Addr imp_addr;  /* Implementation address */
    } *objc_methods;
    int objc_method_count;
} context;

typedef struct {
    dwarf_mach_handle handle;
    Dwarf_Small length_size;
    Dwarf_Small pointer_size;
    Dwarf_Endianness endianness;

    Dwarf_Unsigned section_count;
    struct dwarf_section_t *sections;
    struct dwarf_section_64_t *sections_64;
} dwarf_mach_object_access_internals_t;

void print_help(void)
{
    fprintf(stderr, "atosl %s\n", VERSION);
    fprintf(stderr, USAGE "\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
            "  -o, --dsym=FILE\t\tfile to find symbols in\n");
    fprintf(stderr,
            "  -v, --verbose\t\t\tenable verbose (debug) messages\n");
    fprintf(stderr,
            "  -l, --load-address=ADDRESS\tspecify application load address\n");
    fprintf(stderr,
            "  -A, --arch=ARCH\t\tspecify architecture\n");
    fprintf(stderr,
            "  -g, --globals\t\t\tlookup symbols using global section\n");
    fprintf(stderr,
            "  -c, --no-cache\t\tdon't cache debugging information\n");
    fprintf(stderr,
            "  -D, --no-demangle\t\tdon't demangle symbols\n");
    fprintf(stderr,
            "  -V, --version\t\t\tget current version\n");
    fprintf(stderr,
            "  -h, --help\t\t\tthis help\n");
    fprintf(stderr, "\n");
}

void dwarf_error_handler(Dwarf_Error err, Dwarf_Ptr ptr)
{
    fatal("dwarf error: %s", dwarf_errmsg(err));
}

char *demangle(const char *sym)
{
    char *demangled = NULL;

    if (debug)
        fprintf(stderr, "Unmangled name: %s\n", sym);
    if (strncmp(sym, "_Z", 2) == 0)
        demangled = cplus_demangle(sym, 0);
    else if (strncmp(sym, "__Z", 3) == 0)
        demangled = cplus_demangle(sym+1, 0);

    return demangled;
}

int parse_uuid(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int i;
    int ret;

    ret = _read(obj->handle, context.uuid, UUID_LEN);
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "%10s ", "uuid");
        for (i = 0; i < UUID_LEN; i++) {
            fprintf(stderr, "%.02x", context.uuid[i]);
        }
        fprintf(stderr, "\n");
    }

    return 0;
}

int parse_section(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_t *s;

    s = malloc(sizeof(*s));
    if (!s)
        fatal("unable to allocate memory");

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.08x\n", "addr", s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.08x\n", "size", s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
    }
    
    /* Track Objective-C method name section for potential future use */
    /* Use strncmp because section names are 16 bytes and may be null-padded */
    if (strncmp(s->mach_section.sectname, "__objc_methname", 16) == 0) {
        context.objc_methname_addr = s->mach_section.addr;
        context.objc_methname_size = s->mach_section.size;
        context.objc_methname_offset = s->mach_section.offset;
        if (debug) {
            fprintf(stderr, "*** Found __objc_methname section: addr=0x%x, size=0x%x, offset=%d ***\n",
                    s->mach_section.addr, s->mach_section.size, s->mach_section.offset);
        }
    }
    
    /* Track Objective-C selector references section */
    if (strncmp(s->mach_section.sectname, "__objc_selrefs", 16) == 0) {
        context.objc_selrefs_addr = s->mach_section.addr;
        context.objc_selrefs_size = s->mach_section.size;
        context.objc_selrefs_offset = s->mach_section.offset;
        if (debug) {
            fprintf(stderr, "*** Found __objc_selrefs section: addr=0x%x, size=0x%x, offset=%d ***\n",
                    s->mach_section.addr, s->mach_section.size, s->mach_section.offset);
        }
    }

    struct dwarf_section_t *sec = obj->sections;
    if (!sec)
        obj->sections = s;
    else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}

int parse_section_64(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_64_t *s;

    s = malloc(sizeof(*s));
    if (!s)
        fatal("unable to allocate memory");

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.8llx\n", "addr", (unsigned long long)s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.8llx\n", "size", (unsigned long long)s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
        fprintf(stderr, "%10s %d\n", "reserved3", s->mach_section.reserved3);
    }
    
    /* Track Objective-C method name section for potential future use */
    /* Use strncmp because section names are 16 bytes and may be null-padded */
    if (strncmp(s->mach_section.sectname, "__objc_methname", 16) == 0) {
        context.objc_methname_addr = s->mach_section.addr;
        context.objc_methname_size = s->mach_section.size;
        context.objc_methname_offset = s->mach_section.offset;
        if (debug) {
            fprintf(stderr, "*** FOUND __objc_methname section: addr=0x%llx, size=0x%llx, offset=%d ***\n",
                    (unsigned long long)s->mach_section.addr, 
                    (unsigned long long)s->mach_section.size, 
                    s->mach_section.offset);
        }
    }
    
    /* Track Objective-C method list section */
    if (strncmp(s->mach_section.sectname, "__objc_methlist", 16) == 0) {
        context.objc_methlist_addr = s->mach_section.addr;
        context.objc_methlist_size = s->mach_section.size;
        context.objc_methlist_offset = s->mach_section.offset;
        if (debug) {
            fprintf(stderr, "*** FOUND __objc_methlist section: addr=0x%llx, size=0x%llx, offset=%d ***\n",
                    (unsigned long long)s->mach_section.addr, 
                    (unsigned long long)s->mach_section.size, 
                    s->mach_section.offset);
        }
    }
    
    /* Track Objective-C selector references section */
    if (strncmp(s->mach_section.sectname, "__objc_selrefs", 16) == 0) {
        context.objc_selrefs_addr = s->mach_section.addr;
        context.objc_selrefs_size = s->mach_section.size;
        context.objc_selrefs_offset = s->mach_section.offset;
        if (debug) {
            fprintf(stderr, "*** FOUND __objc_selrefs section: addr=0x%llx, size=0x%llx, offset=%d ***\n",
                    (unsigned long long)s->mach_section.addr, 
                    (unsigned long long)s->mach_section.size, 
                    s->mach_section.offset);
        }
    }

    struct dwarf_section_64_t *sec = obj->sections_64;
    
    if (!sec) {
        obj->sections_64 = s;
    } else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}

int parse_segment(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.08x\n", segment.vmaddr);
        fprintf(stderr, "\tvmsize: %d\n", segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.08x\n", segment.fileoff);
        fprintf(stderr, "\tfilesize: %d\n", segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context.intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context.linkedit_addr = segment.fileoff;
    }

    if (strcmp(segment.segname, "__DWARF") == 0) {
        context.is_dwarf = 1;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section(obj);
        if (err)
            fatal("unable to parse section in `%s`", segment.segname);
    }

    return 0;
}

int parse_segment_64(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_64_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.8llx\n", (unsigned long long)segment.vmaddr);
        fprintf(stderr, "\tvmsize: %llu\n", (unsigned long long)segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.8llx\n", (unsigned long long)segment.fileoff);
        fprintf(stderr, "\tfilesize: %llu\n", (unsigned long long)segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context.intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context.linkedit_addr = segment.fileoff;
    }

    if (strcmp(segment.segname, "__DWARF") == 0) {
        context.is_dwarf = 1;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section_64(obj);
        if (err)
            fatal("unable to parse section in `%s`", segment.segname);
    }

    return 0;
}

int parse_symtab(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int ret;
    off_t pos;
    int i;
    char *strtable;

    struct symtab_command_t symtab;
    struct symbol_t *current;

    ret = _read(obj->handle, &symtab, sizeof(symtab));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Symbol\n");
        fprintf(stderr, "%10s %.08x\n", "symoff", symtab.symoff);
        fprintf(stderr, "%10s %d\n", "nsyms", symtab.nsyms);
        fprintf(stderr, "%10s %.08x\n", "stroff", symtab.stroff);
        fprintf(stderr, "%10s %d\n", "strsize", symtab.strsize);
    }

    strtable = malloc(symtab.strsize);
    if (!strtable)
        fatal("unable to allocate memory");

    pos = lseek(obj->handle, 0, SEEK_CUR);
    if (pos < 0)
        fatal("error seeking: %s", strerror(errno));

    ret = lseek(obj->handle, context.arch.offset+symtab.stroff, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    ret = _read(obj->handle, strtable, symtab.strsize);
    if (ret < 0)
        fatal_file(ret);

    ret = lseek(obj->handle, context.arch.offset+symtab.symoff, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    context.nsymbols = symtab.nsyms;
    context.symlist = malloc(sizeof(struct symbol_t) * symtab.nsyms);
    if (!context.symlist)
        fatal("unable to allocate memory");
    current = context.symlist;

    for (i = 0; i < symtab.nsyms; i++) {
        ret = _read(obj->handle, context.is_64 ? (void*)&current->sym.sym64 : (void*)&current->sym.sym32, context.is_64 ? sizeof(current->sym.sym64) : sizeof(current->sym.sym32));
        if (ret < 0)
            fatal_file(ret);

        if (context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx) {
            if ((context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx) > symtab.strsize)
                fatal("str offset (%d) greater than strsize (%d)",
                      (context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx), symtab.strsize);
            current->name = strtable+(context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx);
        }

        current++;
    }

    ret = lseek(obj->handle, pos, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    return 0;
}

static int compare_symbols(const void *a, const void *b)
{
    struct symbol_t *sym_a = (struct symbol_t *)a;
    struct symbol_t *sym_b = (struct symbol_t *)b;
    if (sym_a->addr < sym_b->addr)
        return -1;
    if (sym_a->addr > sym_b->addr)
        return 1;
    return 0;
}

void print_symbol(const char *symbol, unsigned offset)
{
    char *demangled = options.should_demangle ? demangle(symbol) : NULL;
    const char *name = demangled ? demangled : symbol;

    if (name[0] == '_')
        name++;

    printf("%s%s (in %s) + %d\n",
            name,
            demangled ? "()" : "",
            basename((char *)options.dsym_filename),
            offset);

    if (demangled)
        free(demangled);
}

/* Print symbol name based on stabs information.
 * Currently only handles functions (N_FUN stabs)
 *
 * See README.stabs for stabs format information.
 *
 * Here we find pairs of N_FUN stabs. The first has the name of the function and its starting address;
 * the second has its size.
 *
 * We could also symbolicate global and static symbols (N_GSYM and N_STSYM) here,
 * but it's not necessary to do so since they'll be picked up by the generic symbol table
 * search later in this function.
 *
 * Return 1 if a symbol corresponding to search_addr was found; 0 otherwise.
 */
int handle_stabs_symbol(int is_fun_stab, Dwarf_Addr search_addr, const struct symbol_t *symbol)
{
    /* These are static since they need to persist across pairs of symbols. */
    static const char *last_fun_name = NULL;
    static Dwarf_Addr last_addr;

    if (is_fun_stab) {  
        if (last_fun_name) { /* if this is non-null, the last symbol was an N_FUN stab as well. */
            if (debug)
                fprintf(stderr, "\t\tSecond consecutive N_FUN symbol. Function size: %llu (0x%llx)\n",
                        symbol->addr, symbol->addr);
            if (last_addr <= search_addr
                    && search_addr < last_addr + symbol->addr) {
                print_symbol(last_fun_name, (unsigned int)(search_addr - last_addr));
                return 1;
            } else if (debug)
                fprintf(stderr, "\t\tNot printing symbol %s; 0x%llx not in the interval [0x%llx 0x%llx).\n",
                        last_fun_name, search_addr, last_addr, last_addr + symbol->addr);
            last_fun_name = NULL;
        } else { /* last_fun_name is null, so this is the first N_FUN in (possibly) a pair. */
            last_fun_name = symbol->name;
            if (debug)
                fprintf(stderr, "\t\tFirst consecutive N_FUN symbol. Function name: %s; addr: 0x%llx\n",
                        symbol->name, symbol->addr);
        }
    } else {
        if (debug && last_fun_name) {
            fprintf(stderr, "%s", "\t\tN_FUN symbol not part of a pair! Ignoring.\n");
            fprintf(stderr, "Name: %s, addr: 0x%llx (%llu)\n", last_fun_name, last_addr, last_addr);
        }
        last_fun_name = NULL;
    }
    last_addr = symbol->addr;
    return 0;
}

/* Compare Objective-C methods by address for binary search */
static int compare_objc_methods(const void *a, const void *b)
{
    const struct objc_method_t *meth_a = (const struct objc_method_t *)a;
    const struct objc_method_t *meth_b = (const struct objc_method_t *)b;
    if (meth_a->imp_addr < meth_b->imp_addr)
        return -1;
    if (meth_a->imp_addr > meth_b->imp_addr)
        return 1;
    return 0;
}

/* Parse Objective-C method list and map implementations to method names */
int parse_objc_methods(int fd)
{
    if (context.objc_methlist_size == 0 || context.objc_methlist_offset == 0 ||
        context.objc_methname_size == 0 || context.objc_methname_offset == 0)
        return -1;
    
    /* For relative method lists, we also need __objc_selrefs section to dereference SELs */
    int have_selrefs = (context.objc_selrefs_size > 0 && context.objc_selrefs_offset > 0);
    
    /* Read method name section */
    char *methname_data = malloc(context.objc_methname_size);
    if (!methname_data)
        fatal("unable to allocate memory for objc_methname");
    
    off_t pos = lseek(fd, 0, SEEK_CUR);
    if (pos < 0)
        fatal("error seeking: %s", strerror(errno));
    
    int ret = lseek(fd, context.arch.offset + context.objc_methname_offset, SEEK_SET);
    if (ret < 0)
        fatal("error seeking to objc_methname: %s", strerror(errno));
    
    ret = _read(fd, methname_data, context.objc_methname_size);
    if (ret < 0)
        fatal_file(fd);
    
    /* Read selector references section if available */
    uint8_t *selrefs_data = NULL;
    if (have_selrefs) {
        selrefs_data = malloc(context.objc_selrefs_size);
        if (!selrefs_data)
            fatal("unable to allocate memory for objc_selrefs");
        
        ret = lseek(fd, context.arch.offset + context.objc_selrefs_offset, SEEK_SET);
        if (ret < 0)
            fatal("error seeking to objc_selrefs: %s", strerror(errno));
        
        ret = _read(fd, selrefs_data, context.objc_selrefs_size);
        if (ret < 0)
            fatal_file(fd);
    }
    
    /* Read method list section */
    uint8_t *methlist_data = malloc(context.objc_methlist_size);
    if (!methlist_data)
        fatal("unable to allocate memory for objc_methlist");
    
    ret = lseek(fd, context.arch.offset + context.objc_methlist_offset, SEEK_SET);
    if (ret < 0)
        fatal("error seeking to objc_methlist: %s", strerror(errno));
    
    ret = _read(fd, methlist_data, context.objc_methlist_size);
    if (ret < 0)
        fatal_file(fd);
    
    ret = lseek(fd, pos, SEEK_SET);
    if (ret < 0)
        fatal("error seeking back: %s", strerror(errno));
    
    /* Parse method_list_t structure */
    /* Format: uint32_t entsizeAndFlags, uint32_t count, then method_t entries */
    /* The __objc_methlist section may contain multiple method lists */
    uint8_t *p = methlist_data;
    uint8_t *end = methlist_data + context.objc_methlist_size;
    
    if (context.objc_methlist_size < OBJC_METHOD_LIST_HEADER_SIZE)
        goto cleanup;
    
    /* Allocate method array with reasonable initial size */
    context.objc_methods = malloc(sizeof(struct objc_method_t) * OBJC_METHOD_ARRAY_INITIAL_SIZE);
    if (!context.objc_methods)
        fatal("unable to allocate memory for objc_methods");
    
    context.objc_method_count = 0;
    
    /* Parse method lists until we run out of data */
    /* Note: __objc_methlist typically contains a single method_list_t structure */
    while (p + OBJC_METHOD_LIST_HEADER_SIZE <= end && context.objc_method_count < OBJC_METHOD_ARRAY_MAX_SIZE) {
        uint32_t entsizeAndFlags = *(uint32_t*)p;
        p += OBJC_METHOD_T_FIELD_SIZE;
        uint32_t count = *(uint32_t*)p;
        p += OBJC_METHOD_T_FIELD_SIZE;
        
        /* Extract entsize (mask out flags - low 2 bits are flags, high bit might also be a flag) */
        /* In some Objective-C runtime versions, the high bit indicates small method list format */
        uint32_t entsize = entsizeAndFlags & 0x7FFFFFFC; /* Mask out low 2 bits and high bit */
        
        if (debug && context.objc_method_count == 0) {
            fprintf(stderr, "\n=== Parsing Objective-C Method List ===\n");
            fprintf(stderr, "entsizeAndFlags: 0x%x, entsize: %u, count: %u\n", 
                    entsizeAndFlags, entsize, count);
        }
        
        /* Validate entsize and count */
        if (entsize == 0 || entsize > OBJC_METHOD_ENTSIZE_MAX || count == 0 || count > OBJC_METHOD_COUNT_MAX) {
            if (debug)
                fprintf(stderr, "Invalid method list (entsize=%u, count=%u), stopping\n", entsize, count);
            break; /* Stop parsing if we hit invalid data */
        }
        
        /* Check if we have enough space for this method list */
        if (p + (entsize * count) > end) {
            if (debug)
                fprintf(stderr, "Method list extends beyond section, truncating\n");
            break;
        }
        
        if (debug) {
            fprintf(stderr, "Parsing method list: %u methods, entsize=%u, remaining bytes=%zu\n",
                    count, entsize, (size_t)(end - p));
        }
        
        /* Parse each method entry in this method list */
        for (uint32_t i = 0; i < count; i++) {
            /* Check if we need to reallocate the method array */
            if (context.objc_method_count >= OBJC_METHOD_ARRAY_INITIAL_SIZE) {
                /* Reallocate with more space */
                struct objc_method_t *new_methods = realloc(context.objc_methods, 
                    sizeof(struct objc_method_t) * (context.objc_method_count + OBJC_METHOD_ARRAY_REALLOC_INCREMENT));
                if (!new_methods)
                    fatal("unable to reallocate memory for objc_methods");
                context.objc_methods = new_methods;
            }
            
            /* Check bounds */
            if (p + entsize > end) {
                if (debug)
                    fprintf(stderr, "Method entry %u extends beyond section, stopping\n", i);
                break;
            }
            
            Dwarf_Addr name_offset = 0;
            Dwarf_Addr imp_addr = 0;
            
            /* Parse method_t structure */
            /* Structure: name_offset (32-bit), types_offset (32-bit), imp (32-bit) */
            /* entsize=12 means: name(4) + types(4) + imp(4) = 12 bytes (all 32-bit, even imp on 64-bit!) */
            /* This is a "small" or "relative" method list format where offsets might be relative */
            if (entsize >= OBJC_METHOD_T_MIN_SIZE && p + entsize <= end) {
                /* Debug: dump raw bytes for first few methods */
                if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT) {
                    fprintf(stderr, "Method %u raw bytes: ", i);
                    for (int j = 0; j < OBJC_METHOD_T_MIN_SIZE && (p + j) < end; j++) {
                        fprintf(stderr, "%02x ", p[j]);
                    }
                    fprintf(stderr, "\n");
                    fprintf(stderr, "Method %u entry at offset 0x%lx from method list start\n", 
                            i, (unsigned long)(p - methlist_data));
                }
                
                /* Save pointer to start of this method entry for relative offset calculations */
                uint8_t *method_entry_start = p;
                Dwarf_Addr method_entry_addr = context.objc_methlist_addr + (method_entry_start - methlist_data);
                
                /* Read all three 32-bit fields */
                uint32_t name_field = *(uint32_t*)(p + OBJC_METHOD_T_NAME_OFFSET);
                /* types_field is at OBJC_METHOD_T_TYPES_OFFSET but we don't need it */
                uint32_t imp_field = *(uint32_t*)(p + OBJC_METHOD_T_IMP_OFFSET);
                
                /* Advance pointer to next method entry before processing (in case we continue early) */
                p += entsize;
                
                /* For "relative" method lists (entsize=12 on 64-bit), all offsets are signed
                 * and relative to the field's own address, not the section base.
                 * Structure: name_offset (relative), types_offset (relative), imp_offset (relative)
                 */
                
                /* Calculate absolute address for name field */
                int32_t signed_name_offset = (int32_t)name_field;
                Dwarf_Addr name_field_addr = method_entry_addr + OBJC_METHOD_T_NAME_OFFSET;
                Dwarf_Addr name_absolute_addr = name_field_addr + signed_name_offset;
                
                /* Calculate absolute address for imp field */
                int32_t signed_imp_offset = (int32_t)imp_field;
                Dwarf_Addr imp_field_addr = method_entry_addr + OBJC_METHOD_T_IMP_OFFSET;
                imp_addr = imp_field_addr + signed_imp_offset;
                
                if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT) {
                    fprintf(stderr, "Method %u: name_field_addr=0x%llx, signed_offset=%d, name_addr=0x%llx\n",
                            i, (unsigned long long)name_field_addr, signed_name_offset, 
                            (unsigned long long)name_absolute_addr);
                    fprintf(stderr, "Method %u: imp_field_addr=0x%llx, signed_offset=%d, imp_addr=0x%llx\n",
                            i, (unsigned long long)imp_field_addr, signed_imp_offset,
                            (unsigned long long)imp_addr);
                }
                
                /* Convert name_addr to method name */
                /* name_absolute_addr might point to:
                 * 1. Directly to a method name string in __objc_methname (unlikely in relative format)
                 * 2. To a SEL in __objc_selrefs, which contains a pointer to the name in __objc_methname
                 */
                
                if (name_absolute_addr >= context.objc_methname_addr && 
                    name_absolute_addr < context.objc_methname_addr + context.objc_methname_size) {
                    /* Direct pointer to method name in __objc_methname */
                    name_offset = name_absolute_addr - context.objc_methname_addr;
                    if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                        fprintf(stderr, "Method %u: Direct pointer to methname at offset 0x%llx\n",
                                i, (unsigned long long)name_offset);
                } else if (have_selrefs && 
                          name_absolute_addr >= context.objc_selrefs_addr && 
                          name_absolute_addr < context.objc_selrefs_addr + context.objc_selrefs_size) {
                    /* Pointer to a SEL in __objc_selrefs - need to dereference it */
                    Dwarf_Addr selref_offset = name_absolute_addr - context.objc_selrefs_addr;
                    
                    /* Read the SEL value (64-bit pointer on 64-bit architecture) */
                    if (selref_offset + OBJC_SEL_POINTER_SIZE <= context.objc_selrefs_size) {
                        uint64_t sel_ptr_raw = *(uint64_t*)(selrefs_data + selref_offset);
                        
                        /* On arm64e, pointers may have PAC (Pointer Authentication Code) in high bits */
                        /* Mask off the high bits to get the actual pointer */
                        /* Typically, only the low 48-52 bits are the actual address */
                        uint64_t sel_ptr_masked = sel_ptr_raw & 0x0000FFFFFFFFFFFFULL; /* Keep low 48 bits */
                        
                        /* The masked pointer might be:
                         * 1. An absolute address (if it's in the right range)
                         * 2. A relative offset from __TEXT segment base
                         */
                        uint64_t sel_ptr;
                        if (sel_ptr_masked >= context.intended_addr && sel_ptr_masked < context.intended_addr + OBJC_ADDRESS_RANGE_CHECK) {
                            /* Looks like an absolute address */
                            sel_ptr = sel_ptr_masked;
                        } else {
                            /* Treat as relative offset from __TEXT segment base */
                            sel_ptr = context.intended_addr + sel_ptr_masked;
                        }
                        
                        if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT) {
                            fprintf(stderr, "Method %u: SEL at 0x%llx contains pointer 0x%llx (raw: 0x%llx, masked: 0x%llx)\n",
                                    i, (unsigned long long)name_absolute_addr, 
                                    (unsigned long long)sel_ptr, (unsigned long long)sel_ptr_raw,
                                    (unsigned long long)sel_ptr_masked);
                        }
                        
                        /* Check if sel_ptr points into __objc_methname */
                        if (sel_ptr >= context.objc_methname_addr && 
                            sel_ptr < context.objc_methname_addr + context.objc_methname_size) {
                            name_offset = sel_ptr - context.objc_methname_addr;
                            if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                                fprintf(stderr, "Method %u: SUCCESS - SEL dereferenced to methname offset 0x%llx\n",
                                        i, (unsigned long long)name_offset);
                        } else {
                            /* SEL doesn't point to __objc_methname - skip this method */
                            if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                                fprintf(stderr, "Method %u: SEL pointer 0x%llx doesn't point to methname section (addr=0x%llx, size=0x%llx)\n",
                                        i, (unsigned long long)sel_ptr,
                                        (unsigned long long)context.objc_methname_addr,
                                        (unsigned long long)context.objc_methname_size);
                            continue;
                        }
                    } else {
                        if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                            fprintf(stderr, "Method %u: SEL offset 0x%llx out of bounds\n",
                                    i, (unsigned long long)selref_offset);
                        continue;
                    }
                } else {
                    /* name_absolute_addr doesn't point to either section - skip this method */
                    if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                        fprintf(stderr, "Method %u: name_addr 0x%llx doesn't point to valid section\n",
                                i, (unsigned long long)name_absolute_addr);
                    continue;
                }
                
                if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT) {
                    fprintf(stderr, "Method %u: name_offset=0x%llx, imp_addr=0x%llx, entsize=%u\n", 
                            i, (unsigned long long)name_offset, (unsigned long long)imp_addr, entsize);
                }
            } else {
                if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                    fprintf(stderr, "Skipping method %u: entsize=%u too small or out of bounds\n", i, entsize);
                p += entsize;
                continue;
            }
            
            /* Get method name from __objc_methname section */
            /* Check bounds - but allow slightly out-of-bounds to catch edge cases */
            if (name_offset < context.objc_methname_size + OBJC_METHNAME_BOUNDS_TOLERANCE) {
                /* Ensure we don't read past the end */
                size_t safe_offset = (name_offset < context.objc_methname_size) ? name_offset : context.objc_methname_size - 1;
                const char *method_name = (const char*)(methname_data + safe_offset);
                
                /* Validate that we have a valid null-terminated string */
                size_t max_len = context.objc_methname_size - safe_offset;
                if (max_len > 0 && method_name[0] != '\0') {
                    /* Check if string is null-terminated within bounds */
                    size_t len = strnlen(method_name, max_len);
                    if (len < max_len && len > 0) {
                        context.objc_methods[context.objc_method_count].name = strdup(method_name);
                        context.objc_methods[context.objc_method_count].imp_addr = imp_addr;
                        context.objc_method_count++;
                        
                        if (debug && i < OBJC_DEBUG_METHOD_OUTPUT_LIMIT) {
                            fprintf(stderr, "  Method %u: %s -> imp: 0x%llx (name_offset=0x%llx)\n",
                                    i, method_name, (unsigned long long)imp_addr, (unsigned long long)name_offset);
                        }
                    } else {
                        if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                            fprintf(stderr, "Method %u: invalid method name at offset 0x%llx (empty or not null-terminated)\n", 
                                    i, (unsigned long long)name_offset);
                    }
                } else {
                    if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                        fprintf(stderr, "Method %u: name_offset 0x%llx out of bounds (size=0x%llx)\n", 
                                i, (unsigned long long)name_offset, (unsigned long long)context.objc_methname_size);
                }
            } else {
                if (debug && i < OBJC_DEBUG_METHOD_DUMP_LIMIT)
                    fprintf(stderr, "Method %u: name_offset 0x%llx way out of bounds (size=0x%llx)\n", 
                            i, (unsigned long long)name_offset, (unsigned long long)context.objc_methname_size);
            }
        }
        
        /* After parsing all methods in this list, check if we should continue */
        /* Typically __objc_methlist contains only one method_list_t structure */
        /* If we've parsed methods successfully, we can break here */
        if (context.objc_method_count > 0) {
            /* We've successfully parsed at least one method list */
            /* Check if there's likely another method list after this one */
            if (p + OBJC_METHOD_LIST_HEADER_SIZE > end || (p + OBJC_METHOD_LIST_HEADER_SIZE <= end && *(uint32_t*)p == 0)) {
                /* No more data or next header looks invalid, stop parsing */
                if (debug)
                    fprintf(stderr, "Finished parsing method list, stopping (parsed %d methods)\n", 
                            context.objc_method_count);
                break;
            }
            /* Otherwise, continue to next method list */
        }
    }
    
    if (debug) {
        fprintf(stderr, "Parsed %d Objective-C methods\n", context.objc_method_count);
    }
    
    /* Sort methods by implementation address for efficient lookup */
    if (context.objc_method_count > 0) {
        qsort(context.objc_methods, context.objc_method_count, 
              sizeof(struct objc_method_t), compare_objc_methods);
    }
    
    if (selrefs_data)
        free(selrefs_data);
    free(methname_data);
    free(methlist_data);
    return 0;
    
cleanup:
    if (selrefs_data)
        free(selrefs_data);
    free(methname_data);
    free(methlist_data);
    return -1;
}


/* Find Objective-C method for given address */
static const struct objc_method_t *find_objc_method(Dwarf_Addr addr)
{
    if (context.objc_method_count == 0)
        return NULL;
    
    /* Binary search for the method */
    int left = 0;
    int right = context.objc_method_count - 1;
    const struct objc_method_t *best = NULL;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (context.objc_methods[mid].imp_addr <= addr) {
            best = &context.objc_methods[mid];
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    /* Return the best match found by binary search */
    /* Note: We don't verify offset ranges here because stripped binaries
     * may have large offsets, and we want to symbolicate them correctly */
    return best;
}

int  find_and_print_symtab_symbol(Dwarf_Addr slide, Dwarf_Addr addr)
{
    union {
        struct nlist_t nlist32;
        struct nlist_64 nlist64;
    } nlist;
    struct symbol_t *current;
    int found = 0;

    int i;
    int is_stab;
    uint8_t type;

    /* Store original address for potential error output */
    Dwarf_Addr original_addr = addr;

    if (debug) {
        fprintf(stderr, "\n=== Symbol Lookup Debug ===\n");
        fprintf(stderr, "Raw address: 0x%llx\n", (unsigned long long)addr);
        fprintf(stderr, "Slide: 0x%llx\n", (unsigned long long)slide);
        fprintf(stderr, "Intended address: 0x%llx\n", (unsigned long long)context.intended_addr);
        fprintf(stderr, "Load address: 0x%llx\n", (unsigned long long)options.load_address);
    }

    /* Check if original address is invalid (0) */
    if (original_addr == 0) {
        /* Invalid address - return no match so caller prints original address */
        return DW_DLV_NO_ENTRY;
    }

    /* Check if address is too small before slide adjustment (would wrap around) */
    if (original_addr < slide) {
        /* Invalid address - return no match so caller prints original address */
        return DW_DLV_NO_ENTRY;
    }

    addr = addr - slide;
    
    /* Check if address is invalid after slide adjustment (too small) */
    if (addr < context.intended_addr) {
        /* Invalid address - return no match so caller prints original address */
        return DW_DLV_NO_ENTRY;
    }
    
    /* First, check if this address matches an Objective-C method */
    const struct objc_method_t *objc_method = find_objc_method(addr);
    if (objc_method) {
        /* Validate that address is >= method implementation address */
        if (addr >= objc_method->imp_addr) {
            Dwarf_Addr offset = addr - objc_method->imp_addr;
            printf("%s (in %s) + %llu\n",
                    objc_method->name,
                    basename((char *)options.dsym_filename),
                    (unsigned long long)offset);
            if (debug) {
                fprintf(stderr, "=== Found Objective-C Method ===\n");
                fprintf(stderr, "Method: %s\n", objc_method->name);
                fprintf(stderr, "Implementation address: 0x%llx\n", 
                        (unsigned long long)objc_method->imp_addr);
                fprintf(stderr, "Search address: 0x%llx\n", (unsigned long long)addr);
                fprintf(stderr, "Offset: %llu (0x%llx)\n", 
                        (unsigned long long)offset, (unsigned long long)offset);
            }
            return 0;
        }
        /* If address is before method implementation, treat as no match and continue to symbol table lookup */
    }
    
    if (debug) {
        fprintf(stderr, "Adjusted address (after slide): 0x%llx\n", (unsigned long long)addr);
    }
    current = context.symlist;

    for (i = 0; i < context.nsymbols; i++) {

        memcpy(context.is_64 ? (void*)&nlist.nlist64 : (void*)&nlist.nlist32, context.is_64 ? (void*)&current->sym.sym64 : (void*)&current->sym.sym32, context.is_64 ? sizeof(current->sym.sym64) : sizeof(current->sym.sym32));
        current->thumb = ((context.is_64 ? nlist.nlist64.n_desc : nlist.nlist32.n_desc) & N_ARM_THUMB_DEF) ? 1 : 0;

        current->addr = context.is_64 ? nlist.nlist64.n_value : nlist.nlist32.n_value;
        type = context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type;
        current->n_type = type;
        current->n_sect = context.is_64 ? nlist.nlist64.n_sect : nlist.nlist32.n_sect;
        is_stab = type & N_STAB;
        if (debug) {
            fprintf(stderr, "\t\tname: %s\n", current->name);
            fprintf(stderr, "\t\tn_un.n_un.n_strx: %d\n", context.is_64 ? nlist.nlist64.n_un.n_strx : nlist.nlist32.n_un.n_strx);
            fprintf(stderr, "\t\traw n_type: 0x%x\n", context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type);
            fprintf(stderr, "\t\tn_type: ");
            if (is_stab)
                fprintf(stderr, "N_STAB ");
            if ((context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type) & N_PEXT)
                fprintf(stderr, "N_PEXT ");
            if ((context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type) & N_EXT)
                fprintf(stderr, "N_EXT ");
            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tType: ");
            switch (type & N_TYPE) {
                case 0: fprintf(stderr, "U "); break;
                case N_ABS: fprintf(stderr, "A "); break;
                case N_SECT: fprintf(stderr, "S "); break;
                case N_INDR: fprintf(stderr, "I "); break;
            }

            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tn_sect: %d\n", context.is_64 ? nlist.nlist64.n_sect : nlist.nlist32.n_sect);
            fprintf(stderr, "\t\tn_desc: %d\n", context.is_64 ? nlist.nlist64.n_desc : nlist.nlist32.n_desc);
            fprintf(stderr, "\t\tn_value: 0x%llx\n", (unsigned long long)(context.is_64 ? nlist.nlist64.n_value : nlist.nlist32.n_value));
            fprintf(stderr, "\t\taddr: 0x%llx\n", current->addr);
        }

        if (handle_stabs_symbol(is_stab && type == N_FUN, addr, current))
            return DW_DLV_OK;

        current++;

        if (debug)
            fprintf(stderr, "\n");
    }

    qsort(context.symlist, context.nsymbols, sizeof(*current), compare_symbols);
    
    /* Debug: Print all valid section symbols (functions) with their addresses */
    if (debug) {
        fprintf(stderr, "\n=== All valid section symbols (functions) ===\n");
        fprintf(stderr, "Search address: 0x%llx (after slide: 0x%llx)\n", 
                (unsigned long long)(addr + slide), (unsigned long long)addr);
        fprintf(stderr, "Total symbols: %d\n", context.nsymbols);
        int valid_count = 0;
        for (i = 0; i < context.nsymbols; i++) {
            current = &context.symlist[i];
            uint8_t sym_type = current->n_type & N_TYPE;
            int is_stab = current->n_type & N_STAB;
            
            if (!is_stab && sym_type == N_SECT && current->n_sect != 0) {
                valid_count++;
                fprintf(stderr, "[%d] 0x%llx: %s (sect=%d, type=0x%02x)\n",
                        valid_count,
                        (unsigned long long)current->addr,
                        current->name ? current->name : "(null)",
                        current->n_sect,
                        current->n_type);
            }
        }
        fprintf(stderr, "Total valid section symbols: %d\n\n", valid_count);
    }
    
    /* Use binary search to find the right symbol */
    /* We want the symbol with the highest address that is <= our search address */
    struct symbol_t *best_match = NULL;
    Dwarf_Addr best_addr = 0;
    
    /* Binary search for the insertion point */
    int left = 0;
    int right = context.nsymbols - 1;
    int pos = -1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (context.symlist[mid].addr <= addr) {
            pos = mid;
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    /* Now search backwards from pos to find the best valid symbol */
    /* We want the closest valid section symbol that is <= our address */
    if (pos >= 0) {
        for (i = pos; i >= 0; i--) {
            current = &context.symlist[i];
            
            /* Only consider section symbols (N_SECT), skip stabs and undefined symbols */
            uint8_t sym_type = current->n_type & N_TYPE;
            int is_stab = current->n_type & N_STAB;
            
            /* Skip if it's a stab, not a section symbol, or has invalid section */
            if (is_stab || sym_type != N_SECT || current->n_sect == 0) {
                continue;
            }
            
            /* We know current->addr <= addr from binary search, so this is valid */
            /* Take the first (highest address) valid symbol we find */
            best_match = current;
            best_addr = current->addr;
            break; /* Found the best match, stop searching */
        }
    }
    
    if (best_match) {
        /* Check if there's a next symbol to see the range */
        Dwarf_Addr next_addr = 0;
        int has_next = 0;
        if (pos >= 0 && pos + 1 < context.nsymbols) {
            for (i = pos + 1; i < context.nsymbols; i++) {
                current = &context.symlist[i];
                uint8_t sym_type = current->n_type & N_TYPE;
                int is_stab = current->n_type & N_STAB;
                if (!is_stab && sym_type == N_SECT && current->n_sect != 0) {
                    next_addr = current->addr;
                    has_next = 1;
                    break;
                }
            }
        }
        
        if (debug) {
            fprintf(stderr, "=== Symbol Match Result ===\n");
            fprintf(stderr, "Found symbol: %s\n", best_match->name);
            fprintf(stderr, "Symbol address: 0x%llx\n", (unsigned long long)best_addr);
            if (has_next) {
                fprintf(stderr, "Next symbol address: 0x%llx (gap: 0x%llx)\n",
                        (unsigned long long)next_addr,
                        (unsigned long long)(next_addr - best_addr));
            }
            fprintf(stderr, "Search address: 0x%llx (raw: 0x%llx)\n", 
                    (unsigned long long)addr, (unsigned long long)(addr + slide));
            fprintf(stderr, "Offset: %llu (0x%llx)\n", 
                    (unsigned long long)(addr - best_addr),
                    (unsigned long long)(addr - best_addr));
            fprintf(stderr, "Section: %d, Type: 0x%02x\n", best_match->n_sect, best_match->n_type);
            
        }
        
        
        if (debug) {
            /* Show nearby symbols for context */
            fprintf(stderr, "\n=== Nearby symbols (for context) ===\n");
            int start_idx = (pos > OBJC_DEBUG_NEARBY_SYMBOLS_WINDOW) ? pos - OBJC_DEBUG_NEARBY_SYMBOLS_WINDOW : 0;
            int end_idx = (pos + OBJC_DEBUG_NEARBY_SYMBOLS_WINDOW < context.nsymbols) ? pos + OBJC_DEBUG_NEARBY_SYMBOLS_WINDOW : context.nsymbols - 1;
            for (i = start_idx; i <= end_idx; i++) {
                current = &context.symlist[i];
                uint8_t sym_type = current->n_type & N_TYPE;
                int is_stab = current->n_type & N_STAB;
                const char *marker = (current == best_match) ? " <-- MATCH" : "";
                
                if (!is_stab && sym_type == N_SECT && current->n_sect != 0) {
                    fprintf(stderr, "  0x%llx: %s%s\n",
                            (unsigned long long)current->addr,
                            current->name ? current->name : "(null)",
                            marker);
                }
            }
            fprintf(stderr, "\n");
        }
        print_symbol(best_match->name, (unsigned int)(addr - best_addr));
        found = 1;
    } else if (debug) {
        fprintf(stderr, "=== No Symbol Match ===\n");
        fprintf(stderr, "No matching symbol found for address 0x%llx (raw: 0x%llx)\n", 
                (unsigned long long)addr, (unsigned long long)(addr + slide));
        fprintf(stderr, "Searched %d symbols, binary search pos=%d\n", context.nsymbols, pos);
        if (pos >= 0 && pos < context.nsymbols) {
            fprintf(stderr, "Symbol at pos: 0x%llx (%s)\n",
                    (unsigned long long)context.symlist[pos].addr,
                    context.symlist[pos].name ? context.symlist[pos].name : "(null)");
        }
    }

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int parse_command(
    dwarf_mach_object_access_internals_t *obj,
    struct load_command_t load_command)
{
    int ret = 0;
    int cmdsize;

    switch (load_command.cmd) {
        case LC_UUID:
            ret = parse_uuid(obj, load_command.cmdsize);
            break;
        case LC_SEGMENT:
            ret = parse_segment(obj, load_command.cmdsize);
            break;
        case LC_SEGMENT_64:
            ret = parse_segment_64(obj, load_command.cmdsize);
            break;
        case LC_SYMTAB:
            ret = parse_symtab(obj, load_command.cmdsize);
            break;
        default:
            if (debug)
                fprintf(stderr, "Warning: unhandled command: 0x%x\n",
                                load_command.cmd);
            /* Fallthrough */
        case LC_PREPAGE:
            cmdsize = load_command.cmdsize - sizeof(load_command);
            ret = lseek(obj->handle, cmdsize, SEEK_CUR);
            if (ret < 0)
                fatal("error seeking: %s", strerror(errno));
            break;
    }

    return ret;
}

static int dwarf_mach_object_access_internals_init(
        dwarf_mach_handle handle,
        void *obj_in,
        int *error)
{
    int ret;
    struct mach_header_t header;
    struct load_command_t load_command;
    int i;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    obj->handle = handle;
    obj->length_size = 4;
    obj->pointer_size = 4;
    obj->endianness = DW_OBJECT_LSB;
    obj->sections = NULL;
    obj->sections_64 = NULL;

    ret = _read(obj->handle, &header, sizeof(header));
    if (ret < 0)
        fatal_file(ret);
    // mask cpusubtype
    header.cpusubtype &= ~CPU_SUBTYPE_MASK;
    /* Need to skip 4 bytes of the reserved field of mach_header_64  */
    if (header.cputype == CPU_TYPE_ARM64 && (header.cpusubtype == CPU_SUBTYPE_ARM64_ALL || header.cpusubtype == CPU_SUBTYPE_ARM64E)) {
        context.is_64 = 1;
        ret = lseek(obj->handle, sizeof(uint32_t), SEEK_CUR);
        if (ret < 0)
            fatal_file(ret);
    }

    if (debug) {
        fprintf(stderr, "Mach Header:\n");
        fprintf(stderr, "\tCPU Type: %d\n", header.cputype);
        fprintf(stderr, "\tCPU Subtype: %d\n", header.cpusubtype);
        fprintf(stderr, "\tFiletype: %d\n", header.filetype);
        fprintf(stderr, "\tNumber of Cmds: %d\n", header.ncmds);
        fprintf(stderr, "\tSize of commands: %d\n", header.sizeofcmds);
        fprintf(stderr, "\tFlags: %.08x\n", header.flags);
    }

    switch (header.filetype) {
        case MH_DSYM:
            if (debug)
                fprintf(stderr, "File type: debug file\n");
            break;
        case MH_DYLIB:
            if (debug)
                fprintf(stderr, "File type: dynamic library\n");
            break;
        case MH_DYLIB_STUB:
            if (debug)
                fprintf(stderr, "File type: dynamic library stub\n");
            break;
        case MH_EXECUTE:
            if (debug)
                fprintf(stderr, "File type: executable file\n");
            break;
        case MH_DYLINKER:
            if (debug)
                fprintf(stderr, "File type: dyld file\n");
            break;
        case MH_FILESET:
            if (debug)
                fprintf(stderr, "File type: file set\n");
            break;
        default:
            fatal("unsupported file type: 0x%x", header.filetype);
            assert(0);
    }

    for (i = 0; i < header.ncmds; i++) {
        ret = _read(obj->handle, &load_command, sizeof(load_command));
        if (ret < 0)
            fatal_file(ret);

        if (debug) {
            fprintf(stderr, "Load Command %d\n", i);
            fprintf(stderr, "%10s %x\n", "cmd", load_command.cmd);
            fprintf(stderr, "%10s %d\n", "cmdsize", load_command.cmdsize);
        }

        ret = parse_command(obj, load_command);
        if (ret < 0)
            fatal("unable to parse command %x", load_command.cmd);
    }

    return DW_DLV_OK;
}

static Dwarf_Endianness dwarf_mach_object_access_get_byte_order(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->endianness;
}

static Dwarf_Unsigned dwarf_mach_object_access_get_section_count(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->section_count;
}

static int dwarf_mach_object_access_get_section_info(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Obj_Access_Section *ret_scn,
        int *error)
{
    int i;
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    if (section_index >= obj->section_count) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }
    
    if (obj->sections_64) {
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
    } else {
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
    }
    if (strcmp(ret_scn->name, ".debug_pubnames__DWARF") == 0)
        ret_scn->name = ".debug_pubnames";

    ret_scn->link = 0; /* rela section or from symtab to strtab */
    ret_scn->entrysize = 0;

    return DW_DLV_OK;
}

static int dwarf_mach_object_access_load_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Small **section_data,
        int *error)
{
    void *addr;
    int i;
    int ret;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    if (section_index >= obj->section_count) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    if (obj->sections_64) {
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        addr = malloc(sec->mach_section.size);
        if (!addr)
            fatal("unable to allocate memory");
        ret = lseek(obj->handle, context.arch.offset + sec->mach_section.offset, SEEK_SET);
        if (ret < 0)
            fatal("error seeking: %s", strerror(errno));
        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0)
            fatal_file(ret);

    } else {
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        addr = malloc(sec->mach_section.size);
        if (!addr)
            fatal("unable to allocate memory");
        ret = lseek(obj->handle, context.arch.offset + sec->mach_section.offset, SEEK_SET);
        if (ret < 0)
            fatal("error seeking: %s", strerror(errno));
        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0)
            fatal_file(ret);
        
    }
    *section_data = addr;

    return DW_DLV_OK;
}

static int dwarf_mach_object_relocate_a_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Debug dbg,
        int *error)
{
    return DW_DLV_NO_ENTRY;
}

static Dwarf_Small dwarf_mach_object_access_get_length_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->length_size;
}

static Dwarf_Small dwarf_mach_object_access_get_pointer_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->pointer_size;
}

static const struct Dwarf_Obj_Access_Methods_s
  dwarf_mach_object_access_methods = {
    dwarf_mach_object_access_get_section_info,
    dwarf_mach_object_access_get_byte_order,
    dwarf_mach_object_access_get_length_size,
    dwarf_mach_object_access_get_pointer_size,
    dwarf_mach_object_access_get_section_count,
    dwarf_mach_object_access_load_section,
    dwarf_mach_object_relocate_a_section
};


void dwarf_mach_object_access_init(
        dwarf_mach_handle handle,
        Dwarf_Obj_Access_Interface **ret_obj,
        int *err)
{
    int res = 0;
    dwarf_mach_object_access_internals_t *internals = NULL;
    Dwarf_Obj_Access_Interface *intfc = NULL;

    internals = malloc(sizeof(*internals));
    if (!internals)
        fatal("unable to allocate memory");

    memset(internals, 0, sizeof(*internals));
    res = dwarf_mach_object_access_internals_init(handle, internals, err);
    if (res != DW_DLV_OK)
        fatal("error initializing dwarf internals");

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc)
        fatal("unable to allocate memory");

    intfc->object = internals;
    intfc->methods = &dwarf_mach_object_access_methods;

    *ret_obj = intfc;
}

void dwarf_mach_object_access_finish(Dwarf_Obj_Access_Interface *obj)
{
    if (!obj)
        return;

    if (obj->object)
        free(obj->object);
    free(obj);
}

struct dwarf_subprogram_t *lookup_symbol(Dwarf_Addr addr)
{
    struct dwarf_subprogram_t *subprogram = context.subprograms;

    while (subprogram) {
        if ((addr >= subprogram->lowpc) &&
            (addr < subprogram->highpc)) {
            return subprogram;
        }

        subprogram = subprogram->next;
    }

    return NULL;
}

int print_subprogram_symbol(Dwarf_Addr slide, Dwarf_Addr addr)
{
    char *demangled = NULL;

    addr -= slide;

    struct dwarf_subprogram_t *match = lookup_symbol(addr);

    if (match) {
        demangled = options.should_demangle ? demangle(match->name) : NULL;
        printf("%s (in %s) + %d\n",
               demangled ?: match->name,
               basename((char *)options.dsym_filename),
               (unsigned int)(addr - match->lowpc));
        if (demangled)
            free(demangled);

    }

    return match ? 0 : -1;
}

int print_dwarf_symbol(Dwarf_Debug dbg, Dwarf_Addr slide, Dwarf_Addr addr)
{
    static Dwarf_Arange *arange_buf = NULL;
    Dwarf_Line *linebuf = NULL;
    Dwarf_Signed linecount = 0;
    Dwarf_Off cu_die_offset = 0;
    Dwarf_Die cu_die = NULL;
    Dwarf_Unsigned segment = 0;
    Dwarf_Unsigned segment_entry_size = 0;
    Dwarf_Addr start = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Arange arange;
    static Dwarf_Signed count;
    int ret;
    Dwarf_Error err;
    int i;
    int found = 0;

    addr -= slide;

    if (!arange_buf) {
        ret = dwarf_get_aranges(dbg, &arange_buf, &count, &err);
        DWARF_ASSERT(ret, err);
    }

    ret = dwarf_get_arange(arange_buf, count, addr, &arange, &err);
    DWARF_ASSERT(ret, err);

    if (ret == DW_DLV_NO_ENTRY)
        return ret;
    /*printf("arange=0x%llx, segment=0x%llx, segment_entry_size0x%llx, start=0x%llx, length=0x%llx, cu_die_offset=0x%llx, err=0x%llx\n",
            arange,
            &segment,
            &segment_entry_size,
            &start,
            &length,
            &cu_die_offset,
            &err);*/
    ret = dwarf_get_arange_info_b(
            arange,
            &segment,
            &segment_entry_size,
            &start,
            &length,
            &cu_die_offset,
            &err);
    DWARF_ASSERT(ret, err);

    ret = dwarf_offdie(dbg, cu_die_offset, &cu_die, &err);
    DWARF_ASSERT(ret, err);

    /* ret = dwarf_print_lines(cu_die, &err, &errcnt); */
    /* DWARF_ASSERT(ret, err); */

    ret = dwarf_srclines(cu_die, &linebuf, &linecount, &err);
    DWARF_ASSERT(ret, err);

    for (i = 0; i < linecount; i++) {
        Dwarf_Line prevline;
        Dwarf_Line nextline;
        Dwarf_Line line = linebuf[i];

        Dwarf_Addr lineaddr;
        Dwarf_Addr lowaddr;
        Dwarf_Addr highaddr;

        ret = dwarf_lineaddr(line, &lineaddr, &err);
        DWARF_ASSERT(ret, err);

        if (i > 0) {
            prevline = linebuf[i-1];
            ret = dwarf_lineaddr(prevline, &lowaddr, &err);
            DWARF_ASSERT(ret, err);
            lowaddr += 1;
        } else {
            lowaddr = lineaddr;
        }

        if (i < linecount - 1) {
            nextline = linebuf[i+1];
            ret = dwarf_lineaddr(nextline, &highaddr, &err);
            DWARF_ASSERT(ret, err);
            highaddr -= 1;
        } else {
            highaddr = lineaddr;
        }

        if ((addr >= lowaddr) && (addr <= highaddr)) {
            char *filename;
            Dwarf_Unsigned lineno;
            char *diename;
            char *demangled;
            struct dwarf_subprogram_t *symbol;
            const char *name;

            ret = dwarf_linesrc(line, &filename, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_lineno(line, &lineno, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_diename(cu_die, &diename, &err);
            DWARF_ASSERT(ret, err);

            symbol = lookup_symbol(addr);

            name = symbol ? symbol->name : "(unknown)";

            demangled = options.should_demangle ? demangle(name) : NULL;

            printf("%s (in %s) (%s:%d)\n",
                   demangled ? demangled : name,
                   basename((char *)options.dsym_filename),
                   basename(filename), (int)lineno);

            found = 1;

            if (demangled)
                free(demangled);

            dwarf_dealloc(dbg, diename, DW_DLA_STRING);
            dwarf_dealloc(dbg, filename, DW_DLA_STRING);

            break;
        }
    }

    dwarf_dealloc(dbg, arange, DW_DLA_ARANGE);
    dwarf_srclines_dealloc(dbg, linebuf, linecount);

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int main(int argc, char *argv[]) {
    if (debug) {
        fprintf(stderr, "=== ATOSL STARTING - VERSION WITH OBJC DEBUG ===\n");
        fflush(stderr);
    }
    
    int fd;
    int ret;
    int i;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error err;
    int derr = 0;
    Dwarf_Obj_Access_Interface *binary_interface = NULL;
    Dwarf_Ptr errarg = NULL;
    int option_index;
    int c;
    int found = 0;
    uint32_t magic;
    cpu_type_t cpu_type = -1;
    cpu_subtype_t cpu_subtype = -1;
    Dwarf_Addr address;

    memset(&context, 0, sizeof(context));

    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index))
            >= 0) {
        switch (c) {
            case 'l':
                errno = 0;
                address = strtoull(optarg, (char **)NULL, 16);
                if (errno != 0)
                    fatal("invalid load address: `%s': %s", optarg, strerror(errno));
                options.load_address = address;
                break;
            case 'o':
                options.dsym_filename = optarg;
                break;
            case 'A':
                for (i = 0; i < NUMOF(arch_str_to_type); i++) {
                    if (strcmp(arch_str_to_type[i].name, optarg) == 0) {
                        cpu_type = arch_str_to_type[i].type;
                        cpu_subtype = arch_str_to_type[i].subtype;
                        break;
                    }
                }
                if ((cpu_type < 0) && (cpu_subtype < 0))
                    fatal("unsupported architecture `%s'", optarg);
                options.cpu_type = cpu_type;
                options.cpu_subtype = cpu_subtype;
                break;
            case 'v':
                debug = 1;
                break;
            case 'g':
                options.use_globals = 1;
                break;
            case 'c':
                options.use_cache = 0;
                break;
            case 'C':
                options.cache_dir = optarg;
                break;
            case 'D':
                options.should_demangle = 0;
                break;
            case 'V':
                fprintf(stderr, "atosl %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case '?':
                print_help();
                exit(EXIT_FAILURE);
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            default:
                fatal("unhandled option");
        }
    }

    if (!options.dsym_filename)
        fatal("no filename specified with -o");

    fd = open(options.dsym_filename, O_RDONLY);
    if (fd < 0)
        fatal("unable to open `%s': %s",
              options.dsym_filename,
              strerror(errno));

    ret = _read(fd, &magic, sizeof(magic));
    if (ret < 0)
        fatal_file(fd);

    if (magic == FAT_CIGAM) {
        /* Find the architecture we want.. */
        uint32_t nfat_arch;

        ret = _read(fd, &nfat_arch, sizeof(nfat_arch));
        if (ret < 0)
            fatal_file(fd);

        nfat_arch = ntohl(nfat_arch);
        for (i = 0; i < nfat_arch; i++) {
            ret = _read(fd, &context.arch, sizeof(context.arch));
            if (ret < 0)
                fatal("unable to read arch struct");

            context.arch.cputype = ntohl(context.arch.cputype);
            context.arch.cpusubtype = ntohl(context.arch.cpusubtype) & ~CPU_SUBTYPE_MASK;
            context.arch.offset = ntohl(context.arch.offset);

            if ((context.arch.cputype == options.cpu_type) &&
                (context.arch.cpusubtype == options.cpu_subtype)) {
                /* good! */
                ret = lseek(fd, context.arch.offset, SEEK_SET);
                if (ret < 0)
                    fatal("unable to seek to arch (offset=%ld): %s",
                          context.arch.offset, strerror(errno));

                ret = _read(fd, &magic, sizeof(magic));
                if (ret < 0)
                    fatal_file(fd);

                found = 1;
                break;
            } else {
                /* skip */
                if (debug) {
                    fprintf(stderr, "Skipping arch: %x %x\n",
                            context.arch.cputype, context.arch.cpusubtype);
                }
            }
        }
    } else {
        found = 1;
    }

    if (!found)
        fatal("no valid architectures found");

    if (magic != MH_MAGIC && magic != MH_MAGIC_64)
      fatal("invalid magic for architecture");

    if (argc <= optind)
        fatal_usage("no addresses specified");


    
    dwarf_mach_object_access_init(fd, &binary_interface, &derr);
    assert(binary_interface);
    

    

    
    /* Parse Objective-C methods and sort by address for symbolication */
    parse_objc_methods(fd);
    if (debug && context.objc_method_count > 0) {
        fprintf(stderr, "Loaded %d Objective-C methods for symbolication\n", 
                context.objc_method_count);
    }

    if (options.load_address == LONG_MAX)
        options.load_address = context.intended_addr;

    ret = dwarf_object_init(binary_interface,
                            dwarf_error_handler,
                            errarg, &dbg, &err);
    DWARF_ASSERT(ret, err);

    /* If there is dwarf info we'll use that to parse, otherwise we'll use the
     * symbol table */
    //do not use dwarf
    if (context.is_dwarf && ret == DW_DLV_OK) {

        struct subprograms_options_t opts = {
            .persistent = options.use_cache,
            .cache_dir = options.cache_dir,
        };

        context.subprograms =
            subprograms_load(dbg,
                             context.uuid,
                             options.use_globals ? SUBPROGRAMS_GLOBALS :
                                                   SUBPROGRAMS_CUS,
                             &opts);

        for (i = optind; i < argc; i++) {
            Dwarf_Addr addr;
            errno = 0;
            addr = strtoull(argv[i], (char **)NULL, 16);
            if (errno != 0)
                fatal("invalid address: `%s': %s", argv[i], strerror(errno));
            ret = print_dwarf_symbol(dbg,
                                 options.load_address - context.intended_addr,
                                 addr);
            if (ret != DW_DLV_OK) {
                //derr = print_subprogram_symbol(
                derr = find_and_print_symtab_symbol(
                    options.load_address - context.intended_addr, addr);
            }

            if ((ret != DW_DLV_OK) && derr) {
                printf("%s\n", argv[i]);
            }
        }

        dwarf_mach_object_access_finish(binary_interface);

        ret = dwarf_object_finish(dbg, &err);
        DWARF_ASSERT(ret, err);
    } else {
        for (i = optind; i < argc; i++) {
            Dwarf_Addr addr;
            errno = 0;
            addr = strtoull(argv[i], (char **)NULL, 16);
            if (errno != 0)
                fatal("invalid address address: `%s': %s", optarg, strerror(errno));
            ret = find_and_print_symtab_symbol(
                    options.load_address - context.intended_addr,
                    addr);

            if (ret != DW_DLV_OK)
                printf("%s\n", argv[i]);
        }
    }

    close(fd);

    return 0;
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */

