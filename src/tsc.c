/* expose POSIX functions like getline()/fdopen() */
#define _POSIX_C_SOURCE 200809L
/**==============================================
 *                tsc.c
 *  TheShowLang minimal compiler to ELF64
 *  Author: shirosaaki
 *  Date: 2025-10-23
 *=============================================**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int has_paul = 0;
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* fallback strdup for strict compilation environments */
static char *my_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

/* temporary holder for string returns from functions executed at compile-time */
static char *g_last_return_str = NULL;
/* flag set when the last nested compile-time call produced a string return that was written
    into the caller table (so the caller should not overwrite it with an integer). */
static int g_last_return_was_str = 0;

// Helper to write little-endian integers
static void write_u64(FILE *f, unsigned long v) {
    for (int i = 0; i < 8; ++i) putc((v >> (i*8)) & 0xff, f);
}
static void write_u32(FILE *f, unsigned int v) {
    for (int i = 0; i < 4; ++i) putc((v >> (i*8)) & 0xff, f);
}
static void write_u16(FILE *f, unsigned short v) {
    putc(v & 0xff, f);
    putc((v>>8) & 0xff, f);
}

/* Error reporting helper: prints message to stderr and exits with code 1 */
static void errorf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

// Very small parser: extract the first string inside peric("...")
// and the integer after deschodt
static char *extract_peric_string(const char *src) {
    const char *p = strstr(src, "peric(");
    if (!p) return NULL;
    p = strchr(p, '"');
    if (!p) return NULL;
    ++p;
    const char *q = strchr(p, '"');
    if (!q) return NULL;
    size_t len = q - p;
    char *out = malloc(len + 1);
    memcpy(out, p, len);
    out[len] = '\0';
    return out;
}
static int extract_deschodt_int(const char *src, int default_ret) {
    const char *p = strstr(src, "deschodt");
    if (!p) return default_ret;
    p += strlen("deschodt");
    while (*p && (*p==' ' || *p=='\t')) ++p;
    if (!*p || *p=='\n') return default_ret; // no value
    return atoi(p);
}

// Emit a minimal ELF64 file with one PT_LOAD segment and executable code.
int emit_elf(const char *out_path, const char **msgs, unsigned int *msg_lens, int n_msgs, int retcode) {
    FILE *f = fopen(out_path, "wb");
    if (!f) { perror("fopen"); return 1; }
    if (!f) { perror("fopen"); return 1; }

    // We'll place the ELF header and program header at start and
    // put .text at file offset 0x200 (512) for alignment.
    const unsigned long phoff = 0x40; // right after ELF header
    const unsigned long text_off = 0x200;
    const unsigned long entry = 0x400000 + text_off; // typical base

    // Build simple machine code that does:
    //   mov rax, 1          ; syscall write
    //   mov rdi, 1          ; fd=1
    //   lea rsi, [rip+msg]  ; pointer to message
    //   mov rdx, len        ; length
    //   syscall
    //   mov rax, 60         ; syscall exit
    //   mov rdi, retcode
    //   syscall
    // Then message bytes follow.

    unsigned int total_msg_bytes = 0;
    for (int i = 0; i < n_msgs; ++i) total_msg_bytes += msg_lens[i];

    /* Build machine code into a buffer with zeroed displacement placeholders
       for each message, then patch them after we know final code size. */
    unsigned char final_code[1500];
    size_t fi = 0;

    // mov rax,1
    final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc0; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
    // mov rdi,1
    final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc7; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;

    // For each message, emit: lea rsi,[rip+disp] ; mov rdx,len ; syscall
    // Track where each displacement should be patched and next_instr offsets.
    int *disp_positions = malloc(sizeof(int) * n_msgs);
    int *next_instr_offsets = malloc(sizeof(int) * n_msgs);
    unsigned long *msg_offsets_within_messages = malloc(sizeof(unsigned long) * n_msgs);
    unsigned long cum_msg = 0;
    // We'll also reserve placeholders for a runtime buffer if needed and
    // record their positions so we can patch the final buffer address
    // after the full code size is known.
    int buffer_disp_pos = -1;
    int buffer_disp_pos2 = -1;

    // If the program will perform a runtime paul/read, emit the read
    // syscall sequence BEFORE the message-printing loop so the binary
    // blocks for input prior to printing the peric messages.
    if (has_paul) {
        // mov rax, 0 (syscall read)
        final_code[fi++] = 0x48; final_code[fi++] = 0xb8; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
        // mov rdi, 0 (fd=0)
        final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc7; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
        // mov rsi, buffer_addr (placeholder)
        final_code[fi++] = 0x48; final_code[fi++] = 0xbe;
        buffer_disp_pos = fi;
        final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0;
        // mov rdx, 1024
        final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc2; final_code[fi++] = 0x00; final_code[fi++] = 0x04; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
        // syscall (read)
        final_code[fi++] = 0x0f; final_code[fi++] = 0x05;
        // mov rdx, rax (use bytes read)
        final_code[fi++] = 0x48; final_code[fi++] = 0x89; final_code[fi++] = 0xc2;
        // mov rax, 1 (write)
        final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc0; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
        // mov rdi, 1 (stdout)
        final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc7; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
        // mov rsi, buffer_addr (placeholder) for write
        final_code[fi++] = 0x48; final_code[fi++] = 0xbe;
        buffer_disp_pos2 = fi;
        final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0;
        // syscall (write)
        final_code[fi++] = 0x0f; final_code[fi++] = 0x05;
        // Note: we DO NOT patch buffer_addr here; we'll patch after full code size is known.
    }

    for (int i = 0; i < n_msgs; ++i) {
        // lea rsi,[rip+disp]
        final_code[fi++] = 0x48; final_code[fi++] = 0x8d; final_code[fi++] = 0x35;
        disp_positions[i] = fi;
        final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; // placeholder
        // next instruction offset (relative to code start) is right after the 4-byte disp
        next_instr_offsets[i] = (int)(disp_positions[i] + 4);
        // mov rdx, len
        final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc2;
        unsigned int L = msg_lens[i];
        final_code[fi++] = (unsigned char)(L & 0xff);
        final_code[fi++] = (unsigned char)((L>>8)&0xff);
        final_code[fi++] = (unsigned char)((L>>16)&0xff);
        final_code[fi++] = (unsigned char)((L>>24)&0xff);
    // mov eax,1 (syscall number for write) - ensure each syscall uses SYS_write
    final_code[fi++] = 0xb8; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
    // syscall
    final_code[fi++] = 0x0f; final_code[fi++] = 0x05;
        msg_offsets_within_messages[i] = cum_msg;
        cum_msg += msg_lens[i];
    }

    /* buffer placeholders will be patched below after we know final code size */

    // After printing messages, do exit syscall with retcode
    // mov eax,60 (syscall number for exit)
    final_code[fi++] = 0xb8; final_code[fi++] = 0x3c; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
    // mov rdi,retcode
    final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc7;
    final_code[fi++] = (unsigned char)(retcode & 0xff);
    final_code[fi++] = (unsigned char)((retcode>>8)&0xff);
    final_code[fi++] = (unsigned char)((retcode>>16)&0xff);
    final_code[fi++] = (unsigned char)((retcode>>24)&0xff);
    // syscall
    final_code[fi++] = 0x0f; final_code[fi++] = 0x05;

    /* Compute displacements and patch placeholders. The message i will
       be placed at file offset: text_off + fi + sum(prev msg lens)
       The lea's next instruction virtual offset is next_instr_offsets[i]
       relative to start of code. So disp = (code_size + sum_prev) - next_instr_offset
    */
    for (int i = 0; i < n_msgs; ++i) {
        unsigned long sum_prev = msg_offsets_within_messages[i];
        long disp_val = (long)(fi + sum_prev) - (long)next_instr_offsets[i];
        int pos = disp_positions[i];
        final_code[pos + 0] = (unsigned char)(disp_val & 0xff);
        final_code[pos + 1] = (unsigned char)((disp_val>>8)&0xff);
        final_code[pos + 2] = (unsigned char)((disp_val>>16)&0xff);
        final_code[pos + 3] = (unsigned char)((disp_val>>24)&0xff);
    }

    /* Now patch buffer placeholders (if any) so they point to the buffer
       area which will be placed after the code and all message bytes. */
    if (buffer_disp_pos != -1 || buffer_disp_pos2 != -1) {
        unsigned long buffer_addr = entry + fi + total_msg_bytes;
        if (buffer_disp_pos != -1) {
            final_code[buffer_disp_pos + 0] = (unsigned char)(buffer_addr & 0xff);
            final_code[buffer_disp_pos + 1] = (unsigned char)((buffer_addr>>8)&0xff);
            final_code[buffer_disp_pos + 2] = (unsigned char)((buffer_addr>>16)&0xff);
            final_code[buffer_disp_pos + 3] = (unsigned char)((buffer_addr>>24)&0xff);
            final_code[buffer_disp_pos + 4] = (unsigned char)((buffer_addr>>32)&0xff);
            final_code[buffer_disp_pos + 5] = (unsigned char)((buffer_addr>>40)&0xff);
            final_code[buffer_disp_pos + 6] = (unsigned char)((buffer_addr>>48)&0xff);
            final_code[buffer_disp_pos + 7] = (unsigned char)((buffer_addr>>56)&0xff);
        }
        if (buffer_disp_pos2 != -1) {
            final_code[buffer_disp_pos2 + 0] = (unsigned char)(buffer_addr & 0xff);
            final_code[buffer_disp_pos2 + 1] = (unsigned char)((buffer_addr>>8)&0xff);
            final_code[buffer_disp_pos2 + 2] = (unsigned char)((buffer_addr>>16)&0xff);
            final_code[buffer_disp_pos2 + 3] = (unsigned char)((buffer_addr>>24)&0xff);
            final_code[buffer_disp_pos2 + 4] = (unsigned char)((buffer_addr>>32)&0xff);
            final_code[buffer_disp_pos2 + 5] = (unsigned char)((buffer_addr>>40)&0xff);
            final_code[buffer_disp_pos2 + 6] = (unsigned char)((buffer_addr>>48)&0xff);
            final_code[buffer_disp_pos2 + 7] = (unsigned char)((buffer_addr>>56)&0xff);
        }
    }

    unsigned long filesz = fi + total_msg_bytes + (has_paul ? 1024 : 0);

    unsigned char e_ident[16] = {0x7f,'E','L','F', 2 /*ELFCLASS64*/, 1 /*LE*/, 1 /*EV_CURRENT*/, 0};
    fwrite(e_ident, 1, 16, f);
    write_u16(f, 2); // e_type ET_EXEC
    write_u16(f, 0x3e); // e_machine EM_X86_64
    write_u32(f, 1); // e_version
    write_u64(f, entry); // e_entry
    write_u64(f, phoff); // e_phoff
    write_u64(f, 0); // e_shoff
    write_u32(f, 0); // e_flags
    write_u16(f, 64); // e_ehsize
    write_u16(f, 56); // e_phentsize
    write_u16(f, 1);  // e_phnum
    write_u16(f, 0);  // e_shentsize
    write_u16(f, 0);  // e_shnum
    write_u16(f, 0);  // e_shstrndx

    // Program header (PT_LOAD)
    write_u32(f, 1); // p_type PT_LOAD
    write_u32(f, 5); // p_flags PF_R + PF_X
    write_u64(f, text_off); // p_offset
    write_u64(f, entry);    // p_vaddr
    write_u64(f, entry);    // p_paddr
    write_u64(f, filesz);   // p_filesz
    write_u64(f, filesz);   // p_memsz
    write_u64(f, 0x1000); // p_align

    // Pad to text_off
    long cur = ftell(f);
    while (cur < (long)text_off) { fputc(0, f); cur++; }

    // Write code
    fwrite(final_code, 1, fi, f);
    // Write messages concatenated
    for (int i = 0; i < n_msgs; ++i) {
        fwrite(msgs[i], 1, msg_lens[i], f);
    }
    if (has_paul) {
        char buf[1024] = {0};
        fwrite(buf, 1, 1024, f);
    }

    free(disp_positions);
    free(next_instr_offsets);
    free(msg_offsets_within_messages);
    fclose(f);
    return 0;
}
static struct Program *g_program;
static struct Function *find_function(const char *name);
static long long call_function_compiletime(struct Function *fn, long long *args, int nargs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p);
static long long call_function_compiletime_with_refs(struct Function *fn, long long *arg_vals, char **arg_names, int *by_ref, int nargs, const char *assign_lhs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p);
static char *trim(char *s);

/* forward declaration for helper used when normalizing LHS in assignments */
static char *extract_ident_from_lhs(const char *s, char *out, size_t outsz);

/* forward-declare eval_int_expr so parse_factor can call it without implicit decl */
static long long eval_int_expr(const char *expr);

/* forward-declare helper to create temporary literal string symbols */
static char *create_literal_string(const char *lit);
/* forward-declare helper to evaluate string concatenation expressions like: a + "b" + c */
static char *eval_concat_string(const char *expr);
/* detect augmented assignment operator token immediately before '=' in a statement line
   returns operator char ('+','-','*','/','%') or 0 if none
   This is robust to spacing between the operator and '='. */
static char detect_aug_assign_op(const char *line, const char *eqpos) {
    if (!line || !eqpos) return 0;
    const char *p = eqpos - 1;
    /* skip spaces before '=' */
    while (p >= line && (*p == ' ' || *p == '\t')) p--;
    if (p < line) return 0;
    char c = *p;
    if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') return c;
    return 0;
}

/* Global pointers to the current message buffers used during exec_stmt_list.
    These are set by execute_function_compiletime and call_function_compiletime helpers
    so parse_factor can call functions at compile-time and append callee messages. */
static char ***g_msgs_p = NULL;
static unsigned int **g_msg_lens_p = NULL;
static int *g_n_msgs_p = NULL;
static int *g_max_msgs_p = NULL;
// Globals pointing to the current message buffers so nested function calls
// from the expression parser can append messages.



/* Symbol table for simple compile-time evaluation */
typedef enum { SYM_INT, SYM_STR, SYM_ALIAS } SymType;
typedef struct Sym {
    char *name;
    SymType type;
    long long ival;
    char *sval;
    struct Sym *next;
    struct Sym *alias_target; /* when type==SYM_ALIAS, points to target Sym */
} Sym;

static Sym *sym_table = NULL;

static void sym_set_int(const char *name, long long v) {
    Sym *p = sym_table;
    while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = sym_table; sym_table = p; }
    if (p->type == SYM_ALIAS && p->alias_target) {
        /* forward write to alias target */
        Sym *t = p->alias_target;
        t->type = SYM_INT; t->ival = v; return;
    }
    if (p->type == SYM_STR) { if (p->sval) free(p->sval); p->sval = NULL; }
    p->type = SYM_INT; p->ival = v;
}
static void sym_set_str(const char *name, const char *s) {
    Sym *p = sym_table;
    while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = sym_table; sym_table = p; }
    if (p->type == SYM_ALIAS && p->alias_target) {
        /* forward write to alias target (duplicate before freeing to avoid using freed memory) */
        Sym *t = p->alias_target;
        char *dup = my_strdup(s ? s : "");
        if (t->type == SYM_STR && t->sval) free(t->sval);
        t->type = SYM_STR; t->sval = dup; return;
    }
    if (p->type == SYM_STR && p->sval) free(p->sval);
    p->type = SYM_STR; p->sval = my_strdup(s ? s : "");
}
static Sym *sym_get(const char *name) {
    Sym *p = sym_table;
    int is_index = (strchr(name, '[') != NULL);
    while (p) {
        if (is_index) {
            /* debug compare for indexed lookups */
            if (strcmp(p->name, name) == 0) { printf("DEBUG: sym_get matched '%s' == '%s'\n", p->name, name); return p; }
            else printf("DEBUG: sym_get compare '%s' != '%s'\n", p->name, name);
        } else {
            if (strcmp(p->name, name) == 0) return p;
        }
        p = p->next;
    }
    return NULL;
}
static void sym_clear(void) {
    Sym *p = sym_table; while (p) { Sym *n = p->next; free(p->name); if (p->type==SYM_STR && p->sval) free(p->sval); /* do not free alias_target here */ free(p); p = n; } sym_table = NULL;
}

/* AST structs used by the simple parser/interpreter */
typedef enum {
    ST_PERIC,
    ST_ERIC_DECL,
    ST_ASSIGN,
    ST_RETURN,
    ST_FOR,
    ST_WHILE,
    ST_IF,
    ST_OTHER,
    ST_CONTINUE,
    ST_BREAK,
    ST_PAUL
} StmtKind;

typedef struct Stmt {
    StmtKind kind;
    char *raw;
    struct Stmt *next;
    struct Stmt *body;       /* used for blocks (for/if/while) */
    struct Stmt *else_body;  /* used for if/else */
    char *cond;              /* condition text */
    char *it_name;           /* iterator name for for-loops */
    int indent;
} Stmt;

typedef struct Function {
    char *name;
    char *params;
    char *ret_type;
    Stmt *body;
    struct Function *next;
} Function;

typedef struct Program { Function *functions; } Program;


/* Create an alias symbol in current sym_table that points to target Sym */
static void sym_set_alias(const char *name, Sym *target) {
    if (!name) return;
    Sym *p = sym_table; while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = sym_table; sym_table = p; }
    p->type = SYM_ALIAS; p->alias_target = target; p->sval = NULL; p->ival = 0;
}

/* Variants of sym_set_* that operate on an explicit table head and return the new head.
   These avoid temporarily switching the global `sym_table` pointer when inserting
   symbols into a different table (e.g. caller_table). */
static Sym *sym_set_int_in_table(Sym *table, const char *name, long long v) {
    Sym *p = table;
    while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = table; table = p; }
    if (p->type == SYM_ALIAS && p->alias_target) {
        Sym *t = p->alias_target;
        t->type = SYM_INT; t->ival = v; return table;
    }
    if (p->type == SYM_STR) { if (p->sval) free(p->sval); p->sval = NULL; }
    p->type = SYM_INT; p->ival = v;
    return table;
}
static Sym *sym_set_str_in_table(Sym *table, const char *name, const char *s) {
    Sym *p = table;
    while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = table; table = p; }
    if (p->type == SYM_ALIAS && p->alias_target) {
        Sym *t = p->alias_target;
        char *dup = my_strdup(s ? s : "");
        if (t->type == SYM_STR && t->sval) free(t->sval);
        t->type = SYM_STR; t->sval = dup; return table;
    }
    if (p->type == SYM_STR && p->sval) free(p->sval);
    p->type = SYM_STR; p->sval = my_strdup(s ? s : "");
    return table;
}
static Sym *sym_set_alias_in_table(Sym *table, const char *name, Sym *target) {
    if (!name) return table;
    Sym *p = table;
    while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = table; table = p; }
    p->type = SYM_ALIAS; p->alias_target = target; p->sval = NULL; p->ival = 0;
    return table;
}

/* Resolve aliases: follow alias_target until a non-alias symbol is returned */
static Sym *sym_resolve(Sym *p) {
    while (p && p->type == SYM_ALIAS) p = p->alias_target;
    return p;
}

/* Find a symbol by name in an explicit table (used to locate caller symbols when creating aliases) */
static Sym *sym_find_in_table(Sym *table, const char *name) {
    Sym *p = table; while (p) { if (strcmp(p->name, name) == 0) return p; p = p->next; } return NULL;
}

/* Return true if there exists any symbol whose name starts with prefix followed by '.'
   used to allow assignments to 'param.field' when the struct-like base was declared. */
static int sym_has_field_prefix(const char *prefix) {
    size_t plen = strlen(prefix);
    Sym *p = sym_table;
    while (p) {
        if (strncmp(p->name, prefix, plen) == 0 && p->name[plen] == '.') return 1;
        p = p->next;
    }
    return 0;
}

/* Heuristic: does this line look like a function call statement? e.g. "name(args)" */
static int looks_like_call(const char *s) {
    if (!s) return 0;
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_')) return 0;
    p++;
    while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '.') p++;
    while (*p == ' ' || *p == '\t') p++;
    return (*p == '(');
}

/* Simple recursive-descent expression evaluator for integers */
typedef struct { const char *s; int pos; } ExprState;
static void skip_ws(ExprState *e) { while (e->s[e->pos] == ' ' || e->s[e->pos] == '\t') e->pos++; }
static long long parse_expr(ExprState *e);
static long long parse_rel(ExprState *e);
static int match_kw(ExprState *e, const char *kw) {
    int len = strlen(kw);
    const char *s = e->s + e->pos;
    if (strncmp(s, kw, len) != 0) return 0;
    /* ensure keyword is not part of a longer identifier: next char must be non-alnum/underscore */
    char next = s[len];
    if (next == '\0' || next == ' ' || next == '\t' || next == ')' || next == '(' || next == ']' || next == '[' || next == ',' || next == '+' || next == '-' || next == '*' || next == '/' || next == '%' || next == '<' || next == '>' || next == '=' || next == '!' ) return 1;
    return 0;
}
static long long parse_and(ExprState *e);
static long long parse_or(ExprState *e);
static long long parse_factor(ExprState *e) {
    skip_ws(e);
    const char *s = e->s + e->pos;
    if (s[0] == '(') {
        e->pos++;
        long long v = parse_rel(e);
        skip_ws(e);
        if (e->s[e->pos] == ')') e->pos++;
        return v;
    }
    if ((s[0] >= '0' && s[0] <= '9') || (s[0] == '-' && s[1] >= '0' && s[1] <= '9')) {
        char *end; long long v = strtoll(s, &end, 10); e->pos += (end - s); return v;
    }
    /* character or quoted literal (support '\n','\t','\\','\0' and simple single char) */
    if (s[0] == '\'' || s[0] == '"') {
        char q = s[0];
        int adv = 1;
        int val = 0;
        if (s[adv] == '\\') {
            char esc = s[adv+1];
            if (esc == 'n') val = '\n';
            else if (esc == 't') val = '\t';
            else if (esc == '0') val = '\0';
            else val = esc;
            adv += 2; /* consumed backslash and escape char */
        } else if (s[adv]) {
            val = (unsigned char)s[adv]; adv += 1;
        }
        /* find closing quote if present */
        if (s[adv] == q) adv += 1; /* include closing quote */
        e->pos += adv;
        return (long long)val;
    }
    // identifier (allow dots for fields) or unary dereference
    int i = 0; while ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] == '_' ) || (s[i] >= '0' && s[i] <= '9') || (s[i]=='.')) i++;
    if (i > 0) {
        char name[256]; int n = i < (int)sizeof(name)-1 ? i : (int)sizeof(name)-1; memcpy(name, s, n); name[n] = '\0'; e->pos += i;
        skip_ws(e);
        // function call: name(args)
        if (e->s[e->pos] == '(') {
            e->pos++; // skip '('
            char argsbuf[256]; int ai = 0; int depth = 1; int start = e->pos;
            while (e->s[e->pos] && depth > 0) {
                if (e->s[e->pos] == '(') depth++; else if (e->s[e->pos] == ')') depth--; if (depth > 0 && ai < (int)sizeof(argsbuf)-1) argsbuf[ai++] = e->s[e->pos]; e->pos++; }
            argsbuf[ai] = '\0';
            // parse comma separated args
            long long argvals[8]; int argcnt = 0; char *cpy = my_strdup(argsbuf); char *tok = strtok(cpy, ","); while (tok && argcnt < 8) { char *t = trim(tok); argvals[argcnt++] = eval_int_expr(t); tok = strtok(NULL, ","); } free(cpy);
            Function *fn = find_function(name);
            if (fn) {
                // call using the current global message buffers if available, else create temporaries
                if (!g_msgs_p) {
                    int lm = 8;
                    char **lm_msgs = malloc(sizeof(char*) * lm);
                    unsigned int *lm_lens = malloc(sizeof(unsigned int) * lm);
                    int ln = 0;
                    /* call with addresses of temporaries */
                    long long res = call_function_compiletime(fn, argvals, argcnt, &lm_msgs, &lm_lens, &ln, &lm);
                    /* if there is a higher-level caller buffer (saved in globals), append into it */
                    if (g_msgs_p) {
                        for (int ii = 0; ii < ln; ++ii) {
                            if (*g_n_msgs_p >= *g_max_msgs_p) { *g_max_msgs_p *= 2; *g_msgs_p = realloc(*g_msgs_p, sizeof(char*)*(*g_max_msgs_p)); *g_msg_lens_p = realloc(*g_msg_lens_p, sizeof(unsigned int)*(*g_max_msgs_p)); }
                            (*g_msgs_p)[*g_n_msgs_p] = lm_msgs[ii]; (*g_msg_lens_p)[*g_n_msgs_p] = lm_lens[ii]; (*g_n_msgs_p)++;
                        }
                        free(lm_lens);
                        free(lm_msgs);
                    } else {
                        /* no one to keep these messages, free them */
                        for (int ii = 0; ii < ln; ++ii) free(lm_msgs[ii]);
                        free(lm_lens);
                        free(lm_msgs);
                    }
                    return res;
                } else {
                    long long res = call_function_compiletime(fn, argvals, argcnt, g_msgs_p, g_msg_lens_p, g_n_msgs_p, g_max_msgs_p);
                    return res;
                }
            } else {
                errorf("Call to undefined function '%s' in expression '%s'", name, e->s);
            }
        }
        // array indexing
        if (e->s[e->pos] == '[') {
            e->pos++; // skip '['
            long long idx = parse_expr(e);
            skip_ws(e);
            if (e->s[e->pos] == ']') e->pos++;
            char key[512]; snprintf(key, sizeof(key), "%s[%lld]", name, idx);
            Sym *sym = sym_get(key);
            if (sym) {
                Sym *res = sym_resolve(sym);
                if (res) {
                    if (res->type == SYM_INT) {
                        printf("DEBUG: parse_factor lookup '%s' -> %lld\n", key, res->ival);
                        return res->ival;
                    } else if (res->type == SYM_STR) {
                        /* string element exists: treat non-empty string as true (1), empty as 0 */
                        int truth = (res->sval && res->sval[0]) ? 1 : 0;
                        printf("DEBUG: parse_factor lookup '%s' -> STR present (truth=%d)\n", key, truth);
                        return truth;
                    }
                }
            }
            else {
                /* debugging: dump a few symbols in current table when lookup fails */
                printf("DEBUG: parse_factor lookup '%s' -> (not found) ; current table head: %p\n", key, (void*)sym_table);
                int dd = 0;
                for (Sym *pp = sym_table; pp && dd < 8; pp = pp->next, ++dd) {
                    if (pp->type == SYM_INT) printf("  [tbl] %s -> INT %lld (addr=%p)\n", pp->name, pp->ival, (void*)&pp->ival);
                    else if (pp->type == SYM_STR) printf("  [tbl] %s -> STR '%s' (sval=%p)\n", pp->name, pp->sval?pp->sval:"(null)", (void*)pp->sval);
                    else if (pp->type == SYM_ALIAS) printf("  [tbl] %s -> ALIAS to %s\n", pp->name, pp->alias_target?pp->alias_target->name:"(null)");
                }
            }
            /* Fallback: if 'name' resolves to a string, return the character code at index */
            Sym *base = sym_get(name);
            if (base) {
                Sym *r = sym_resolve(base);
                if (r && r->type == SYM_STR && r->sval) {
                    size_t sl = strlen(r->sval);
                    if (idx >= 0 && (size_t)idx < sl) {
                        unsigned char c = (unsigned char)r->sval[idx];
                        printf("DEBUG: parse_factor string lookup '%s'[%lld] -> %d\n", name, idx, c);
                        return (long long)c;
                    }
                    return 0;
                }
            }
            printf("DEBUG: parse_factor lookup '%s' -> (not found)\n", key);
            return 0;
        }
        Sym *sym = sym_get(name);
        if (sym) {
            Sym *res = sym_resolve(sym);
            if (res && res->type == SYM_INT) {
                printf("DEBUG: parse_factor lookup '%s' -> %lld\n", name, res->ival);
                return res->ival;
            }
        }
        errorf("Undefined variable '%s' in expression '%s'", name, e->s);
    }
    // unary dereference: *name
    if (s[0] == '*') {
        e->pos++; skip_ws(e);
        // parse identifier after *
        const char *s2 = e->s + e->pos; int i2 = 0; while ((s2[i2] >= 'a' && s2[i2] <= 'z') || (s2[i2] >= 'A' && s2[i2] <= 'Z') || (s2[i2] == '_' ) || (s2[i2] >= '0' && s2[i2] <= '9') || (s2[i2]=='.')) i2++; if (i2>0) {
            char name[256]; int nn = i2 < (int)sizeof(name)-1 ? i2 : (int)sizeof(name)-1; memcpy(name, s2, nn); name[nn] = '\0'; e->pos += i2;
            Sym *sym = sym_get(name);
            if (sym) {
                Sym *r = sym_resolve(sym);
                if (r && r->type == SYM_INT) return r->ival;
            }
        }
        return 0;
    }
    return 0;
}
static long long parse_term(ExprState *e) {
    long long v = parse_factor(e);
    for (;;) {
        skip_ws(e);
        char c = e->s[e->pos];
        if (c == '*') { e->pos++; long long r = parse_factor(e); v = v * r; }
        else if (c == '/') { e->pos++; long long r = parse_factor(e); if (r!=0) v = v / r; else errorf("Division by zero in expression '%s'", e->s); }
        else break;
    }
    return v;
}
static long long parse_expr(ExprState *e) {
    long long v = parse_term(e);
    for (;;) {
        skip_ws(e);
        char c = e->s[e->pos];
        if (c == '+') { e->pos++; long long r = parse_term(e); v = v + r; }
        else if (c == '-') { e->pos++; long long r = parse_term(e); v = v - r; }
        else break;
    }
    return v;

}

/* relational operators: >, <, >=, <=, ==, != */
static long long parse_rel(ExprState *e) {
    long long left = parse_expr(e);
    for (;;) {
        skip_ws(e);
        char a = e->s[e->pos]; char b = e->s[e->pos+1];
        if (a == '>' && b == '=') { e->pos += 2; long long right = parse_expr(e); left = (left >= right); }
        else if (a == '<' && b == '=') { e->pos += 2; long long right = parse_expr(e); left = (left <= right); }
        else if (a == '=' && b == '=') { e->pos += 2; long long right = parse_expr(e); left = (left == right); }
        else if (a == '!' && b == '=') { e->pos += 2; long long right = parse_expr(e); left = (left != right); }
        else if (a == '>') { e->pos += 1; long long right = parse_expr(e); left = (left > right); }
        else if (a == '<') { e->pos += 1; long long right = parse_expr(e); left = (left < right); }
        else break;
    }
    return left;

}

/* parse 'and' with higher precedence than 'or' */
static long long parse_and(ExprState *e) {
    long long left = parse_rel(e);
    for (;;) {
        skip_ws(e);
        /* debug: show where we are when trying to match 'and' (temporary) */
        printf("DEBUG_PARSE: parse_and pos=%d next='%.40s'\n", e->pos, e->s + e->pos);
        if (match_kw(e, "and")) {
            printf("DEBUG_PARSE: match 'and' at pos=%d next='%.20s'\n", e->pos, e->s + e->pos);
            e->pos += 3; /* consume 'and' */
            long long right = parse_rel(e);
            left = (left && right) ? 1 : 0;
        } else break;
    }
    return left;
}

/* parse 'or' (lowest precedence for logical ops) */
static long long parse_or(ExprState *e) {
    long long left = parse_and(e);
    for (;;) {
        skip_ws(e);
        /* debug: show where we are when trying to match 'or' (temporary) */
        printf("DEBUG_PARSE: parse_or pos=%d next='%.40s'\n", e->pos, e->s + e->pos);
        if (match_kw(e, "or")) {
            printf("DEBUG_PARSE: match 'or' at pos=%d next='%.20s'\n", e->pos, e->s + e->pos);
            e->pos += 2; /* consume 'or' */
            long long right = parse_and(e);
            left = (left || right) ? 1 : 0;
        } else break;
    }
    return left;
}

static long long eval_int_expr(const char *expr) {
    ExprState e = { expr, 0 };
    return parse_or(&e);
}

/* Evaluate a placeholder: if it's a plain identifier and maps to string, return string;
   otherwise evaluate as integer and return string form. */
static char *eval_placeholder(const char *inside) {
    // trim
    while (*inside == ' ' || *inside == '\t') inside++;
    int len = strlen(inside);
    while (len>0 && (inside[len-1]==' '||inside[len-1]=='\t')) len--;
    char tmp[256]; if (len >= (int)sizeof(tmp)) len = sizeof(tmp)-1; memcpy(tmp, inside, len); tmp[len] = '\0';
    // check if plain identifier
    int allid = 1; for (int i = 0; i < len; ++i) { char c=tmp[i]; if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||(c>='0'&&c<='9')||(c=='.'))) { allid=0; break; } }
    if (allid) {
        Sym *s = sym_get(tmp);
        if (s) {
            Sym *r = sym_resolve(s);
            if (r->type == SYM_STR) return my_strdup(r->sval);
            else { char buf[64]; snprintf(buf, sizeof(buf), "%lld", r->ival); return my_strdup(buf); }
        }
    }
    /* Support indexed placeholders like tab[i] where the index is an expression.
       We evaluate the index and attempt a direct lookup of the concrete symbol
       (e.g. "tab[0]") and return the string if present. */
    char *obr = strchr(tmp, '[');
    char *cbr = obr ? strchr(obr, ']') : NULL;
    if (obr && cbr) {
        /* build base and index expression */
        int baselen = obr - tmp;
        char basename[256]; if (baselen >= (int)sizeof(basename)) baselen = sizeof(basename)-1; memcpy(basename, tmp, baselen); basename[baselen] = '\0'; char idxexpr[256]; int ilen = cbr - (obr + 1); if (ilen >= (int)sizeof(idxexpr)) ilen = sizeof(idxexpr)-1; memcpy(idxexpr, obr + 1, ilen); idxexpr[ilen] = '\0'; trim(basename); trim(idxexpr);
        long long idxval = eval_int_expr(idxexpr);
        char key[512]; snprintf(key, sizeof(key), "%s[%lld]", basename, idxval);
        Sym *s2 = sym_get(key);
        if (s2) { Sym *r2 = sym_resolve(s2); if (r2->type == SYM_STR) return my_strdup(r2->sval ? r2->sval : ""); else { char buf2[64]; snprintf(buf2, sizeof(buf2), "%lld", r2->ival); return my_strdup(buf2); } }
    }
    // else evaluate as int expression
    long long v = eval_int_expr(tmp);
    char buf[64]; snprintf(buf, sizeof(buf), "%lld", v); return my_strdup(buf);
}

/* Unescape peric template sequences: \n -> newline, \t -> 4 spaces, \\\ -> backslash
   Return a newly malloc()'d string. */
static char *unescape_peric(const char *s) {
    if (!s) return NULL;
    int len = strlen(s);
    int max = len * 4 + 1; /* tabs may expand */
    char *out = malloc(max);
    if (!out) return NULL;
    int oi = 0;
    for (int i = 0; i < len; ++i) {
        if (s[i] == '\\' && i + 1 < len) {
            char c = s[i+1];
            if (c == 'n') { out[oi++] = '\n'; i++; }
            else if (c == 't') { /* tab -> 4 spaces */ out[oi++] = ' '; out[oi++] = ' '; out[oi++] = ' '; out[oi++] = ' '; i++; }
            else if (c == '\\') { out[oi++] = '\\'; i++; }
            else { /* unknown escape: keep next char as-is */ out[oi++] = c; i++; }
        } else {
            out[oi++] = s[i];
        }
        if (oi >= max - 1) break;
    }
    out[oi] = '\0';
    return out;
}

/* Unescape C-like string literal sequences for stored string literals.
   \n -> newline, \t -> tab, \\ -> backslash, \" -> ", \' -> ', \0 -> NUL, \r -> CR, \b -> backspace
   Returns a newly malloc()'d string (caller must free). */
static char *unescape_cstring(const char *s) {
    if (!s) return NULL;
    int len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    int oi = 0;
    for (int i = 0; i < len; ++i) {
        if (s[i] == '\\' && i + 1 < len) {
            char c = s[i+1];
            if (c == 'n') { out[oi++] = '\n'; i++; }
            else if (c == 't') { out[oi++] = '\t'; i++; }
            else if (c == '\\') { out[oi++] = '\\'; i++; }
            else if (c == 'r') { out[oi++] = '\r'; i++; }
            else if (c == '0') { out[oi++] = '\0'; i++; }
            else if (c == 'b') { out[oi++] = '\b'; i++; }
            else if (c == '\"') { out[oi++] = '\"'; i++; }
            else if (c == '\'') { out[oi++] = '\''; i++; }
            else { /* unknown escape: keep the char as-is */ out[oi++] = c; i++; }
        } else {
            out[oi++] = s[i];
        }
    }
    out[oi] = '\0';
    return out;
}

/* Execute function statements at compile-time to populate msgs and return code */
static int exec_stmt_list(Stmt *stlist, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p, int *retcode_p);

static int execute_function_compiletime(Function *f, char ***out_msgs, unsigned int **out_lens, int *out_n_msgs, int *out_ret) {
    int max_msgs = 8; char **msgs = malloc(sizeof(char*) * max_msgs); unsigned int *msg_lens = malloc(sizeof(unsigned int) * max_msgs); int n_msgs = 0; int retcode = 0;

    // set current global message buffer pointers so nested calls can append messages
    char ***old_msgs_p = g_msgs_p; unsigned int **old_msg_lens_p = g_msg_lens_p; int *old_n_msgs_p = g_n_msgs_p; int *old_max_msgs_p = g_max_msgs_p;
    g_msgs_p = &msgs; g_msg_lens_p = &msg_lens; g_n_msgs_p = &n_msgs; g_max_msgs_p = &max_msgs;
    // set global program pointer for function lookup
    // (we expect caller to set g_program before calling execute_function_compiletime)
    // execute top-level body
    exec_stmt_list(f->body, &msgs, &msg_lens, &n_msgs, &max_msgs, &retcode);
    // restore old globals
    g_msgs_p = old_msgs_p; g_msg_lens_p = old_msg_lens_p; g_n_msgs_p = old_n_msgs_p; g_max_msgs_p = old_max_msgs_p;

    *out_msgs = msgs; *out_lens = msg_lens; *out_n_msgs = n_msgs; *out_ret = retcode;
    return 0;
}

static int exec_stmt_list(Stmt *stlist, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p, int *retcode_p) {
    Stmt *s = stlist;
    while (s) {
        if (s->kind == ST_ERIC_DECL) {
            const char *p = s->raw + 5; while (*p == ' ') p++; const char *eq = strchr(p, '=');
            if (eq) {
                /* extract LHS name */
                const char *name_start = p; while (*name_start == ' ' || *name_start=='\t') name_start++; const char *name_end = eq; while (name_end > name_start && (*(name_end-1)==' '||*(name_end-1)=='\t')) name_end--; int namelen = name_end - name_start; char name[256]; if (namelen >= (int)sizeof(name)) namelen = sizeof(name)-1; memcpy(name, name_start, namelen); name[namelen] = '\0';
                const char *rhs = eq+1; while (*rhs==' '||*rhs=='\t') rhs++;
                if (rhs[0] == '"' || rhs[0] == '\'') {
                    char q = rhs[0];
                    /* find closing quote, respect backslash-escaped quotes */
                    const char *q2 = rhs + 1;
                    while (*q2) {
                        if (*q2 == '\\' && *(q2+1)) q2 += 2;
                        else if (*q2 == q) break;
                        else q2++;
                    }
                    if (!*q2) q2 = rhs + 1; /* fallback */
                    size_t llen = q2 - (rhs+1);
                    char *raw = malloc(llen+1); memcpy(raw, rhs+1, llen); raw[llen] = '\0';
                    char *val = unescape_cstring(raw);
                    free(raw);
                    sym_set_str(name, val ? val : "");
                    if (val) free(val);
                } else {
                    /* detect function call like fname(arg1, arg2) */
                    const char *op = strchr(rhs, '(');
                    if (op) {
                        int fname_len = op - rhs;
                        char fname[128]; if (fname_len >= (int)sizeof(fname)) fname_len = sizeof(fname)-1; memcpy(fname, rhs, fname_len); fname[fname_len]='\0'; char *ftrim = trim(fname);
                        const char *cl = strchr(op, ')'); if (cl) {
                                            char argsbuf[256]; int alen = cl - op - 1; if (alen >= (int)sizeof(argsbuf)) alen = sizeof(argsbuf)-1; memcpy(argsbuf, op+1, alen); argsbuf[alen]='\0';
                                            long long argvals[8]; int argcnt = 0; char *argnames[8]; int byref[8]; for (int ii=0; ii<8; ++ii) { argnames[ii]=NULL; byref[ii]=0; argvals[ii]=0; }
                                            char *cpy = my_strdup(argsbuf); char *tok = strtok(cpy, ",");
                                            while (tok && argcnt < 8) {
                                                char *t = trim(tok);
                                                if (t[0] == '&') {
                                                    char *n = trim(t+1);
                                                    argnames[argcnt] = my_strdup(n);
                                                    byref[argcnt] = 1;
                                                    argvals[argcnt] = 0;
                                                } else if (t[0] == '"' || t[0] == '\'') {
                                                    /* literal string or char argument */
                                                    if (t[0] == '\'' && t[1] && t[2] == '\'' && t[3] == '\0') {
                                                        /* single-quoted single char literal: pass as integer value */
                                                        argnames[argcnt] = NULL;
                                                        argvals[argcnt] = (int)t[1];
                                                        byref[argcnt] = 0;
                                                    } else {
                                                        /* create temporary literal symbol and pass its name */
                                                        char *tmpname = create_literal_string(t);
                                                        argnames[argcnt] = tmpname;
                                                        byref[argcnt] = 0;
                                                        argvals[argcnt] = 0;
                                                    }
                                                } else {
                                                    /* if the token is a plain identifier (starts with letter or _), record its name so callee can alias arrays */
                                                    int is_id = 1;
                                                    if (!((t[0] >= 'a' && t[0] <= 'z') || (t[0] >= 'A' && t[0] <= 'Z') || t[0] == '_')) is_id = 0;
                                                    for (int _i = 1; t[_i]; ++_i) { char _c = t[_i]; if (!((_c>='a'&&_c<='z')||(_c>='A'&&_c<='Z')||_c=='_'||(_c>='0'&&_c<='9')||_c=='.')) { is_id = 0; break; } }
                                                    if (is_id) {
                                                        argnames[argcnt] = my_strdup(t);
                                                        argvals[argcnt] = 0;
                                                    } else {
                                                        argnames[argcnt] = NULL;
                                                        argvals[argcnt] = eval_int_expr(t);
                                                    }
                                                    byref[argcnt] = 0;
                                                }
                                                argcnt++; tok = strtok(NULL, ",");
                                            }
                                            free(cpy);
                            /* Call handling: prefer language functions, but allow a few host-level
                               helpers at compile-time. Keep the structure simple and balanced. */
                            Function *fn = find_function(ftrim);
                            if (fn) {
                                /* language-level function: delegate to call wrapper */
                                long long cres = call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, name, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                                /* If callee produced a string return, don't overwrite it with integer */
                                if (!g_last_return_was_str) sym_set_int(name, cres);
                            } else if (strcmp(ftrim, "sammy") == 0 || strcmp(ftrim, "rogers") == 0 || strcmp(ftrim, "john") == 0 || strcmp(ftrim, "paul") == 0) {
                                /* simple host helpers implemented inline (mirror C semantics) */
                                if (strcmp(ftrim, "sammy") == 0) {
                                    int fd = -1; char *path = NULL; int flags = 0; mode_t mode = 0;
                                    if (argcnt >= 1 && argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR) path = r->sval; } }
                                    if (argcnt >= 2) { if (argnames[1]) { Sym *s = sym_get(argnames[1]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR && r->sval) { if (strcmp(r->sval, "r") == 0) flags = O_RDONLY; else if (strcmp(r->sval, "w") == 0) flags = O_WRONLY | O_CREAT | O_TRUNC; else if (strcmp(r->sval, "a") == 0) flags = O_WRONLY | O_CREAT | O_APPEND; else if (strcmp(r->sval, "r+") == 0) flags = O_RDWR; else flags = O_RDONLY; } } } else { flags = (int)argvals[1]; } }
                                    if (argcnt >= 3) mode = (mode_t)argvals[2];
                                    if (path) fd = open(path, flags, mode);
                                    sym_set_int(name, fd);
                                } else if (strcmp(ftrim, "rogers") == 0) {
                                    int res = -1; int fd = -1; if (argcnt >= 1) { if (argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_INT) fd = (int)r->ival; } } else fd = (int)argvals[0]; if (fd >= 0) res = close(fd); } sym_set_int(name, res);
                                } else if (strcmp(ftrim, "john") == 0) {
                                    ssize_t nread = -1; int fd = -1; char *dstname = NULL;
                                    if (argcnt >= 1) { if (argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_INT) fd = (int)r->ival; } } else fd = (int)argvals[0]; }
                                    if (argcnt >= 2 && argnames[1]) dstname = argnames[1];
                                    if (fd >= 0 && dstname) {
                                        if (argcnt >= 3) { size_t cnt = (size_t)argvals[2]; char *buf = malloc(cnt + 1); if (buf) { nread = read(fd, buf, cnt); if (nread > 0) { buf[nread] = '\0'; sym_set_str(dstname, buf); } free(buf); } }
                                        else { size_t cap = 4096; size_t pos = 0; char *buf = malloc(cap+1); if (buf) { while (1) { ssize_t r = read(fd, buf + pos, cap - pos); if (r > 0) { pos += r; if (cap - pos < 1024) { cap *= 2; char *nb = realloc(buf, cap+1); if (!nb) break; buf = nb; } } else if (r == 0) break; else break; } nread = (ssize_t)pos; buf[pos] = '\0'; sym_set_str(dstname, buf); free(buf); } }
                                    }
                                    sym_set_int(name, (long long)nread);
                                } else if (strcmp(ftrim, "paul") == 0) {
                                    ssize_t rv = -1; char *line = NULL; size_t linelen = 0; FILE *fp = NULL;
                                    if (argcnt >= 3) {
                                        if (argnames[2]) { Sym *s = sym_get(argnames[2]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR && r->sval) fp = fopen(r->sval, "r"); } }
                                        if (!fp) { int fd = (int)argvals[2]; if (fd >= 0) fp = fdopen(fd, "r"); }
                                        if (fp) { rv = getline(&line, &linelen, fp); if (rv >= 0 && line) { if (argnames[0]) sym_set_str(argnames[0], line); if (argnames[1]) sym_set_int(argnames[1], (long long)linelen); free(line); } fclose(fp); }
                                    }
                                    sym_set_int(name, (long long)rv);
                                }
                            } else {
                                errorf("Call to undefined function '%s' in assignment to '%s'", ftrim, name);
                            }
                            for (int ii=0; ii<argcnt; ++ii) if (argnames[ii]) free(argnames[ii]);
                        } else {
                            long long v = eval_int_expr(rhs);
                            printf("DEBUG: ASSIGN expr -> setting '%s' = %lld\n", name, v);
                            sym_set_int(name, v);
                        }
                    } else {
                        long long v = eval_int_expr(rhs);
                        printf("DEBUG: ASSIGN expr -> setting '%s' = %lld\n", name, v);
                        sym_set_int(name, v);
                    }
                }
            } else {
                    const char *arrow = strstr(p, "->"); const char *name_end = arrow ? arrow : p + strlen(p); while (name_end > p && (*(name_end-1)==' '||*(name_end-1)=='\t')) name_end--; int namelen = name_end - p; char name[128]; if (namelen>=127) namelen=127; memcpy(name,p,namelen); name[namelen]='\0';
                    // handle array type like int[5]
                    if (arrow) {
                        const char *typ = arrow + 2; while (*typ==' '||*typ=='\t') typ++; // expect int[...] or similar
                        // find '['
                        const char *obr = strchr(typ, '[');
                        const char *cbr = obr ? strchr(obr, ']') : NULL;
                        if (obr && cbr && cbr > obr+1) {
                            char numbuf[32]; int nlen = cbr - obr - 1; if (nlen >= (int)sizeof(numbuf)) nlen = sizeof(numbuf)-1; memcpy(numbuf, obr+1, nlen); numbuf[nlen] = '\0'; int count = atoi(numbuf);
                            for (int ii = 0; ii < count; ++ii) { char key[256]; snprintf(key, sizeof(key), "%s[%d]", name, ii); sym_set_int(key, 0); }
                        } else {
                            /* if declared as char * or contains '*' in type, initialize as empty string */
                            if (strstr(typ, "char") || strchr(typ, '*')) {
                                sym_set_str(name, "");
                            } else {
                                sym_set_int(name, 0);
                            }
                        }
                    } else {
                        sym_set_int(name, 0);
                    }
            }
        } else if (s->kind == ST_ASSIGN) {
            const char *p = s->raw; const char *eq = strchr(p, '=');
            if (eq) {
                /* extract LHS cleanly: trim spaces and capture everything up to '=' */
                const char *lhs_start = p; while (*lhs_start == ' '||*lhs_start=='\t') lhs_start++;
                const char *lhs_end = eq; while (lhs_end > lhs_start && (*(lhs_end-1)==' '||*(lhs_end-1)=='\t')) lhs_end--;
                int namelen = lhs_end - lhs_start;
                char raw_lhs[256]; if (namelen >= (int)sizeof(raw_lhs)) namelen = sizeof(raw_lhs)-1; memcpy(raw_lhs, lhs_start, namelen); raw_lhs[namelen] = '\0';
                /* strip trailing operator characters that may be present in augmented assignment like 'src +' */
                int rlen = (int)strlen(raw_lhs);
                while (rlen > 0 && (raw_lhs[rlen-1] == ' ' || raw_lhs[rlen-1] == '\t' || raw_lhs[rlen-1] == '+' || raw_lhs[rlen-1] == '-' || raw_lhs[rlen-1] == '*' || raw_lhs[rlen-1] == '/' || raw_lhs[rlen-1] == '%')) { raw_lhs[rlen-1] = '\0'; rlen--; }
                /* detect if LHS is a dereference like '*name' (first non-space is '*') */
                int deref_flag = 0; for (int _i=0; raw_lhs[_i]; ++_i) { if (raw_lhs[_i] == ' ' || raw_lhs[_i] == '\t') continue; if (raw_lhs[_i] == '*') deref_flag = 1; break; }
                char name[256]; extract_ident_from_lhs(raw_lhs, name, sizeof(name));
                /* support indexed LHS like tab[i] by resolving the index now and building a concrete symbol name */
                char base_name[256]; char use_name[256]; memset(base_name,0,sizeof(base_name)); memset(use_name,0,sizeof(use_name));
                char *br = strchr(raw_lhs, '[');
                if (br) {
                    /* extract base up to '[' */
                    int blen = br - raw_lhs; if (blen >= (int)sizeof(base_name)) blen = sizeof(base_name)-1; memcpy(base_name, raw_lhs, blen); base_name[blen] = '\0'; trim(base_name);
                    /* extract index expression between [ and ] */
                    const char *idxstart = br + 1; const char *idxend = strchr(idxstart, ']'); char idxexpr[128]; if (idxend) { int ilen = idxend - idxstart; if (ilen >= (int)sizeof(idxexpr)) ilen = sizeof(idxexpr)-1; memcpy(idxexpr, idxstart, ilen); idxexpr[ilen] = '\0'; } else { idxexpr[0] = '\0'; }
                    int idxval = 0; if (idxexpr[0]) { idxval = (int)eval_int_expr(idxexpr); }
                    snprintf(use_name, sizeof(use_name), "%s[%d]", base_name, idxval);
                } else {
                    strncpy(base_name, name, sizeof(base_name)-1); base_name[sizeof(base_name)-1] = '\0'; strncpy(use_name, name, sizeof(use_name)-1); use_name[sizeof(use_name)-1] = '\0';
                }
                printf("DEBUG: ASSIGN detected raw_lhs='%s' -> base='%s' use_name='%s'\n", raw_lhs, base_name, use_name);
                /* require prior declaration via 'eric' (ST_ERIC_DECL) for the base name before assigning to a variable */
                Sym *lhs_sym = sym_get(base_name);
                if (!lhs_sym) {
                    /* allow assignment to dotted fields when the base was declared */
                    if (strchr(base_name, '.')) {
                        char base[256]; size_t pos = 0; while (pos < sizeof(base)-1 && base_name[pos] && base_name[pos] != '.') { base[pos] = base_name[pos]; pos++; } base[pos] = '\0';
                        if (!sym_has_field_prefix(base)) {
                            errorf("Assignment to undeclared variable '%s' (declare using 'eric <name> -> type')", base_name);
                        }
                    } else {
                        errorf("Assignment to undeclared variable '%s' (declare using 'eric <name> -> type')", base_name);
                    }
                }
                const char *rhs = eq+1; while (*rhs==' '||*rhs=='\t') rhs++;
                /* If RHS contains a '+' outside quotes, it might be string concatenation.
                   But '+' is also a valid arithmetic operator. Only treat as string
                   concatenation when the RHS contains quoted strings or the LHS
                   variable is known to be a string. This avoids treating expressions
                   like 'end - start + 1' as string concat producing '281'. */
                int plus_found_local = 0; const char *ppp = rhs; while (*ppp) {
                    if (*ppp == '"' || *ppp == '\'') { char q = *ppp; ppp++; while (*ppp && *ppp != q) ppp++; if (*ppp) ppp++; }
                    else { if (*ppp == '+') { plus_found_local = 1; break; } ppp++; }
                }
                if (plus_found_local) {
                    int must_concat = 0;
                    /* If RHS contains explicit quoted strings, it's clearly concatenation */
                    if (strchr(rhs, '"') || strchr(rhs, '\'')) must_concat = 1;
                    /* Otherwise if the LHS symbol exists and is a string, prefer concatenation */
                    else if (lhs_sym) { Sym *lsr = sym_resolve(lhs_sym); if (lsr && lsr->type == SYM_STR) must_concat = 1; }
                    if (must_concat) {
                        char *cres = eval_concat_string(rhs);
                        if (cres) { sym_set_str(use_name, cres); free(cres); }
                        /* done with assignment */
                        goto ASSIGN_DONE_LABEL;
                    }
                }

                /* Detect augmented assignment operator token robustly */
                char aug_op_token = detect_aug_assign_op(p, eq);
                /* Fallback: scan the region between lhs_start and eq for an operator character
                   (handles cases where the '=' parsing/trimming removed the operator). */
                if (!aug_op_token) {
                    const char *scanptr = lhs_start; const char *lastop = NULL;
                    while (scanptr < eq) {
                        if (*scanptr == '+' || *scanptr == '-' || *scanptr == '*' || *scanptr == '/' || *scanptr == '%') lastop = scanptr;
                        scanptr++;
                    }
                    if (lastop) aug_op_token = *lastop;
                }
                if (aug_op_token) {
                    printf("DEBUG: AUG_ASSIGN detected name='%s' op='%c' raw_lhs='%s' rhs='%s'\n", name, aug_op_token, raw_lhs, rhs);
                    /* perform augmented op based on LHS type */
                    Sym *ls = sym_get(base_name);
                    Sym *lr = ls ? sym_resolve(ls) : NULL;
            if (aug_op_token == '+') {
                /* string concat if LHS is string or RHS is quoted or RHS contains quotes */
                            if ((lr && lr->type == SYM_STR) || strchr(rhs, '"') || strchr(rhs, '\'')) {
                            char *rhsstr = eval_concat_string(rhs);
                            const char *left = (lr && lr->type == SYM_STR && lr->sval) ? lr->sval : "";
                            size_t nl = strlen(left) + (rhsstr ? strlen(rhsstr) : 0);
                            char *nstr = malloc(nl + 1);
                            if (nstr) {
                                nstr[0] = '\0'; strcat(nstr, left); if (rhsstr) strcat(nstr, rhsstr);
                                sym_set_str(use_name, nstr);
                                free(nstr);
                            }
                            if (rhsstr) free(rhsstr);
                            Sym *nn = sym_get(use_name); if (nn) { Sym *nr = sym_resolve(nn); if (nr && nr->type==SYM_STR) printf("DEBUG: AUG_ASSIGN result '%s'\n", nr->sval?nr->sval:"(null)"); }
                        } else {
                            long long cur = 0; if (lr && lr->type == SYM_INT) cur = lr->ival;
                            long long add = eval_int_expr(rhs);
                            sym_set_int(use_name, cur + add);
                            Sym *nn = sym_get(use_name); if (nn) { Sym *nr = sym_resolve(nn); if (nr && nr->type==SYM_INT) printf("DEBUG: AUG_ASSIGN result %lld\n", nr->ival); }
                        }
                    } else if (aug_op_token == '-') {
                        long long cur = 0; if (lr && lr->type == SYM_INT) cur = lr->ival;
                        long long sub = eval_int_expr(rhs);
                        sym_set_int(use_name, cur - sub);
                    } else if (aug_op_token == '*') {
                        long long cur = 0; if (lr && lr->type == SYM_INT) cur = lr->ival;
                        long long mul = eval_int_expr(rhs);
                        sym_set_int(use_name, cur * mul);
                    } else if (aug_op_token == '/') {
                        long long cur = 0; if (lr && lr->type == SYM_INT) cur = lr->ival;
                        long long dv = eval_int_expr(rhs);
                        if (dv != 0) sym_set_int(use_name, cur / dv);
                        else errorf("Division by zero in augmented assignment on '%s'", name);
                    } else if (aug_op_token == '%') {
                        long long cur = 0; if (lr && lr->type == SYM_INT) cur = lr->ival;
                        long long dv = eval_int_expr(rhs);
                        if (dv != 0) sym_set_int(use_name, cur % dv);
                        else errorf("Modulo by zero in augmented assignment on '%s'", name);
                    }
                    goto ASSIGN_DONE_LABEL;
                }
                if (rhs[0] == '"' || rhs[0] == '\'') {
                    char q = rhs[0]; const char *q2 = strchr(rhs+1, q); if (!q2) q2 = rhs+1; size_t llen = q2 - (rhs+1); char *val = malloc(llen+1); memcpy(val, rhs+1, llen); val[llen]='\0';
                    printf("DEBUG: ASSIGN string literal -> setting '%s' = '%s'\n", use_name, val);
                    sym_set_str(use_name, val); free(val);
                } else {
                    /* detect function call like fname(arg1, arg2) */
                    const char *op = strchr(rhs, '(');
                    if (op) {
                        int fname_len = op - rhs;
                        char fname[128]; if (fname_len >= (int)sizeof(fname)) fname_len = sizeof(fname)-1; memcpy(fname, rhs, fname_len); fname[fname_len]='\0'; char *ftrim = trim(fname);
                        const char *cl = strchr(op, ')'); if (cl) {
                            char argsbuf[256]; int alen = cl - op - 1; if (alen >= (int)sizeof(argsbuf)) alen = sizeof(argsbuf)-1; memcpy(argsbuf, op+1, alen); argsbuf[alen]='\0';
                            // parse comma-separated args, support &name (by-ref)
                            long long argvals[8]; int argcnt = 0; char *argnames[8]; int byref[8]; for (int ii=0; ii<8; ++ii) { argnames[ii]=NULL; byref[ii]=0; argvals[ii]=0; }
                            char *cpy = my_strdup(argsbuf); char *tok = strtok(cpy, ",");
                            while (tok && argcnt < 8) {
                                char *t = trim(tok);
                                if (t[0] == '&') {
                                    char *n = trim(t+1);
                                    argnames[argcnt] = my_strdup(n);
                                    byref[argcnt] = 1;
                                    argvals[argcnt] = 0;
                                } else {
                                    int is_id = 1;
                                    if (!((t[0] >= 'a' && t[0] <= 'z') || (t[0] >= 'A' && t[0] <= 'Z') || t[0] == '_')) is_id = 0;
                                    for (int _i = 1; t[_i]; ++_i) { char _c = t[_i]; if (!((_c>='a'&&_c<='z')||(_c>='A'&&_c<='Z')||_c=='_'||(_c>='0'&&_c<='9')||_c=='.')) { is_id = 0; break; } }
                                    if (is_id) { argnames[argcnt] = my_strdup(t); argvals[argcnt]=0; } else { argnames[argcnt] = NULL; argvals[argcnt] = eval_int_expr(t); }
                                    byref[argcnt] = 0;
                                }
                                argcnt++; tok = strtok(NULL, ",");
                            }
                            free(cpy);
                            Function *fn = find_function(ftrim);
                            if (fn) {
                                if (strcmp(ftrim, "my_strlen") == 0 && argcnt >= 1) {
                                    long long cres = 0;
                                    if (argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR && r->sval) cres = (long long)strlen(r->sval); } }
                                    sym_set_int(use_name, cres);
                                } else if (strcmp(ftrim, "my_strcmp") == 0 && argcnt >= 2) {
                                    long long cres = 0;
                                    char *s1 = NULL; char *s2 = NULL;
                                    if (argnames[0]) { Sym *a = sym_get(argnames[0]); if (a) { Sym *ra = sym_resolve(a); if (ra && ra->type==SYM_STR) s1 = ra->sval; } }
                                    if (argnames[1]) { Sym *b = sym_get(argnames[1]); if (b) { Sym *rb = sym_resolve(b); if (rb && rb->type==SYM_STR) s2 = rb->sval; } }
                                    if (s1 && s2) cres = (long long)strcmp(s1, s2);
                                    printf("DEBUG: ASSIGN builtin my_strcmp -> setting '%s' = %lld\n", use_name, cres);
                                    sym_set_int(use_name, cres);
                                } else {
                                                long long cres = call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, use_name, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                                                /* If the nested call produced a string return and assigned it into the
                                                    current table (g_last_return_was_str==1), don't overwrite it with an int. */
                                                if (!g_last_return_was_str) sym_set_int(use_name, cres);
                                }
                            } else {
                                long long v = eval_int_expr(rhs);
                                printf("DEBUG: ASSIGN expr -> setting '%s' = %lld\n", use_name, v);
                                sym_set_int(use_name, v);
                            }
                            for (int ii=0; ii<argcnt; ++ii) if (argnames[ii]) free(argnames[ii]);
                        } else {
                            long long v = eval_int_expr(rhs);
                            printf("DEBUG: ASSIGN expr -> setting '%s' = %lld\n", use_name, v);
                            sym_set_int(use_name, v);
                        }
                    } else {
                        long long v = eval_int_expr(rhs);
                        printf("DEBUG: ASSIGN expr -> setting '%s' = %lld\n", use_name, v);
                        sym_set_int(use_name, v);
                    }
                }
                /* handle deref assignment (if original LHS used *name) */
                if (deref_flag) {
                    char *ntrim = name;
                    Sym *s2 = sym_get(ntrim);
                    if (s2) {
                        Sym *t = sym_resolve(s2);
                        if (t && t->type == SYM_INT) {
                            long long v = 0; if (rhs && *rhs) v = eval_int_expr(rhs); t->ival = v;
                        }
                    }
                }
                ASSIGN_DONE_LABEL: ;
            }
        } else if (s->kind == ST_PERIC) {
            const char *p = strstr(s->raw, "peric(");
            if (!p) { s = s->next; continue; }
            const char *q = strchr(p, '"'); if (!q) { s = s->next; continue; } q++;
            const char *r = strchr(q, '"'); if (!r) { s = s->next; continue; }
            size_t len = r - q;
            char *tmpl = malloc(len+1);
            memcpy(tmpl, q, len);
            tmpl[len] = '\0';
            /* build output dynamically to avoid truncation for large templates */
            size_t out_cap = 1024; size_t out_len = 0; char *out = malloc(out_cap);
            if (!out) { free(tmpl); s = s->next; continue; }
            out[0] = '\0';
            const char *cur = tmpl;
            while (*cur) {
                const char *obr = strchr(cur, '{');
                if (!obr) {
                    size_t need = strlen(cur);
                    if (out_len + need + 1 > out_cap) { out_cap = out_len + need + 1; char *nb = realloc(out, out_cap); if (!nb) break; out = nb; }
                    memcpy(out + out_len, cur, need); out_len += need; out[out_len] = '\0';
                    break;
                }
                size_t chunk = obr - cur;
                if (out_len + chunk + 1 > out_cap) { out_cap = out_len + chunk + 1; char *nb = realloc(out, out_cap); if (!nb) break; out = nb; }
                memcpy(out + out_len, cur, chunk); out_len += chunk; out[out_len] = '\0';
                const char *cbr = strchr(obr, '}');
                if (!cbr) {
                    /* append rest */
                    size_t rest = strlen(obr);
                    if (out_len + rest + 1 > out_cap) { out_cap = out_len + rest + 1; char *nb = realloc(out, out_cap); if (!nb) break; out = nb; }
                    memcpy(out + out_len, obr, rest); out_len += rest; out[out_len] = '\0';
                    break;
                }
                int ilen = cbr - (obr+1);
                char inner[256]; if (ilen >= (int)sizeof(inner)) ilen = sizeof(inner)-1; memcpy(inner, obr+1, ilen); inner[ilen] = '\0';

                /* detect function(...) placeholder and evaluate at compile-time */
                char *popen = strchr(inner, '(');
                if (popen) {
                    char fname[128]; int flen = popen - inner; if (flen >= (int)sizeof(fname)) flen = sizeof(fname)-1; memcpy(fname, inner, flen); fname[flen] = '\0'; char *ftrim = trim(fname);
                    char *pclose = strchr(popen, ')');
                    if (pclose) {
                        char argsbuf[256]; int alen = pclose - popen - 1; if (alen >= (int)sizeof(argsbuf)) alen = sizeof(argsbuf)-1; memcpy(argsbuf, popen+1, alen); argsbuf[alen] = '\0';
                        long long argvals[8]; int argcnt = 0; char *cpy2 = my_strdup(argsbuf); char *tok2 = strtok(cpy2, ",");
                        while (tok2 && argcnt < 8) { char *t2 = trim(tok2); argvals[argcnt++] = eval_int_expr(t2); tok2 = strtok(NULL, ","); }
                        free(cpy2);
                        Function *ff = find_function(ftrim);
                        if (ff) {
                            long long cres = call_function_compiletime(ff, argvals, argcnt, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                            char numbuf[64]; snprintf(numbuf, sizeof(numbuf), "%lld", cres);
                            size_t need = strlen(numbuf);
                            if (out_len + need + 1 > out_cap) { out_cap = out_len + need + 1; char *nb = realloc(out, out_cap); if (!nb) { free(out); free(tmpl); errorf("out of memory in peric"); } out = nb; }
                            memcpy(out + out_len, numbuf, need); out_len += need; out[out_len] = '\0';
                            cur = cbr + 1;
                            continue;
                        } else {
                            errorf("Call to undefined function '%s' inside peric placeholder '%s'", ftrim, inner);
                        }
                    }
                }

                char *evaled = eval_placeholder(inner);
                size_t need2 = strlen(evaled);
                if (out_len + need2 + 1 > out_cap) { out_cap = out_len + need2 + 1; char *nb = realloc(out, out_cap); if (!nb) { free(out); free(tmpl); free(evaled); errorf("out of memory in peric"); } out = nb; }
                memcpy(out + out_len, evaled, need2); out_len += need2; out[out_len] = '\0';
                free(evaled);
                cur = cbr + 1;
            }

            /* ensure escape sequences like \n and \t are interpreted */
            char *un = unescape_peric(out);
            if (!un) un = my_strdup("");
            size_t olen = strlen(un);
            /* DEBUG: show the resolved peric string before storing */
            printf("DEBUG: peric resolved='%s'\n", un);
            char *withn = malloc(olen + 2);
            memcpy(withn, un, olen);
            withn[olen] = '\n';
            withn[olen + 1] = '\0';
            free(un);
            if (*n_msgs_p >= *max_msgs_p) { *max_msgs_p *= 2; *msgs_p = realloc(*msgs_p, sizeof(char*)*(*max_msgs_p)); *msg_lens_p = realloc(*msg_lens_p, sizeof(unsigned int)*(*max_msgs_p)); }
            (*msgs_p)[*n_msgs_p] = withn;
            (*msg_lens_p)[*n_msgs_p] = (unsigned int)strlen(withn);
            (*n_msgs_p)++;
            free(tmpl);
        } else if (s->kind == ST_PAUL) {
            /* Do NOT read input at compile-time. Mark that the generated
               binary should perform a runtime read and print the value.
               emit_elf will emit the necessary syscalls when `has_paul` is set. */
            has_paul = 1;
        } else if (s->kind == ST_RETURN) {
            const char *p = s->raw + strlen("deschodt"); while (*p==' '||*p=='\t') p++;
            /* capture string return if expression refers to a string variable or literal
               We try to detect string returns first so we don't call eval_int_expr on
               an identifier that holds a string (which would trigger an "Undefined
               variable" error from the integer evaluator). */
            const char *q = s->raw + strlen("deschodt"); while (*q==' '||*q=='\t') q++;
            /* free previous if any */
            if (g_last_return_str) { free(g_last_return_str); g_last_return_str = NULL; }
            int handled_as_string = 0;
            if (*q == '\'' || *q == '"') {
                char quote = *q; const char *q2 = strchr(q+1, quote); if (!q2) q2 = q+1; size_t llen = q2 - (q+1); g_last_return_str = malloc(llen+1); if (g_last_return_str) { memcpy(g_last_return_str, q+1, llen); g_last_return_str[llen] = '\0'; }
                handled_as_string = 1;
            } else {
                /* try simple identifier lookup for string variable */
                char idtmp[256] = {0}; const char *r = q; while (*r && !(((*r>='a'&&*r<='z')||(*r>='A'&&*r<='Z')||(*r=='_')))) r++; int ii=0; while (*r && (((*r>='a'&&*r<='z')||(*r>='A'&&*r<='Z')||(*r>='0'&&*r<='9')||(*r=='_')) ) && ii < (int)sizeof(idtmp)-1) { idtmp[ii++] = *r++; } idtmp[ii] = '\0'; if (idtmp[0]) { Sym *sx = sym_find_in_table(sym_table, idtmp); if (sx) { Sym *sr = sym_resolve(sx); if (sr && sr->type == SYM_STR && sr->sval) { g_last_return_str = my_strdup(sr->sval); handled_as_string = 1; } } }
            }
            /* If not handled as a string, evaluate as integer expression (if any) */
            if (!handled_as_string && *q) {
                long long rv = eval_int_expr(q);
                *retcode_p = (int)rv;
            }
            /* set the global flag indicating whether this return produced a string */
            g_last_return_was_str = handled_as_string;
            printf("DEBUG: ST_RETURN encountered raw='%s' ret=%d\n", s->raw, *retcode_p);
            return 1;
        }
        else if (s->kind == ST_OTHER) {
            /* detect function call used as a statement, e.g. incremente(&n) */
            const char *r = s->raw;
            const char *op = strchr(r, '(');
            const char *cl = op ? strchr(op, ')') : NULL;
            if (op && cl) {
                int fname_len = op - r;
                char fname[128]; if (fname_len >= (int)sizeof(fname)) fname_len = sizeof(fname)-1; memcpy(fname, r, fname_len); fname[fname_len] = '\0'; char *ftrim = trim(fname);
                char argsbuf[256]; int alen = cl - op - 1; if (alen >= (int)sizeof(argsbuf)) alen = sizeof(argsbuf)-1; memcpy(argsbuf, op+1, alen); argsbuf[alen] = '\0';
                long long argvals[8]; int argcnt = 0; char *argnames[8]; int byref[8]; for (int ii=0; ii<8; ++ii) { argnames[ii]=NULL; byref[ii]=0; argvals[ii]=0; }
                char *cpy = my_strdup(argsbuf); char *tok = strtok(cpy, ",");
                            while (tok && argcnt < 8) {
                                char *t = trim(tok);
                                if (t[0] == '&') { char *n = trim(t+1); argnames[argcnt] = my_strdup(n); byref[argcnt] = 1; argvals[argcnt]=0; }
                                else if (t[0] == '"' || t[0] == '\'') {
                                    if (t[0] == '\'' && t[1] && t[2] == '\'' && t[3] == '\0') {
                                        argnames[argcnt] = NULL; argvals[argcnt] = (int)t[1]; byref[argcnt] = 0;
                                    } else { argnames[argcnt] = create_literal_string(t); byref[argcnt]=0; argvals[argcnt]=0; }
                                }
                                else {
                                    int is_id = 1;
                                    if (!((t[0] >= 'a' && t[0] <= 'z') || (t[0] >= 'A' && t[0] <= 'Z') || t[0] == '_')) is_id = 0;
                                    for (int _i = 1; t[_i]; ++_i) { char _c = t[_i]; if (!((_c>='a'&&_c<='z')||(_c>='A'&&_c<='Z')||_c=='_'||(_c>='0'&&_c<='9')||_c=='.')) { is_id = 0; break; } }
                                    if (is_id) { argnames[argcnt] = my_strdup(t); argvals[argcnt]=0; } else { argnames[argcnt]=NULL; argvals[argcnt]=eval_int_expr(t); }
                                    byref[argcnt]=0;
                                }
                                argcnt++; tok = strtok(NULL, ",");
                            }
                free(cpy);
                Function *fn = find_function(ftrim);
                if (fn) {
                    /* language-level function: delegate to compile-time call wrapper
                       but allow known simple builtins to be no-ops when used as statements */
                    if (strcmp(ftrim, "my_strlen") == 0 || strcmp(ftrim, "my_strcmp") == 0) {
                        /* ignore return; builtins operate on symbols */
                        /* nothing to do when called as a statement */
                    } else {
                        call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, NULL, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                    }
                } else if (strcmp(ftrim, "sammy") == 0 || strcmp(ftrim, "rogers") == 0 || strcmp(ftrim, "john") == 0 || strcmp(ftrim, "paul") == 0) {
                    /* handle a small set of host helpers when called as statements */
                    if (strcmp(ftrim, "sammy") == 0) {
                        int fd = -1; char *path = NULL; int flags = 0; mode_t mode = 0;
                        if (argcnt >= 1 && argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR) path = r->sval; } }
                        if (argcnt >= 2) { if (argnames[1]) { Sym *s = sym_get(argnames[1]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR && r->sval) { if (strcmp(r->sval, "r") == 0) flags = O_RDONLY; else if (strcmp(r->sval, "w") == 0) flags = O_WRONLY | O_CREAT | O_TRUNC; else if (strcmp(r->sval, "a") == 0) flags = O_WRONLY | O_CREAT | O_APPEND; else if (strcmp(r->sval, "r+") == 0) flags = O_RDWR; else flags = O_RDONLY; } } } else { flags = (int)argvals[1]; } }
                        if (argcnt >= 3) mode = (mode_t)argvals[2];
                        if (path) { fd = open(path, flags, mode); if (fd >= 0) close(fd); }
                    } else if (strcmp(ftrim, "rogers") == 0) {
                        if (argcnt >= 1) {
                            int fd = -1; if (argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_INT) fd = (int)r->ival; } } else fd = (int)argvals[0]; if (fd >= 0) close(fd);
                        }
                    } else if (strcmp(ftrim, "john") == 0) {
                        /* john(fd, bufname [, count]) as a statement: perform read and store into bufname if provided */
                        ssize_t nread = -1; int fd = -1; char *dstname = NULL;
                        if (argcnt >= 1) { if (argnames[0]) { Sym *s = sym_get(argnames[0]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_INT) fd = (int)r->ival; } } else fd = (int)argvals[0]; }
                        if (argcnt >= 2 && argnames[1]) dstname = argnames[1];
                        if (fd >= 0 && dstname) {
                            if (argcnt >= 3) {
                                size_t cnt = (size_t)argvals[2]; char *buf = malloc(cnt + 1); if (buf) { nread = read(fd, buf, cnt); if (nread > 0) { buf[nread] = '\0'; sym_set_str(dstname, buf); } free(buf); }
                            } else {
                                size_t cap = 4096; size_t pos = 0; char *buf = malloc(cap+1); if (buf) { while (1) { ssize_t r = read(fd, buf + pos, cap - pos); if (r > 0) { pos += r; if (cap - pos < 1024) { cap *= 2; char *nb = realloc(buf, cap+1); if (!nb) break; buf = nb; } } else if (r == 0) break; else break; } nread = (ssize_t)pos; buf[pos] = '\0'; sym_set_str(dstname, buf); free(buf); }
                            }
                        }
                    } else if (strcmp(ftrim, "paul") == 0) {
                        /* paul(line_sym, n_sym, stream_or_fd) as statement: perform getline and store into symbols if provided */
                        ssize_t rv = -1; char *line = NULL; size_t linelen = 0; FILE *fp = NULL;
                        if (argcnt >= 3) {
                            if (argnames[2]) { Sym *s = sym_get(argnames[2]); if (s) { Sym *r = sym_resolve(s); if (r && r->type == SYM_STR && r->sval) fp = fopen(r->sval, "r"); } }
                            if (!fp) { int fd = (int)argvals[2]; if (fd >= 0) fp = fdopen(fd, "r"); }
                            if (fp) { rv = getline(&line, &linelen, fp); if (rv >= 0 && line) { if (argnames[0]) sym_set_str(argnames[0], line); if (argnames[1]) sym_set_int(argnames[1], (long long)linelen); free(line); } fclose(fp); }
                        } else if (argcnt >= 1) {
                            /* paul(var) : read from stdin into var */
                            rv = getline(&line, &linelen, stdin);
                            if (rv >= 0 && line) {
                                if (argnames[0]) sym_set_str(argnames[0], line);
                                free(line);
                            }
                        }
                    }
                } else {
                    errorf("Call to undefined function '%s' at statement '%s'", ftrim, r);
                }
                for (int ii=0; ii<argcnt; ++ii) if (argnames[ii]) free(argnames[ii]);
            }
        }
        else if (s->kind == ST_CONTINUE) { /* continue */ return 2; }
        else if (s->kind == ST_BREAK) { /* break */ return 3; }
        else if (s->kind == ST_FOR) {
            if (!s->cond || !s->it_name) { s = s->next; continue; }
            char *cpy = my_strdup(s->cond); char *comma = strchr(cpy, ','); long long start = 0, end = 0; if (comma) { *comma='\0'; start = eval_int_expr(cpy); end = eval_int_expr(comma+1); } else { start = eval_int_expr(cpy); end = start; }
            for (long long ii = start; ii < end; ++ii) {
                sym_set_int(s->it_name, ii);
                int code = exec_stmt_list(s->body, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p, retcode_p);
                if (code == 1) { free(cpy); return 1; }
                if (code == 2) { /* continue */ continue; }
                if (code == 3) { /* break */ break; }
            }
            free(cpy);
        } else if (s->kind == ST_WHILE) {
            if (!s->cond) { s = s->next; continue; }
            int safety = 0;
            while (1) {
                long long v = eval_int_expr(s->cond);
                if (!v) break;
                int code = exec_stmt_list(s->body, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p, retcode_p);
                if (code == 1) return 1;
                if (code == 2) { /* continue */ ; }
                if (code == 3) break;
                if (++safety > 10000) break;
            }
        } else if (s->kind == ST_IF) {
            if (!s->cond) { s = s->next; continue; }
            /* debug: show condition and any referenced symbol before evaluation */
            printf("DEBUG: IF cond='%s'\n", s->cond);
            /* try to extract a simple identifier from the condition for debugging */
            char idtmp[128] = {0}; const char *q = s->cond; while (*q && !(((*q>='a'&&*q<='z')||(*q>='A'&&*q<='Z')||(*q=='_')))) q++; int ii = 0; while (*q && (((*q>='a'&&*q<='z')||(*q>='A'&&*q<='Z')||(*q>='0'&&*q<='9')||(*q=='_')) ) && ii < (int)sizeof(idtmp)-1) { idtmp[ii++] = *q++; } idtmp[ii] = '\0';
            if (idtmp[0]) {
                Sym *sx = sym_get(idtmp);
                if (sx) {
                    if (sx->type == SYM_INT) printf("DEBUG: symbol %s = %lld (int)\n", idtmp, sx->ival);
                    else printf("DEBUG: symbol %s = '%s' (str)\n", idtmp, sx->sval ? sx->sval : "(null)");
                } else {
                    printf("DEBUG: symbol %s not found\n", idtmp);
                }
            }
            long long v = eval_int_expr(s->cond);
            printf("DEBUG: cond '%s' => %lld\n", s->cond, v);
            if (v) {
                int code = exec_stmt_list(s->body, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p, retcode_p);
                if (code != 0) return code;
            } else {
                int code = exec_stmt_list(s->else_body, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p, retcode_p);
                if (code != 0) return code;
            }
        }
        s = s->next;
    }
    return 0;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') ++s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) { *end = '\0'; --end; }
    return s;
}

/* Extract the effective identifier from a left-hand-side string.
     Examples:
         "char *str" -> out="str"
         "valeurs[0]" -> out="valeurs[0]"
         "car.marque" -> out="car.marque"
     out must be provided with outsz bytes; function returns out. */
static char *extract_ident_from_lhs(const char *s, char *out, size_t outsz) {
        if (!s || !out || outsz == 0) return NULL;
        int len = strlen(s);
        int i = len - 1;
        // skip trailing whitespace
        while (i >= 0 && (s[i] == ' ' || s[i] == '\t')) --i;
        if (i < 0) { out[0] = '\0'; return out; }
        // now find start of token: allow letters, digits, '_', '.', '[', ']', '*'
        int end = i;
        // if ends with ']' find matching '[' and include index
        if (s[i] == ']') {
                // move left until '[' or non-digit
                while (i >= 0 && s[i] != '[') --i;
                // move further left to include identifier
                --i;
        }
        // move left while char is part of identifier or dot
        while (i >= 0 && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '.' || s[i] == '[' || s[i] == ']')) --i;
        int start = i + 1;
        int copylen = end - start + 1;
        if (copylen >= (int)outsz) copylen = outsz - 1;
        if (copylen > 0) memcpy(out, s + start, copylen); else out[0] = '\0';
        out[copylen] = '\0';
        return out;
}

/* Create a temporary literal string symbol in the current symbol table and return its name (caller must free). */
static int g_litstr_counter = 0;
static char *create_literal_string(const char *lit) {
    if (!lit) return NULL;
    /* lit points to a quoted string ("..." or '...') or just content; normalize by removing surrounding quotes if present */
    const char *start = lit;
    char q = 0;
    if (*start == '"' || *start == '\'') { q = *start; start++; }
    size_t len = strlen(start);
    const char *end = start + len - 1;
    if (q && len > 0 && *end == q) { len--; }
    char *buf = malloc(len + 1);
    memcpy(buf, start, len);
    buf[len] = '\0';
    char name[64]; snprintf(name, sizeof(name), "__litstr_%d", g_litstr_counter++);
    /* unescape escape sequences inside the literal before storing */
    char *un = unescape_cstring(buf);
    if (un) { sym_set_str(name, un); free(un); }
    else { sym_set_str(name, buf); }
    free(buf);
    return my_strdup(name);
}

/* Evaluate a '+'-concatenation expression and return a newly allocated string.
   Supports quoted strings, identifiers (string or int), and integer expressions.
   Example: src + "Hello" + 123
*/
static char *eval_concat_string(const char *expr) {
    if (!expr) return NULL;
    const char *p = expr;
    char *parts[64]; int np = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;
        if (*p == '"' || *p == '\'') {
            char q = *p;
            p++; const char *start = p;
            while (*p && *p != q) p++;
            int len = p - start;
            char *s = malloc(len + 1);
            if (!s) return NULL;
            memcpy(s, start, len); s[len] = '\0';
            parts[np++] = s;
            if (*p == q) p++;
        } else {
            /* collect until '+' at same level or end */
            const char *start = p;
            while (*p && *p != '+') p++;
            int len = p - start;
            char *tok = malloc(len + 1);
            if (!tok) return NULL;
            memcpy(tok, start, len); tok[len] = '\0';
            char *ttrim = trim(tok);
            /* try symbol lookup first */
            Sym *s = sym_get(ttrim);
            if (s) {
                Sym *r = sym_resolve(s);
                if (r->type == SYM_STR) {
                    parts[np++] = my_strdup(r->sval ? r->sval : "");
                } else {
                    char numbuf[64]; snprintf(numbuf, sizeof(numbuf), "%lld", r->ival);
                    parts[np++] = my_strdup(numbuf);
                }
            } else {
                /* not a known symbol: special-case indexed string access like name[idx]
                   so that concatenating a character (e.g. src[i]) appends the actual
                   character instead of its decimal representation. */
                char *brack = strchr(ttrim, '[');
                if (brack) {
                    /* extract base name and index expression */
                    int baselen = brack - ttrim;
                    char basename[256]; if (baselen >= (int)sizeof(basename)) baselen = sizeof(basename)-1; memcpy(basename, ttrim, baselen); basename[baselen] = '\0'; char *btrim = trim(basename);
                    const char *idxstart = brack + 1; const char *idxend = strchr(idxstart, ']'); char idxexpr[256]; if (idxend) { int ilen = idxend - idxstart; if (ilen >= (int)sizeof(idxexpr)) ilen = sizeof(idxexpr)-1; memcpy(idxexpr, idxstart, ilen); idxexpr[ilen] = '\0'; } else { idxexpr[0] = '\0'; }
                    Sym *basesym = sym_get(btrim);
                    if (basesym) {
                        Sym *bres = sym_resolve(basesym);
                        if (bres && bres->type == SYM_STR && bres->sval) {
                            int idxval = 0; if (idxexpr[0]) idxval = (int)eval_int_expr(idxexpr);
                            size_t sl = strlen(bres->sval);
                            char one[2] = {'\0','\0'};
                            if (idxval >= 0 && (size_t)idxval < sl) { one[0] = bres->sval[idxval]; }
                            parts[np++] = my_strdup(one);
                            free(tok);
                            continue;
                        }
                    }
                }
                /* fallback: try integer expression and convert to decimal string */
                long long v = eval_int_expr(ttrim);
                char numbuf[64]; snprintf(numbuf, sizeof(numbuf), "%lld", v);
                parts[np++] = my_strdup(numbuf);
            }
            free(tok);
        }
        /* skip spaces and a single '+' if present */
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '+') { p++; continue; }
    }

    /* compute total length */
    size_t total = 0;
    for (int i = 0; i < np; ++i) total += strlen(parts[i]);
    char *out = malloc(total + 1);
    if (!out) {
        for (int i = 0; i < np; ++i) free(parts[i]);
        return NULL;
    }
    out[0] = '\0';
    for (int i = 0; i < np; ++i) {
        strcat(out, parts[i]); free(parts[i]);
    }
    return out;
}

static Stmt *make_stmt(StmtKind k, const char *rawline) {
    Stmt *s = malloc(sizeof(Stmt));
    s->kind = k;
    s->raw = my_strdup(rawline);
    s->next = NULL;
    s->body = NULL;
    s->else_body = NULL;
    s->cond = NULL;
    s->it_name = NULL;
    s->indent = 0;
    return s;
}

static Stmt *make_stmt_indent(StmtKind k, const char *rawline, int indent) {
    Stmt *s = make_stmt(k, rawline);
    if (s) s->indent = indent;
    return s;
}

/* Basic syntax checks used during parsing: detect unclosed string literals and
   unbalanced parentheses (ignoring parentheses inside string literals). This
   produces a fatal error with the offending line to help the user fix syntax
   mistakes early. */
static void syntax_check_or_error(const char *line) {
    if (!line) return;
    int paren = 0;
    int in_str = 0; char quote = 0;
    for (const char *c = line; *c; ++c) {
        if (*c == '"' || *c == '\'') {
            if (!in_str) { in_str = 1; quote = *c; }
            else if (quote == *c) { in_str = 0; quote = 0; }
            continue;
        }
        if (in_str) continue;
        if (*c == '(') paren++;
        else if (*c == ')') paren--;
    }
    if (in_str) errorf("Syntax error: unclosed string literal: %s", line);
    if (paren != 0) errorf("Syntax error: unmatched parentheses: %s", line);
}

static void append_stmt(Stmt **head, Stmt *s) {
    if (!s) return;
    /* Run the top-level syntax checker on the raw line before accepting it. */
    syntax_check_or_error(s->raw);

    if (!*head) { *head = s; return; }
    Stmt *p = *head; while (p->next) p = p->next; p->next = s;
}

static Program *parse_program(const char *src) {
    Program *prog = calloc(1, sizeof(Program));
    char *copy = my_strdup(src);
    char *line = strtok(copy, "\n");
    Function *curf = NULL;
    // We'll simulate a stack of indentation levels by capturing leading spaces
    while (line) {
        char *rawline = line;
        // count leading spaces
        int indent = 0; while (rawline[indent] == ' ' || rawline[indent] == '\t') indent++;
        char *trimmed = trim(line);
        if (trimmed[0] == '\0') { line = strtok(NULL, "\n"); continue; }
        // top-level function
        if (strncmp(trimmed, "Deschodt ", 9) == 0) {
            // parse header: Deschodt Name(params) -> ret
            char namebuf[128] = {0};
            char paramsbuf[256] = {0};
            char retdat[64] = {0};
            const char *p = trimmed + 9;
            // extract name up to '('
            const char *paren = strchr(p, '(');
            if (!paren) { line = strtok(NULL, "\n"); continue; }
            size_t nlen = paren - p;
            if (nlen >= sizeof(namebuf)) nlen = sizeof(namebuf)-1;
            memcpy(namebuf, p, nlen);
            // params
            const char *close = strchr(paren, ')');
            if (close && close > paren+1) {
                size_t plen = close - (paren+1);
                if (plen >= sizeof(paramsbuf)) plen = sizeof(paramsbuf)-1;
                memcpy(paramsbuf, paren+1, plen);
            }
            const char *arr = strstr(close ? close : trimmed, "->");
            if (arr) {
                arr += 2;
                while (*arr == ' ' || *arr == '\t') ++arr;
                strncpy(retdat, arr, sizeof(retdat)-1);
            }
            Function *f = malloc(sizeof(Function));
            f->name = my_strdup(namebuf);
            f->params = my_strdup(paramsbuf);
            f->ret_type = my_strdup(retdat);
            f->body = NULL;
            f->next = NULL;
            // check duplicate or reserved names
            for (Function *ex = prog->functions; ex; ex = ex->next) {
                if (strcmp(ex->name, f->name) == 0) errorf("Duplicate function '%s' defined", f->name);
            }
            if (strcasecmp(f->name, "Deschodt") == 0) errorf("Invalid function name '%s' (reserved)", f->name);
            // attach
            if (!prog->functions) prog->functions = f; else {
                Function *t = prog->functions; while (t->next) t = t->next; t->next = f;
            }
            curf = f;
            // read following indented lines as body
            char *peek = strtok(NULL, "\n");
            while (peek) {
                char *rawpeek = peek; int pindent = 0;
                while (rawpeek[pindent] == ' ' || rawpeek[pindent] == '\t') pindent++;
                char *tpeek = trim(peek);
                if (tpeek[0] == '\0') { peek = strtok(NULL, "\n"); continue; }
                // stop when indentation goes back to top-level
                if (pindent == 0) break;
                // parse nested statements: for, while, if, peric, eric, assign, return
                if (strncmp(tpeek, "peric(", 6) == 0) append_stmt(&curf->body, make_stmt_indent(ST_PERIC, tpeek, pindent));
                else if (strncmp(tpeek, "paul(", 5) == 0) append_stmt(&curf->body, make_stmt_indent(ST_PAUL, tpeek, pindent));
                else if (strncmp(tpeek, "eric ", 5) == 0) append_stmt(&curf->body, make_stmt_indent(ST_ERIC_DECL, tpeek, pindent));
                else if (strncmp(tpeek, "deschodt", 8) == 0) append_stmt(&curf->body, make_stmt_indent(ST_RETURN, tpeek, pindent));
                else if (strncmp(tpeek, "deschontinue", 12) == 0) append_stmt(&curf->body, make_stmt_indent(ST_CONTINUE, tpeek, pindent));
                else if (strncmp(tpeek, "deschreak", 9) == 0) append_stmt(&curf->body, make_stmt_indent(ST_BREAK, tpeek, pindent));
                else if (strncmp(tpeek, "aer ", 4) == 0) {
                    // format: aer i in range(0, 5):
                    Stmt *st = make_stmt(ST_FOR, tpeek);
                    // extract iterator name
                    const char *inpos = strstr(tpeek, " in ");
                    if (inpos) {
                        int inlen = inpos - (tpeek + 4);
                        char itn[64]; if (inlen>=63) inlen=63; memcpy(itn, tpeek+4, inlen); itn[inlen]='\0'; st->it_name = my_strdup(itn);
                        // store range args in cond
                        const char *rpos = strstr(inpos, "range("); if (rpos) { const char *open = strchr(rpos, '('); const char *close = strchr(rpos, ')'); if (open && close) { size_t clen = close-open-1; st->cond = malloc(clen+1); memcpy(st->cond, open+1, clen); st->cond[clen]='\0'; } }
                    }
                    st->indent = pindent;
                    append_stmt(&curf->body, st);
                    /* consume following indented lines as the for-body */
                    char *inner = strtok(NULL, "\n");
                    while (inner) {
                        char *iraw = inner; int iindent = 0; while (iraw[iindent]==' '||iraw[iindent]=='\t') iindent++; char *tinner = trim(inner);
                        if (tinner[0] == '\0') { inner = strtok(NULL, "\n"); continue; }
                        if (iindent <= pindent) break; /* end of this block */
                        /* recognize simple statements inside body */
                        if (strncmp(tinner, "peric(", 6) == 0) append_stmt(&st->body, make_stmt_indent(ST_PERIC, tinner, iindent));
                        else if (strncmp(tinner, "eric ", 5) == 0) append_stmt(&st->body, make_stmt_indent(ST_ERIC_DECL, tinner, iindent));
                        else if (strncmp(tinner, "erif ", 5) == 0) {
                            /* nested if inside for */
                            Stmt *ifs = make_stmt(ST_IF, tinner);
                            const char *op = strchr(tinner, '('); const char *cl = strchr(tinner, ')'); if (op && cl && cl > op) { size_t clen = cl-op-1; ifs->cond = malloc(clen+1); memcpy(ifs->cond, op+1, clen); ifs->cond[clen]='\0'; }
                            ifs->indent = iindent;
                            /* consume nested if-body lines */
                            char *inner2 = strtok(NULL, "\n");
                            while (inner2) {
                                char *r2 = inner2; int ind2 = 0; while (r2[ind2]==' '||r2[ind2]=='\t') ind2++; char *t2 = trim(inner2);
                                if (t2[0] == '\0') { inner2 = strtok(NULL, "\n"); continue; }
                                if (ind2 <= iindent) break;
                                if (strncmp(t2, "peric(", 6) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_PERIC, t2, ind2));
                                else if (strncmp(t2, "eric ", 5) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_ERIC_DECL, t2, ind2));
                                else if (strncmp(t2, "deschodt", 8) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_RETURN, t2, ind2));
                                else if (strncmp(t2, "deschontinue", 12) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_CONTINUE, t2, ind2));
                                else if (strncmp(t2, "deschreak", 9) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_BREAK, t2, ind2));
                                else if (strchr(t2, '=') != NULL) {
                                    if (looks_like_call(t2)) append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                    else append_stmt(&ifs->body, make_stmt_indent(ST_ASSIGN, t2, ind2));
                                } else append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                inner2 = strtok(NULL, "\n");
                            }
                            append_stmt(&st->body, ifs);
                            inner = inner2; if (!inner) break; continue;
                        }
                        else if (strncmp(tinner, "deschodt", 8) == 0) append_stmt(&st->body, make_stmt_indent(ST_RETURN, tinner, iindent));
                        else if (strncmp(tinner, "deschontinue", 12) == 0) append_stmt(&st->body, make_stmt_indent(ST_CONTINUE, tinner, iindent));
                        else if (strncmp(tinner, "deschreak", 9) == 0) append_stmt(&st->body, make_stmt_indent(ST_BREAK, tinner, iindent));
                        else if (strchr(tinner, '=') != NULL) {
                            if (looks_like_call(tinner)) append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                            else append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        } else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                        inner = strtok(NULL, "\n");
                    }
                    /* resume outer parse from the line that ended the block */
                    peek = inner; if (!peek) break;
                    continue;
                }
                else if (strncmp(tpeek, "darius ", 7) == 0) {
                    Stmt *st = make_stmt(ST_WHILE, tpeek);
                    // capture condition inside parentheses
                    const char *op = strchr(tpeek, '('); const char *cl = strchr(tpeek, ')'); if (op && cl && cl > op) { size_t clen = cl-op-1; st->cond = malloc(clen+1); memcpy(st->cond, op+1, clen); st->cond[clen]='\0'; }
                    st->indent = pindent;
                    append_stmt(&curf->body, st);
                    /* consume following indented lines as the while-body */
                    char *innerw = strtok(NULL, "\n");
                    while (innerw) {
                        char *iraw = innerw; int iindent = 0; while (iraw[iindent]==' '||iraw[iindent]=='\t') iindent++; char *tinner = trim(innerw);
                        if (tinner[0] == '\0') { innerw = strtok(NULL, "\n"); continue; }
                        if (iindent <= pindent) break;
                        if (strncmp(tinner, "darius ", 7) == 0) {
                            /* nested while inside while */
                            Stmt *nwh = make_stmt(ST_WHILE, tinner);
                            const char *nop = strchr(tinner, '('); const char *ncl = strchr(tinner, ')');
                            if (nop && ncl && ncl > nop) { size_t nlen = ncl - nop - 1; nwh->cond = malloc(nlen + 1); memcpy(nwh->cond, nop+1, nlen); nwh->cond[nlen] = '\0'; }
                            nwh->indent = iindent;
                            /* consume nested while-body lines */
                            char *inner2 = strtok(NULL, "\n");
                            while (inner2) {
                                char *r2 = inner2; int ind2 = 0; while (r2[ind2]==' '||r2[ind2]=='\t') ind2++; char *t2 = trim(inner2);
                                            if (t2[0] == '\0') { inner2 = strtok(NULL, "\n"); continue; }
                                            if (ind2 <= iindent) break;
                                            if (strncmp(t2, "peric(", 6) == 0) append_stmt(&nwh->body, make_stmt_indent(ST_PERIC, t2, ind2));
                                            else if (strncmp(t2, "eric ", 5) == 0) append_stmt(&nwh->body, make_stmt_indent(ST_ERIC_DECL, t2, ind2));
                                            else if (strncmp(t2, "deschodt", 8) == 0) append_stmt(&nwh->body, make_stmt_indent(ST_RETURN, t2, ind2));
                                            else if (strncmp(t2, "deschontinue", 12) == 0) append_stmt(&nwh->body, make_stmt_indent(ST_CONTINUE, t2, ind2));
                                            else if (strncmp(t2, "deschreak", 9) == 0) append_stmt(&nwh->body, make_stmt_indent(ST_BREAK, t2, ind2));
                                            else if (strchr(t2, '=') != NULL) {
                                                if (looks_like_call(t2)) append_stmt(&nwh->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                                else append_stmt(&nwh->body, make_stmt_indent(ST_ASSIGN, t2, ind2));
                                            } else append_stmt(&nwh->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                inner2 = strtok(NULL, "\n");
                            }
                            append_stmt(&st->body, nwh);
                            innerw = inner2; if (!innerw) break; continue;
                        } else if (strncmp(tinner, "erif ", 5) == 0) {
                            /* nested if inside while */
                            Stmt *ifs = make_stmt(ST_IF, tinner);
                            const char *op = strchr(tinner, '('); const char *cl = strchr(tinner, ')'); if (op && cl && cl > op) { size_t clen = cl-op-1; ifs->cond = malloc(clen+1); memcpy(ifs->cond, op+1, clen); ifs->cond[clen]='\0'; }
                            ifs->indent = iindent;
                            char *inner2 = strtok(NULL, "\n");
                            while (inner2) {
                                char *r2 = inner2; int ind2 = 0; while (r2[ind2]==' '||r2[ind2]=='\t') ind2++; char *t2 = trim(inner2);
                                if (t2[0] == '\0') { inner2 = strtok(NULL, "\n"); continue; }
                                if (ind2 <= iindent) break;
                                if (strncmp(t2, "peric(", 6) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_PERIC, t2, ind2));
                                else if (strncmp(t2, "eric ", 5) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_ERIC_DECL, t2, ind2));
                                else if (strncmp(t2, "deschodt", 8) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_RETURN, t2, ind2));
                                else if (strncmp(t2, "deschontinue", 12) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_CONTINUE, t2, ind2));
                                else if (strncmp(t2, "deschreak", 9) == 0) append_stmt(&ifs->body, make_stmt_indent(ST_BREAK, t2, ind2));
                                else if (strchr(t2, '=') != NULL) {
                                    if (looks_like_call(t2)) append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                    else append_stmt(&ifs->body, make_stmt_indent(ST_ASSIGN, t2, ind2));
                                } else append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                inner2 = strtok(NULL, "\n");
                            }
                            append_stmt(&st->body, ifs);
                            innerw = inner2; if (!innerw) break; continue;
                        }
                        if (strncmp(tinner, "peric(", 6) == 0) append_stmt(&st->body, make_stmt_indent(ST_PERIC, tinner, iindent));
                        else if (strncmp(tinner, "eric ", 5) == 0) append_stmt(&st->body, make_stmt_indent(ST_ERIC_DECL, tinner, iindent));
                        else if (strncmp(tinner, "deschodt", 8) == 0) append_stmt(&st->body, make_stmt_indent(ST_RETURN, tinner, iindent));
                        else if (strncmp(tinner, "deschontinue", 12) == 0) append_stmt(&st->body, make_stmt_indent(ST_CONTINUE, tinner, iindent));
                        else if (strncmp(tinner, "deschreak", 9) == 0) append_stmt(&st->body, make_stmt_indent(ST_BREAK, tinner, iindent));
                        else if (strchr(tinner, '=') != NULL) {
                            if (looks_like_call(tinner)) append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                            else append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        } else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                        innerw = strtok(NULL, "\n");
                    }
                    peek = innerw; if (!peek) break;
                    continue;
                }
                else if (strncmp(tpeek, "erif ", 5) == 0) {
                    Stmt *st = make_stmt(ST_IF, tpeek);
                    const char *op = strchr(tpeek, '('); const char *cl = strchr(tpeek, ')'); if (op && cl && cl > op) { size_t clen = cl-op-1; st->cond = malloc(clen+1); memcpy(st->cond, op+1, clen); st->cond[clen]='\0'; }
                    st->indent = pindent;
                    append_stmt(&curf->body, st);
                    /* consume following indented lines as the if-body */
                    char *inneri = strtok(NULL, "\n");
                    while (inneri) {
                        char *iraw = inneri; int iindent = 0; while (iraw[iindent]==' '||iraw[iindent]=='\t') iindent++; char *tinner = trim(inneri);
                        if (tinner[0] == '\0') { inneri = strtok(NULL, "\n"); continue; }
                        if (iindent <= pindent) break;
                        if (strncmp(tinner, "peric(", 6) == 0) append_stmt(&st->body, make_stmt_indent(ST_PERIC, tinner, iindent));
                        else if (strncmp(tinner, "eric ", 5) == 0) append_stmt(&st->body, make_stmt_indent(ST_ERIC_DECL, tinner, iindent));
                        else if (strncmp(tinner, "deschodt", 8) == 0) append_stmt(&st->body, make_stmt_indent(ST_RETURN, tinner, iindent));
                        else if (strncmp(tinner, "deschontinue", 12) == 0) append_stmt(&st->body, make_stmt_indent(ST_CONTINUE, tinner, iindent));
                        else if (strncmp(tinner, "deschreak", 9) == 0) append_stmt(&st->body, make_stmt_indent(ST_BREAK, tinner, iindent));
                        else if (strchr(tinner, '=') != NULL) {
                            if (looks_like_call(tinner)) append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                            else append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        } else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
                        inneri = strtok(NULL, "\n");
                    }
                    peek = inneri; if (!peek) break; 
                    continue;
                }
                else if (strstr(tpeek, "deschelse") == tpeek) {
                    printf("processing deschelse\n");
                    // attach else to last if
                    // find last statement in curf->body
                    Stmt *last = curf->body; while (last && last->next) last = last->next; if (last && last->kind == ST_IF) {
                        // consume following indented lines as else body
                        char *elsepeek = strtok(NULL, "\n");
                        while (elsepeek) {
                            char *rt = elsepeek; int rind = 0; while (rt[rind]==' '||rt[rind]=='\t') rind++; char *ttr = trim(elsepeek);
                            if (ttr[0] == '\0') { elsepeek = strtok(NULL, "\n"); continue; }
                                /* stop else-body when indentation returns to or is less than the if line */
                                if (rind <= pindent) break;
                                if (strncmp(ttr, "peric(", 6) == 0) { printf("appending to else_body: %s\n", ttr); append_stmt(&last->else_body, make_stmt(ST_PERIC, ttr)); }
                                else if (strncmp(ttr, "eric ", 5) == 0) append_stmt(&last->else_body, make_stmt(ST_ERIC_DECL, ttr));
                                else if (strncmp(ttr, "deschodt", 8) == 0) append_stmt(&last->else_body, make_stmt(ST_RETURN, ttr));
                                else if (strncmp(ttr, "deschontinue", 12) == 0) append_stmt(&last->else_body, make_stmt(ST_CONTINUE, ttr));
                                else if (strncmp(ttr, "deschreak", 9) == 0) append_stmt(&last->else_body, make_stmt(ST_BREAK, ttr));
                                else if (strchr(ttr, '=') != NULL) {
                                    if (looks_like_call(ttr)) append_stmt(&last->else_body, make_stmt(ST_OTHER, ttr));
                                    else append_stmt(&last->else_body, make_stmt(ST_ASSIGN, ttr));
                                } else append_stmt(&last->else_body, make_stmt(ST_OTHER, ttr));
                            elsepeek = strtok(NULL, "\n");
                        }
                        // resume parse from elsepeek
                        peek = elsepeek; line = peek; continue;
                    }
                }
                else if (strchr(tpeek, '=') != NULL) {
                    if (looks_like_call(tpeek)) append_stmt(&curf->body, make_stmt(ST_OTHER, tpeek));
                    else append_stmt(&curf->body, make_stmt(ST_ASSIGN, tpeek));
                } else append_stmt(&curf->body, make_stmt(ST_OTHER, tpeek));
                peek = strtok(NULL, "\n");
            }
            // continue from peek (which might be top-level) - strtok state already advanced, so set line accordingly
            line = peek;
            continue;
        }
        // other top-level constructs ignored for now
        line = strtok(NULL, "\n");
    }
    free(copy);
    return prog;
}

static void free_program(Program *p) {
    if (!p) return;
    Function *f = p->functions;
    while (f) {
        Function *nf = f->next;
        free(f->name); free(f->params); free(f->ret_type);
        Stmt *s = f->body;
        while (s) { Stmt *ns = s->next; free(s->raw); free(s); s = ns; }
        free(f);
        f = nf;
    }
    free(p);
}

/* Scan the filtered source for top-level desconst and desenum declarations
   and populate the compile-time symbol table accordingly. */
static void process_top_level_decls(const char *filtered) {
    char *copy = my_strdup(filtered);
    char *line = strtok(copy, "\n");
    while (line) {
        char *t = trim(line);
        if (strncmp(t, "desconst ", 9) == 0) {
            const char *p = t + 9;
            const char *eq = strchr(p, '=');
            if (eq) {
                const char *name_start = p; while (*name_start==' '||*name_start=='\t') name_start++;
                const char *name_end = eq; while (name_end > name_start && (*(name_end-1)==' '||*(name_end-1)=='\t')) name_end--;
                int nlen = name_end - name_start; char name[128]; if (nlen >= (int)sizeof(name)) nlen = sizeof(name)-1; memcpy(name, name_start, nlen); name[nlen] = '\0';
                const char *rhs = eq + 1; while (*rhs==' '||*rhs=='\t') rhs++;
                // if quoted string
                if (rhs[0] == '"' || rhs[0] == '\'') {
                    char q = rhs[0]; const char *q2 = strchr(rhs+1, q); if (!q2) q2 = rhs+1; int vlen = q2 - (rhs+1); char val[256]; if (vlen >= (int)sizeof(val)) vlen = sizeof(val)-1; memcpy(val, rhs+1, vlen); val[vlen] = '\0';
                    sym_set_str(name, val);
                } else {
                    // decide int vs string (float contains '.')
                    int is_float = 0; for (const char *c = rhs; *c; ++c) if (*c == '.') { is_float = 1; break; }
                    if (is_float) {
                        // keep textual representation
                        char val[256]; int vlen = 0; while (rhs[vlen] && rhs[vlen] != ' ' && rhs[vlen] != '\t' && rhs[vlen] != '\n') vlen++; if (vlen >= (int)sizeof(val)) vlen = sizeof(val)-1; memcpy(val, rhs, vlen); val[vlen] = '\0';
                        sym_set_str(name, val);
                    } else {
                        long long v = eval_int_expr(rhs);
                        sym_set_int(name, v);
                    }
                }
            }
        } else if (strncmp(t, "desenum ", 8) == 0) {
            // collect following indented names as enum members
            char *peek = strtok(NULL, "\n"); int idx = 0;
            while (peek) {
                char *rawpeek = peek; int pindent = 0; while (rawpeek[pindent]==' '||rawpeek[pindent]=='\t') pindent++; char *tpeek = trim(peek);
                if (tpeek[0] == '\0') { peek = strtok(NULL, "\n"); continue; }
                if (pindent == 0) { break; }
                // tpeek is a member name
                sym_set_int(tpeek, idx++);
                peek = strtok(NULL, "\n");
            }
            // continue parse from peek
        }
        line = strtok(NULL, "\n");
    }
    free(copy);
}

static void print_program(Program *p) {
    if (!p) return;
    Function *f = p->functions;
    while (f) {
        printf("Function %s(%s) -> %s\n", f->name, f->params, f->ret_type);
        Stmt *s = f->body;
        while (s) {
            const char *kname = "OTHER";
            if (s->kind == ST_PERIC) kname = "PERIC";
            if (s->kind == ST_PAUL) kname = "PAUL";
            if (s->kind == ST_ERIC_DECL) kname = "ERIC";
            if (s->kind == ST_ASSIGN) kname = "ASSIGN";
            if (s->kind == ST_RETURN) kname = "RETURN";
            if (s->kind == ST_FOR) kname = "FOR";
            if (s->kind == ST_WHILE) kname = "WHILE";
            if (s->kind == ST_IF) kname = "IF";
            printf("  [%s] %s\n", kname, s->raw);
            if (s->kind == ST_IF) {
                Stmt *b = s->body;
                while (b) { printf("    (if-body) %s\n", b->raw); b = b->next; }
                Stmt *e = s->else_body;
                while (e) { printf("    (else-body) %s\n", e->raw); e = e->next; }
            } else if (s->kind == ST_FOR || s->kind == ST_WHILE) {
                Stmt *b = s->body;
                while (b) { printf("    (body) %s\n", b->raw); b = b->next; }
            }
            s = s->next;
        }
        f = f->next;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <src1.tslang> [<src2.tslang> ...] <out_binary>\n", argv[0]);
        return 1;
    }
    const char *out_path = argv[argc-1];
    /* concatenate all input sources (argv[1..argc-2]) into one buffer, handling johnsenat includes */
    size_t total_cap = 4096; char *buf = malloc(total_cap); if (!buf) { fprintf(stderr, "alloc fail\n"); return 1; } buf[0] = '\0';
    for (int ai = 1; ai < argc-1; ++ai) {
        const char *src_path = argv[ai];
        FILE *s = fopen(src_path, "rb");
        if (!s) { perror("fopen src"); return 1; }
        fseek(s, 0, SEEK_END);
        long sz = ftell(s);
        fseek(s, 0, SEEK_SET);
        char *part = malloc(sz + 1);
        if (!part) { fclose(s); fprintf(stderr, "alloc fail\n"); return 1; }
        fread(part, 1, sz, s);
        part[sz] = '\0';
        fclose(s);
        /* append part to buf */
        size_t need = strlen(buf) + strlen(part) + 2;
        if (need > total_cap) { total_cap = need * 2; buf = realloc(buf, total_cap); }
        strcat(buf, part);
        strcat(buf, "\n");
        free(part);
    }

    // Remove 'desnote' comment lines and process johnsenat includes into a filtered buffer
    char *filtered = malloc(strlen(buf) + 1024);
    filtered[0] = '\0';
    char *copy2 = my_strdup(buf);
    char *ln = strtok(copy2, "\n");
    while (ln) {
        char *t = trim(ln);
        if (strncmp(t, "desnote", 7) == 0) { ln = strtok(NULL, "\n"); continue; }
        if (strncmp(t, "johnsenat ", 10) == 0) {
            const char *inc = t + 10; while (*inc == ' '||*inc=='\t') ++inc; char *incf = trim(my_strdup((char*)inc));
            FILE *h = fopen(incf, "rb");
            if (h) {
                fseek(h, 0, SEEK_END); long hsz = ftell(h); fseek(h, 0, SEEK_SET);
                char *hbuf = malloc(hsz + 1); if (hbuf) { fread(hbuf,1,hsz,h); hbuf[hsz]='\0'; strcat(filtered, hbuf); strcat(filtered, "\n"); free(hbuf); }
                fclose(h);
            } else {
                fprintf(stderr, "warning: include file '%s' not found\n", incf);
            }
            free(incf);
            ln = strtok(NULL, "\n");
            continue;
        }
        strcat(filtered, ln);
        strcat(filtered, "\n");
        ln = strtok(NULL, "\n");
    }

    // Process top-level consts/enums, then parse program and execute the main function at compile-time to collect messages
    process_top_level_decls(filtered);
    Program *prog = parse_program(filtered);
    // debug: print parsed AST
    print_program(prog);
    g_program = prog;
    Function *f = prog->functions;
    Function *mainf = NULL;
    while (f) { if (strcmp(f->name, "Eric") == 0) { mainf = f; break; } f = f->next; }
    int r;
    if (!mainf) {
        fprintf(stderr, "No main function Deschodt Eric() found\n");
        r = 1;
    } else {
        char **msgs2; unsigned int *msg_lens2; int n_msgs2; int ret2;
        execute_function_compiletime(mainf, &msgs2, &msg_lens2, &n_msgs2, &ret2);
        r = emit_elf(out_path, (const char**)msgs2, msg_lens2, n_msgs2, ret2);
        if (r == 0) {
            printf("Wrote %s\n", out_path);
        }
    }
    free_program(prog);
    free(filtered);
    free(copy2);
    return r;
}

/* Implementations for function lookup and compile-time calls (placed after sym helpers) */
static Function *find_function(const char *name) {
    if (!g_program) return NULL;
    Function *f = g_program->functions;
    while (f) {
        if (strcmp(f->name, name) == 0) return f;
        f = f->next;
    }
    return NULL;
}

/* New helper: call a function at compile-time with potential by-ref args.
   arg_names: array of strings for each arg (if by_ref[i]==1, arg_names[i] is the variable name in caller to alias),
   otherwise arg_names[i] may be NULL and arg_vals[i] used.
*/
static long long call_function_compiletime_with_refs(Function *fn, long long *arg_vals, char **arg_names, int *by_ref, int nargs, const char *assign_lhs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p) {
    if (!fn) return 0;
    // Save caller table and create fresh sym_table for callee
    Sym *saved = sym_table;
    Sym *caller_table = saved; // keep pointer to locate targets
    sym_table = NULL; // new callee table
    // bind parameters
    if (fn->params) {
        const char *p = fn->params;
        char *cpy = my_strdup(p);
        char *tok = strtok(cpy, ",");
        int idx = 0;
        while (tok && idx < nargs) {
            char *t = trim(tok);
            char *arr = strstr(t, "->");
            char namebuf[128];
            if (arr) { int ln = arr - t; if (ln >= (int)sizeof(namebuf)) ln = sizeof(namebuf)-1; memcpy(namebuf, t, ln); namebuf[ln] = '\0'; }
            else { strncpy(namebuf, t, sizeof(namebuf)-1); namebuf[sizeof(namebuf)-1] = '\0'; }
            char *ntrim = trim(namebuf);
            int param_is_array = 0;
            if (arr) {
                if (strchr(arr, '[') || strstr(arr, "[]")) param_is_array = 1;
            }

            if (arg_names && arg_names[idx]) {
                /* if caller provided an indexed name like base[3], alias that specific element */
                char *brc = strchr(arg_names[idx], '[');
                if (brc) {
                    /* map param_name[index] -> caller base[index] */
                    char base[128]; int blen = brc - arg_names[idx]; if (blen >= (int)sizeof(base)) blen = sizeof(base)-1; memcpy(base, arg_names[idx], blen); base[blen] = '\0'; char *idxpart = brc+1; char *cr = strchr(idxpart, ']'); if (cr) *cr='\0'; char caller_key[256]; snprintf(caller_key, sizeof(caller_key), "%s[%s]", base, idxpart);
                    Sym *t2 = sym_find_in_table(caller_table, caller_key);
                        if (t2) {
                        /* create matching callee symbol name: if param is array, create param[index], else alias param name */
                        if (param_is_array) {
                            char callee_key[256]; snprintf(callee_key, sizeof(callee_key), "%s[%s]", ntrim, idxpart);
                            /* create alias in callee table (current sym_table) */
                            sym_set_alias(callee_key, t2);
                            /* also add alias into caller_table */
                            caller_table = sym_set_alias_in_table(caller_table, callee_key, t2);
                            printf("DEBUG: alias created %s -> %s\n", callee_key, caller_key);
                        } else {
                            sym_set_alias(ntrim, t2);
                            caller_table = sym_set_alias_in_table(caller_table, ntrim, t2);
                            printf("DEBUG: alias created %s -> %s\n", ntrim, caller_key);
                        }
                        idx++; tok = strtok(NULL, ",");
                        continue;
                    }
                }
                /* if param expects array, try to alias consecutive elements from caller base[0..] */
                if (param_is_array) {
                    char base[128]; strncpy(base, arg_names[idx], sizeof(base)-1); base[sizeof(base)-1] = '\0'; char *br = strchr(base, '['); if (br) *br='\0';
                    int found_any = 0;
                        for (int k = 0; k < 1024; ++k) {
                        char caller_key[256]; snprintf(caller_key, sizeof(caller_key), "%s[%d]", base, k);
                        Sym *t2 = sym_find_in_table(caller_table, caller_key);
                        if (!t2) break;
                        char callee_key[256]; snprintf(callee_key, sizeof(callee_key), "%s[%d]", ntrim, k);
                        sym_set_alias(callee_key, t2);
                        caller_table = sym_set_alias_in_table(caller_table, callee_key, t2);
                        printf("DEBUG: alias created %s -> %s\n", callee_key, caller_key);
                        found_any = 1;
                    }
                    if (found_any) { idx++; tok = strtok(NULL, ","); continue; }
                    /* fallback to aliasing base[0] if present */
                    char elem0[256]; snprintf(elem0, sizeof(elem0), "%s[0]", arg_names[idx]); Sym *t0 = sym_find_in_table(caller_table, elem0);
                    if (t0) { sym_set_alias(ntrim, t0); caller_table = sym_set_alias_in_table(caller_table, ntrim, t0); printf("DEBUG: alias created %s -> %s\n", ntrim, elem0); idx++; tok = strtok(NULL, ","); continue; }
                }
                /* try struct-field mapping: if caller_table has entries like 'name.field', create callee.alias 'param.field' -> caller.name.field */
                {
                    size_t base_len = strlen(arg_names[idx]);
                    int mapped_any = 0;
                    for (Sym *pp = caller_table; pp; pp = pp->next) {
                        if (strncmp(pp->name, arg_names[idx], base_len) == 0 && pp->name[base_len] == '.') {
                            const char *field = pp->name + base_len + 1;
                            char callee_field[256]; snprintf(callee_field, sizeof(callee_field), "%s.%s", ntrim, field);
                            sym_set_alias(callee_field, pp);
                            caller_table = sym_set_alias_in_table(caller_table, callee_field, pp);
                            printf("DEBUG: alias created %s -> %s\n", callee_field, pp->name);
                            mapped_any = 1;
                        }
                    }
                    if (mapped_any) { idx++; tok = strtok(NULL, ","); continue; }
                }
                /* otherwise, try aliasing whole symbol by name */
                Sym *target = sym_find_in_table(caller_table, arg_names[idx]);
                if (target) { sym_set_alias(ntrim, target); idx++; tok = strtok(NULL, ","); continue; }
            }

            /* fallback: bind by value */
            sym_set_int(ntrim, arg_vals ? arg_vals[idx] : 0);
            idx++; tok = strtok(NULL, ",");
        }
        free(cpy);
    }
    int local_max = 4; char **local_msgs = malloc(sizeof(char*) * local_max); unsigned int *local_lens = malloc(sizeof(unsigned int) * local_max); int local_n = 0; int retcode = 0;
    // set globals so nested calls inside callee append into local_msgs
    char ***old_msgs_p = g_msgs_p; unsigned int **old_msg_lens_p = g_msg_lens_p; int *old_n_msgs_p = g_n_msgs_p; int *old_max_msgs_p = g_max_msgs_p;
    g_msgs_p = &local_msgs; g_msg_lens_p = &local_lens; g_n_msgs_p = &local_n; g_max_msgs_p = &local_max;
    /* reset the nested-call string flag and clear any leftover string return before executing callee body */
    if (g_last_return_str) { free(g_last_return_str); g_last_return_str = NULL; }
    g_last_return_was_str = 0;
    exec_stmt_list(fn->body, &local_msgs, &local_lens, &local_n, &local_max, &retcode);
    // restore globals
    g_msgs_p = old_msgs_p; g_msg_lens_p = old_msg_lens_p; g_n_msgs_p = old_n_msgs_p; g_max_msgs_p = old_max_msgs_p;
    /* If callee produced a string return (g_last_return_str) and caller requested a target name,
       write that string into the caller_table under assign_lhs. This supports patterns like
       `tab[i] = extract(...)` where the extract() return should populate the caller element. */
    /* Only treat a callee string-return as the function's return value if the
       function's declared return type is a string/pointer (e.g. contains "char" or '*').
       This avoids cases where a nested helper produced g_last_return_str but the
       callee itself is meant to return an integer. */
    int callee_declares_string_ret = 0;
    if (fn && fn->ret_type) {
        if (strstr(fn->ret_type, "char") || strchr(fn->ret_type, '*')) callee_declares_string_ret = 1;
    }
    if (g_last_return_str && assign_lhs && assign_lhs[0] && callee_declares_string_ret) {
        printf("DEBUG: call returned string, assigning to '%s'\n", assign_lhs);
        /* Insert string directly into caller_table without changing global sym_table. */
        caller_table = sym_set_str_in_table(caller_table, assign_lhs, g_last_return_str);
        /* debug: confirm the symbol was created in caller_table */
        Sym *just = sym_find_in_table(caller_table, assign_lhs);
        if (just) {
            Sym *jr = sym_resolve(just);
            if (jr->type == SYM_STR) printf("DEBUG: assigned caller symbol '%s' -> STR '%s'\n", assign_lhs, jr->sval ? jr->sval : "(null)");
            else if (jr->type == SYM_INT) printf("DEBUG: assigned caller symbol '%s' -> INT %lld\n", assign_lhs, jr->ival);
            else printf("DEBUG: assigned caller symbol '%s' -> ALIAS\n", assign_lhs);
        } else {
            printf("DEBUG: assigned caller symbol '%s' not found after sym_set_str_in_table\n", assign_lhs);
        }
        free(g_last_return_str); g_last_return_str = NULL;
        g_last_return_was_str = 1;
    } else {
        /* clear any stray last-return string to avoid leaking into the caller */
        if (g_last_return_str) { free(g_last_return_str); g_last_return_str = NULL; }
        g_last_return_was_str = 0;
    }
    /* If caller requested to receive callee-created symbols with the given LHS name,
       copy matching callee symbols (exact name, or name[...] or name.field) into caller_table.
       This allows code like `tab = foo(...)` where `foo` creates `tab[i]` entries to populate
       the caller's `tab` symbol. */
    if (assign_lhs && assign_lhs[0]) {
        printf("DEBUG: callee_table symbols:\n");
        for (Sym *pp = sym_table; pp; pp = pp->next) {
            if (pp->type == SYM_INT) printf("  %s (type=INT val=%lld)\n", pp->name, pp->ival);
            else if (pp->type == SYM_STR) printf("  %s (type=STR sval='%s')\n", pp->name, pp->sval?pp->sval:"(null)");
            else if (pp->type == SYM_ALIAS) printf("  %s (type=ALIAS -> %s)\n", pp->name, pp->alias_target?pp->alias_target->name:"(null)");
            else printf("  %s (type=%d)\n", pp->name, pp->type);
        }
        size_t alen = strlen(assign_lhs);
        for (Sym *pp = sym_table; pp; pp = pp->next) {
            if (strcmp(pp->name, assign_lhs) == 0 || (strncmp(pp->name, assign_lhs, alen) == 0 && (pp->name[alen] == '[' || pp->name[alen] == '.'))) {
                printf("DEBUG: copying callee symbol '%s' to caller_table for assign_lhs '%s'\n", pp->name, assign_lhs);
                Sym *r = sym_resolve(pp);
                if (r) {
                    if (r->type == SYM_INT) caller_table = sym_set_int_in_table(caller_table, pp->name, r->ival);
                    else if (r->type == SYM_STR) caller_table = sym_set_str_in_table(caller_table, pp->name, r->sval ? r->sval : "");
                }
            }
        }
    }
    /* copy back by-ref parameters from callee table into caller table to ensure updates are visible */
    if (fn->params) {
        const char *p = fn->params;
        char *cpy = my_strdup(p);
        char *tok = strtok(cpy, ",");
        int idx = 0;
        while (tok && idx < nargs) {
            char *t = trim(tok);
            char *arr = strstr(t, "->");
            char namebuf[128];
            if (arr) { int ln = arr - t; if (ln >= (int)sizeof(namebuf)) ln = sizeof(namebuf)-1; memcpy(namebuf, t, ln); namebuf[ln] = '\0'; }
            else { strncpy(namebuf, t, sizeof(namebuf)-1); namebuf[sizeof(namebuf)-1] = '\0'; }
            char *param_name = trim(namebuf);
            if (by_ref && by_ref[idx] && arg_names && arg_names[idx]) {
                Sym *callee_sym = sym_find_in_table(sym_table, param_name);
                Sym *caller_sym = sym_find_in_table(caller_table, arg_names[idx]);
                if (callee_sym && caller_sym && callee_sym->type == SYM_INT) {
                    caller_sym->ival = callee_sym->ival;
                }
                /* copy callee-visible fields into caller_table under the callee param name so caller can reference param.field afterwards */
                size_t plen = strlen(param_name);
                for (Sym *pp = sym_table; pp; pp = pp->next) {
                    if (strncmp(pp->name, param_name, plen) == 0 && pp->name[plen] == '.') {
                        const char *field = pp->name + plen + 1;
                        char callee_field_name[256]; snprintf(callee_field_name, sizeof(callee_field_name), "%s.%s", param_name, field);
                        Sym *r = sym_resolve(pp);
                        if (r) {
                            if (r->type == SYM_INT) {
                                caller_table = sym_set_int_in_table(caller_table, callee_field_name, r->ival);
                            } else if (r->type == SYM_STR) {
                                caller_table = sym_set_str_in_table(caller_table, callee_field_name, r->sval ? r->sval : "");
                            }
                        }
                    }
                }
            }
            idx++; tok = strtok(NULL, ",");
        }
        free(cpy);
    }
    // append local messages to caller's message buffers
    for (int i = 0; i < local_n; ++i) {
        if (*n_msgs_p >= *max_msgs_p) { *max_msgs_p *= 2; *msgs_p = realloc(*msgs_p, sizeof(char*)*(*max_msgs_p)); *msg_lens_p = realloc(*msg_lens_p, sizeof(unsigned int)*(*max_msgs_p)); }
        (*msgs_p)[*n_msgs_p] = local_msgs[i]; (*msg_lens_p)[*n_msgs_p] = local_lens[i]; (*n_msgs_p)++;
    }
    free(local_lens);
    free(local_msgs);
    // clear callee sym_table and restore caller
    sym_clear();
    sym_table = caller_table;
    /* Ensure caller_table contains aliases for callee parameter fields like 'v.field' -> 'car.field' */
    if (fn->params) {
        const char *p2 = fn->params;
        char *cpy2 = my_strdup(p2);
        char *tok2 = strtok(cpy2, ",");
        int idx2 = 0;
        while (tok2 && idx2 < nargs) {
            char *t2 = trim(tok2);
            char *arr2 = strstr(t2, "->");
            char pname[128];
            if (arr2) { int ln = arr2 - t2; if (ln >= (int)sizeof(pname)) ln = sizeof(pname)-1; memcpy(pname, t2, ln); pname[ln] = '\0'; }
            else { strncpy(pname, t2, sizeof(pname)-1); pname[sizeof(pname)-1] = '\0'; }
            char *param_name = trim(pname);
            if (arg_names && arg_names[idx2]) {
                size_t base_len = strlen(arg_names[idx2]);
                for (Sym *pp = caller_table; pp; pp = pp->next) {
                    if (strncmp(pp->name, arg_names[idx2], base_len) == 0 && pp->name[base_len] == '.') {
                        const char *field = pp->name + base_len + 1;
                        char alias_name[256]; snprintf(alias_name, sizeof(alias_name), "%s.%s", param_name, field);
                        Sym *target = sym_find_in_table(caller_table, pp->name);
                        if (target) sym_set_alias(alias_name, target);
                    }
                }
            }
            idx2++; tok2 = strtok(NULL, ",");
        }
        free(cpy2);
    }
    /* DEBUG: dump caller_table symbols after returning from callee */
    printf("DEBUG: caller_table symbols after call:\n");
    for (Sym *pp = sym_table; pp; pp = pp->next) {
        if (pp->type == SYM_INT) printf("  %s -> INT %lld (addr=%p)\n", pp->name, pp->ival, (void*)&pp->ival);
        else if (pp->type == SYM_STR) printf("  %s -> STR '%s' (sval=%p)\n", pp->name, pp->sval?pp->sval:"(null)", (void*)pp->sval);
        else if (pp->type == SYM_ALIAS) printf("  %s -> ALIAS to %s (alias_target=%p)\n", pp->name, pp->alias_target?pp->alias_target->name:"(null)", (void*)pp->alias_target);
    }
    return retcode;
}

/* Backwards-compatible wrapper: no refs */
static long long call_function_compiletime(Function *fn, long long *args, int nargs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p) {
    return call_function_compiletime_with_refs(fn, args, NULL, NULL, nargs, NULL, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
}
