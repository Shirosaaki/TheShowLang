/**==============================================
 *                tsc.c
 *  TheShowLang minimal compiler to ELF64
 *  Author: shirosaaki
 *  Date: 2025-10-23
 *=============================================**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fallback strdup for strict compilation environments */
static char *my_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

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

    unsigned long filesz = fi + total_msg_bytes;

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

    free(disp_positions);
    free(next_instr_offsets);
    free(msg_offsets_within_messages);

    fclose(f);
    return 0;
}

/* --- lightweight parser (line-oriented) ---
   This builds a simple AST with top-level constructs (functions, destruct, enums)
   and function bodies as a list of statement strings. It's sufficient as a
   first step before implementing a full expression parser and native codegen.
*/

typedef enum { ST_PERIC, ST_ERIC_DECL, ST_ASSIGN, ST_RETURN, ST_CONTINUE, ST_BREAK, ST_OTHER, ST_FOR, ST_WHILE, ST_IF } StmtKind;

typedef struct Stmt {
    StmtKind kind;
    char *raw; // original line trimmed
    struct Stmt *next;
    struct Stmt *body; // nested block
    struct Stmt *else_body; // for if/else
    char *cond; // condition or extra data (e.g., range args)
    char *it_name; // iterator name for for-loops
    int indent; // number of leading spaces (for block detection)
} Stmt;

typedef struct Function {
    char *name;
    char *ret_type;
    char *params; // raw param string for now
    Stmt *body;
    struct Function *next;
} Function;

typedef struct Program {
    Function *functions;
} Program;

/* forward declarations for compile-time function call support */
static Program *g_program;
static Function *find_function(const char *name);
static long long call_function_compiletime(Function *fn, long long *args, int nargs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p);
static long long call_function_compiletime_with_refs(Function *fn, long long *arg_vals, char **arg_names, int *by_ref, int nargs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p);
static char *trim(char *s);

/* forward-declare eval_int_expr so parse_factor can call it without implicit decl */
static long long eval_int_expr(const char *expr);

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
    if (p->type == SYM_STR) { free(p->sval); p->sval = NULL; }
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
    p->type = SYM_STR; p->sval = my_strdup(s);
}
static Sym *sym_get(const char *name) {
    Sym *p = sym_table; while (p) { if (strcmp(p->name, name) == 0) return p; p = p->next; } return NULL;
}
static void sym_clear(void) {
    Sym *p = sym_table; while (p) { Sym *n = p->next; free(p->name); if (p->type==SYM_STR && p->sval) free(p->sval); /* do not free alias_target here */ free(p); p = n; } sym_table = NULL;
}

/* Create an alias symbol in current sym_table that points to target Sym */
static void sym_set_alias(const char *name, Sym *target) {
    if (!name) return;
    Sym *p = sym_table; while (p) { if (strcmp(p->name, name) == 0) break; p = p->next; }
    if (!p) { p = malloc(sizeof(Sym)); p->name = my_strdup(name); p->next = sym_table; sym_table = p; }
    p->type = SYM_ALIAS; p->alias_target = target; p->sval = NULL; p->ival = 0;
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

/* Simple recursive-descent expression evaluator for integers */
typedef struct { const char *s; int pos; } ExprState;
static void skip_ws(ExprState *e) { while (e->s[e->pos] == ' ' || e->s[e->pos] == '\t') e->pos++; }
static long long parse_expr(ExprState *e);
static long long parse_rel(ExprState *e);
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
                if (res && res->type == SYM_INT) {
                    printf("DEBUG: parse_factor lookup '%s' -> %lld\n", key, res->ival);
                    return res->ival;
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
        printf("DEBUG: parse_factor lookup '%s' -> (not found)\n", name);
        return 0; // default 0 if unknown
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
        else if (c == '/') { e->pos++; long long r = parse_factor(e); if (r!=0) v = v / r; else v = 0; }
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

static long long eval_int_expr(const char *expr) {
    ExprState e = { expr, 0 };
    return parse_rel(&e);
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
                if (rhs[0] == '"') {
                    const char *q = strchr(rhs+1, '"'); if (!q) q = rhs+1; size_t llen = q - (rhs+1); char *val = malloc(llen+1); memcpy(val, rhs+1, llen); val[llen]='\0'; sym_set_str(name, val); free(val);
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
                                                } else {
                                                    /* if the token is a plain identifier, record its name so callee can alias arrays */
                                                    int is_id = 1; for (int _i=0; t[_i]; ++_i) { char _c = t[_i]; if (!((_c>='a'&&_c<='z')||(_c>='A'&&_c<='Z')||_c=='_'||(_c>='0'&&_c<='9')||_c=='.')) { is_id = 0; break; } }
                                                    if (is_id) {
                                                        argnames[argcnt] = my_strdup(t);
                                                    } else {
                                                        argnames[argcnt] = NULL;
                                                    }
                                                    byref[argcnt] = 0;
                                                    argvals[argcnt] = eval_int_expr(t);
                                                }
                                                argcnt++; tok = strtok(NULL, ",");
                                            }
                                            free(cpy);
                            Function *fn = find_function(ftrim);
                            if (fn) {
                                long long cres = call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                                sym_set_int(name, cres);
                            } else {
                                long long v = eval_int_expr(rhs);
                                sym_set_int(name, v);
                            }
                            for (int ii=0; ii<argcnt; ++ii) if (argnames[ii]) free(argnames[ii]);
                        } else {
                            long long v = eval_int_expr(rhs);
                            sym_set_int(name, v);
                        }
                    } else {
                        long long v = eval_int_expr(rhs);
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
                            sym_set_int(name, 0);
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
                char name[256]; if (namelen >= (int)sizeof(name)) namelen = sizeof(name)-1; memcpy(name, lhs_start, namelen); name[namelen] = '\0';
                const char *rhs = eq+1; while (*rhs==' '||*rhs=='\t') rhs++;
                if (rhs[0] == '"') {
                    const char *q = strchr(rhs+1, '"'); if (!q) q = rhs+1; size_t llen = q - (rhs+1); char *val = malloc(llen+1); memcpy(val, rhs+1, llen); val[llen]='\0'; sym_set_str(name, val); free(val);
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
                                    int is_id = 1; for (int _i=0; t[_i]; ++_i) { char _c = t[_i]; if (!((_c>='a'&&_c<='z')||(_c>='A'&&_c<='Z')||_c=='_'||(_c>='0'&&_c<='9')||_c=='.')) { is_id = 0; break; } }
                                    if (is_id) argnames[argcnt] = my_strdup(t); else argnames[argcnt] = NULL;
                                    byref[argcnt] = 0; argvals[argcnt] = eval_int_expr(t);
                                }
                                argcnt++; tok = strtok(NULL, ",");
                            }
                            free(cpy);
                            Function *fn = find_function(ftrim);
                            if (fn) {
                                long long cres = call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
                                sym_set_int(name, cres);
                            } else {
                                long long v = eval_int_expr(rhs);
                                sym_set_int(name, v);
                            }
                            for (int ii=0; ii<argcnt; ++ii) if (argnames[ii]) free(argnames[ii]);
                        } else {
                            long long v = eval_int_expr(rhs);
                            sym_set_int(name, v);
                        }
                    } else {
                        long long v = eval_int_expr(rhs);
                        sym_set_int(name, v);
                    }
                }
                /* handle deref assignment: if LHS starts with '*' then update alias target */
                if (name[0] == '*') {
                    char *n = name + 1; char *ntrim = trim(n);
                    Sym *s2 = sym_get(ntrim);
                    if (s2) {
                        Sym *t = sym_resolve(s2);
                        if (t && t->type == SYM_INT) {
                            long long v = 0; if (rhs && *rhs) v = eval_int_expr(rhs); t->ival = v;
                        }
                    }
                }
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
            char out[1024]; out[0] = '\0';
            const char *cur = tmpl;
            while (*cur) {
                const char *obr = strchr(cur, '{');
                if (!obr) { strncat(out, cur, sizeof(out)-strlen(out)-1); break; }
                strncat(out, cur, obr - cur);
                const char *cbr = strchr(obr, '}');
                if (!cbr) { strncat(out, obr, sizeof(out)-strlen(out)-1); break; }
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
                            strncat(out, numbuf, sizeof(out)-strlen(out)-1);
                            cur = cbr + 1;
                            continue;
                        }
                    }
                }

                char *evaled = eval_placeholder(inner);
                strncat(out, evaled, sizeof(out)-strlen(out)-1);
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
        } else if (s->kind == ST_RETURN) {
            const char *p = s->raw + strlen("deschodt"); while (*p==' '||*p=='\t') p++;
            if (*p) {
                /* evaluate the return expression (may be an expression or identifiers) */
                long long rv = eval_int_expr(p);
                *retcode_p = (int)rv;
            }
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
                    else { argnames[argcnt]=NULL; byref[argcnt]=0; argvals[argcnt]=eval_int_expr(t); }
                    argcnt++; tok = strtok(NULL, ",");
                }
                free(cpy);
                Function *fn = find_function(ftrim);
                if (fn) {
                    call_function_compiletime_with_refs(fn, argvals, argnames, byref, argcnt, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
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

static void append_stmt(Stmt **head, Stmt *s) {
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
                                else if (strchr(t2, '=') != NULL) append_stmt(&ifs->body, make_stmt_indent(ST_ASSIGN, t2, ind2));
                                else append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
                                inner2 = strtok(NULL, "\n");
                            }
                            append_stmt(&st->body, ifs);
                            inner = inner2; if (!inner) break; continue;
                        }
                        else if (strncmp(tinner, "deschodt", 8) == 0) append_stmt(&st->body, make_stmt_indent(ST_RETURN, tinner, iindent));
                        else if (strncmp(tinner, "deschontinue", 12) == 0) append_stmt(&st->body, make_stmt_indent(ST_CONTINUE, tinner, iindent));
                        else if (strncmp(tinner, "deschreak", 9) == 0) append_stmt(&st->body, make_stmt_indent(ST_BREAK, tinner, iindent));
                        else if (strchr(tinner, '=') != NULL) append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
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
                        if (strncmp(tinner, "erif ", 5) == 0) {
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
                                else if (strchr(t2, '=') != NULL) append_stmt(&ifs->body, make_stmt_indent(ST_ASSIGN, t2, ind2));
                                else append_stmt(&ifs->body, make_stmt_indent(ST_OTHER, t2, ind2));
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
                        else if (strchr(tinner, '=') != NULL) append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
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
                        else if (strchr(tinner, '=') != NULL) append_stmt(&st->body, make_stmt_indent(ST_ASSIGN, tinner, iindent));
                        else append_stmt(&st->body, make_stmt_indent(ST_OTHER, tinner, iindent));
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
                                else if (strchr(ttr, '=') != NULL) append_stmt(&last->else_body, make_stmt(ST_ASSIGN, ttr));
                                else append_stmt(&last->else_body, make_stmt(ST_OTHER, ttr));
                            elsepeek = strtok(NULL, "\n");
                        }
                        // resume parse from elsepeek
                        peek = elsepeek; line = peek; continue;
                    }
                }
                else if (strchr(tpeek, '=') != NULL) append_stmt(&curf->body, make_stmt(ST_ASSIGN, tpeek));
                else append_stmt(&curf->body, make_stmt(ST_OTHER, tpeek));
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
                if (rhs[0] == '"') {
                    const char *q = strchr(rhs+1, '"'); if (!q) q = rhs+1; int vlen = q - (rhs+1); char val[256]; if (vlen >= (int)sizeof(val)) vlen = sizeof(val)-1; memcpy(val, rhs+1, vlen); val[vlen] = '\0';
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
        fprintf(stderr, "Usage: %s <source.tslang> <out_binary>\n", argv[0]);
        return 1;
    }
    const char *src_path = argv[1];
    const char *out_path = argv[2];

    FILE *s = fopen(src_path, "rb");
    if (!s) { perror("fopen src"); return 1; }
    fseek(s, 0, SEEK_END);
    long sz = ftell(s);
    fseek(s, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(s); fprintf(stderr, "alloc fail\n"); return 1; }
    fread(buf, 1, sz, s);
    buf[sz] = '\0';
    fclose(s);

    // Remove 'desnote' comment lines into a filtered buffer
    char *filtered = malloc(sz + 1);
    filtered[0] = '\0';
    char *copy2 = my_strdup(buf);
    char *ln = strtok(copy2, "\n");
    while (ln) {
        char *t = trim(ln);
        if (strncmp(t, "desnote", 7) != 0) {
            strcat(filtered, ln);
            strcat(filtered, "\n");
        }
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
static long long call_function_compiletime_with_refs(Function *fn, long long *arg_vals, char **arg_names, int *by_ref, int nargs, char ***msgs_p, unsigned int **msg_lens_p, int *n_msgs_p, int *max_msgs_p) {
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
                            sym_set_alias(callee_key, t2);
                            /* also add alias into caller_table so caller can reference param.field names */
                            Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_alias(callee_key, t2); sym_table = saved_sym;
                            printf("DEBUG: alias created %s -> %s\n", callee_key, caller_key);
                        } else {
                            sym_set_alias(ntrim, t2);
                            Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_alias(ntrim, t2); sym_table = saved_sym;
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
                        Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_alias(callee_key, t2); sym_table = saved_sym;
                        printf("DEBUG: alias created %s -> %s\n", callee_key, caller_key);
                        found_any = 1;
                    }
                    if (found_any) { idx++; tok = strtok(NULL, ","); continue; }
                    /* fallback to aliasing base[0] if present */
                    char elem0[256]; snprintf(elem0, sizeof(elem0), "%s[0]", arg_names[idx]); Sym *t0 = sym_find_in_table(caller_table, elem0);
                    if (t0) { sym_set_alias(ntrim, t0); Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_alias(ntrim, t0); sym_table = saved_sym; printf("DEBUG: alias created %s -> %s\n", ntrim, elem0); idx++; tok = strtok(NULL, ","); continue; }
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
                            Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_alias(callee_field, pp); sym_table = saved_sym;
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

            /* default: bind by value */
            sym_set_int(ntrim, arg_vals ? arg_vals[idx] : 0);
            idx++; tok = strtok(NULL, ",");
        }
        free(cpy);
    }
    int local_max = 4; char **local_msgs = malloc(sizeof(char*) * local_max); unsigned int *local_lens = malloc(sizeof(unsigned int) * local_max); int local_n = 0; int retcode = 0;
    // set globals so nested calls inside callee append into local_msgs
    char ***old_msgs_p = g_msgs_p; unsigned int **old_msg_lens_p = g_msg_lens_p; int *old_n_msgs_p = g_n_msgs_p; int *old_max_msgs_p = g_max_msgs_p;
    g_msgs_p = &local_msgs; g_msg_lens_p = &local_lens; g_n_msgs_p = &local_n; g_max_msgs_p = &local_max;
    exec_stmt_list(fn->body, &local_msgs, &local_lens, &local_n, &local_max, &retcode);
    // restore globals
    g_msgs_p = old_msgs_p; g_msg_lens_p = old_msg_lens_p; g_n_msgs_p = old_n_msgs_p; g_max_msgs_p = old_max_msgs_p;
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
                                Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_int(callee_field_name, r->ival); sym_table = saved_sym;
                            } else if (r->type == SYM_STR) {
                                Sym *saved_sym = sym_table; sym_table = caller_table; sym_set_str(callee_field_name, r->sval ? r->sval : ""); sym_table = saved_sym;
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
    return call_function_compiletime_with_refs(fn, args, NULL, NULL, nargs, msgs_p, msg_lens_p, n_msgs_p, max_msgs_p);
}
