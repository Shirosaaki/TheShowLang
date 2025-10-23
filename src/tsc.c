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
// The code will perform write(1, msg, len) and exit(status).
int emit_elf(const char *out_path, const char **msgs, unsigned int *msg_lens, int n_msgs, int retcode) {
    FILE *f = fopen(out_path, "wb");
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
          // next_instr offset is offset_of_lea + 7
          next_instr_offsets[i] = (int)(fi - 7 + 7);
          // mov rdx, len
          final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc2;
          unsigned int L = msg_lens[i];
          final_code[fi++] = (unsigned char)(L & 0xff);
          final_code[fi++] = (unsigned char)((L>>8)&0xff);
          final_code[fi++] = (unsigned char)((L>>16)&0xff);
          final_code[fi++] = (unsigned char)((L>>24)&0xff);
          // syscall
          final_code[fi++] = 0x0f; final_code[fi++] = 0x05;
          msg_offsets_within_messages[i] = cum_msg;
          cum_msg += msg_lens[i];
     }

     // After printing messages, do exit syscall with retcode
     // mov rax,60
     final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc0;
     final_code[fi++] = 0x3c; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
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

    // Collect all peric("...") messages
    int max_msgs = 16;
    char **msgs = malloc(sizeof(char*) * max_msgs);
    unsigned int *msg_lens = malloc(sizeof(unsigned int) * max_msgs);
    int n_msgs = 0;
    const char *p = buf;
    while ((p = strstr(p, "peric(")) != NULL) {
        const char *q = strchr(p, '"');
        if (!q) break; q++;
        const char *rpos = strchr(q, '"');
        if (!rpos) break;
        size_t len = rpos - q;
        char *m = malloc(len + 1);
        memcpy(m, q, len);
        m[len] = '\0';
        if (n_msgs >= max_msgs) {
            max_msgs *= 2;
            msgs = realloc(msgs, sizeof(char*) * max_msgs);
            msg_lens = realloc(msg_lens, sizeof(unsigned int) * max_msgs);
        }
        msgs[n_msgs] = m;
        msg_lens[n_msgs] = (unsigned int)len;
        n_msgs++;
        p = rpos + 1;
    }
    if (n_msgs == 0) {
        msgs[0] = my_strdup("Hello from TheShowLang!\n");
        msg_lens[0] = (unsigned int)strlen(msgs[0]);
        n_msgs = 1;
    }
    int ret = extract_deschodt_int(buf, 0);

    int r = emit_elf(out_path, (const char**)msgs, msg_lens, n_msgs, ret);
    if (r != 0) {
        fprintf(stderr, "emit failed\n");
        return 1;
    }
    printf("Wrote %s (message=\"%s\", ret=%d)\n", out_path, msgs[0], ret);
    for (int i = 0; i < n_msgs; ++i) free(msgs[i]);
    free(msgs);
    free(msg_lens);
    return 0;
}
