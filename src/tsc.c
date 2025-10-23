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
int emit_elf(const char *out_path, const char *msg, int retcode) {
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

     unsigned int msg_len = (unsigned int)strlen(msg);

     /* Build machine code into a buffer with zeroed displacement, then
         patch the lea displacement after we know the final code length. */
     unsigned char final_code[512];
     size_t fi = 0;

     // mov rax,1
     final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc0; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
     // mov rdi,1
     final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc7; final_code[fi++] = 0x01; final_code[fi++] = 0x00; final_code[fi++] = 0x00; final_code[fi++] = 0x00;
     // lea rsi,[rip+disp]
     final_code[fi++] = 0x48; final_code[fi++] = 0x8d; final_code[fi++] = 0x35;
     size_t disp_index = fi; // remember where to patch 4-byte disp
     final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0; final_code[fi++] = 0;
     // mov rdx, msg_len
     final_code[fi++] = 0x48; final_code[fi++] = 0xc7; final_code[fi++] = 0xc2;
     final_code[fi++] = (unsigned char)(msg_len & 0xff);
     final_code[fi++] = (unsigned char)((msg_len>>8)&0xff);
     final_code[fi++] = (unsigned char)((msg_len>>16)&0xff);
     final_code[fi++] = (unsigned char)((msg_len>>24)&0xff);
     // syscall
     final_code[fi++] = 0x0f; final_code[fi++] = 0x05;
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

     /* Now compute displacement for lea rsi,[rip+disp]. The lea's next
         instruction is at offset (offset_of_lea + 7) from start of code. */
     unsigned long offset_of_lea = 7 + 7; // first two movs lengths
     unsigned long next_instr_offset = offset_of_lea + 7; // lea is 7 bytes
     long disp = (long)(fi) - (long)next_instr_offset;
     final_code[disp_index + 0] = (unsigned char)(disp & 0xff);
     final_code[disp_index + 1] = (unsigned char)((disp>>8)&0xff);
     final_code[disp_index + 2] = (unsigned char)((disp>>16)&0xff);
     final_code[disp_index + 3] = (unsigned char)((disp>>24)&0xff);

     /* Now we can write the ELF header and program header with the
         correct file size (code + message). */
     unsigned long filesz = fi + msg_len;

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

     // Write code and message
     fwrite(final_code, 1, fi, f);
     fwrite(msg, 1, msg_len, f);

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

    char *msg = extract_peric_string(buf);
    if (!msg) msg = my_strdup("Hello from TheShowLang!\n");
    int ret = extract_deschodt_int(buf, 0);

    int r = emit_elf(out_path, msg, ret);
    if (r != 0) {
        fprintf(stderr, "emit failed\n");
        return 1;
    }
    printf("Wrote %s (message=\"%s\", ret=%d)\n", out_path, msg, ret);
    return 0;
}
