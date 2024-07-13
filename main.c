#include <stdio.h>
#include <stdlib.h>

#include "constants.h"
#include "elf.h"

void read_elf64_header(FILE* restrict file,
                        void* restrict buffer) {
    fseek(file, 0, SEEK_SET);
    fread(buffer, sizeof(struct ELF64_Header), 1, file);
}

void write_elf64_header(FILE* restrict file,
                        struct ELF64_Header* restrict hdr) {
    fseek(file, 0, SEEK_SET);
    fwrite(hdr, sizeof(struct ELF64_Header), 1, file);
}

void read_elf64_program_headers(FILE* restrict file,
                                uint64_t phdr_offset,
                                uint16_t num,
                                struct ProgramHeader* restrict buffer) {
    fseek(file, phdr_offset, SEEK_SET);
    fread(buffer, sizeof(struct ProgramHeader), num, file);
}

void write_elf64_program_headers(FILE* restrict file,
                                uint64_t phdr_offset,
                                uint16_t num,
                                struct ProgramHeader* restrict buffer) {
    fseek(file, phdr_offset, SEEK_SET);
    fwrite(buffer, sizeof(struct ProgramHeader), num, file);
}

void read_elf64_section_headers(FILE* restrict file,
                                uint64_t shdr_offset,
                                uint16_t num,
                                struct SectionHeader* restrict buffer) {
    fseek(file, shdr_offset, SEEK_SET);
    fread(buffer, sizeof(struct SectionHeader), num, file);
}

void write_elf64_section_headers(FILE* restrict file,
                                uint64_t shdr_offset,
                                uint16_t num,
                                struct SectionHeader* restrict buffer) {
    fseek(file, shdr_offset, SEEK_SET);
    fwrite(buffer, sizeof(struct SectionHeader), num, file);
}

void read_elf64_symbol_table(FILE* restrict file, struct SectionHeader* restrict hdr, struct SymbolTableEntry* restrict buf) {
    uint64_t offset = hdr->sh_offset;
    uint64_t size = hdr->sh_size;
    uint64_t entsize = hdr->sh_entsize;
    size_t num = size / entsize;

    if (entsize != sizeof(struct SymbolTableEntry)) {
        fprintf(stderr, "entsize ~ symbol_table_entry_size mismatch");
        exit(1);
    }

    fseek(file, offset, SEEK_SET);
    fread(buf, SYMBOL_TABLE_ENTRY_SIZE, num, file);
}

void patch_jump(uint8_t* shellcode, uint64_t entry_point) {
    shellcode[0] = 0x48;
    shellcode[1] = 0xB8;
    *(uint64_t*)(&shellcode[2]) = entry_point;
    shellcode[10] = 0xFF;
    shellcode[11] = 0xE0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Not enough arguments!\n");
        exit(1);
    }

    FILE* file = fopen(argv[1], "r+");
    if (!file){
        fprintf(stderr, "Failed to open file!");
        exit(1);
    }
    FILE* shellcode = fopen(argv[2], "r");
    if (!shellcode) {
        fprintf(stderr, "Failed to open shellcode file!");
        goto fclose;
    }

    struct ELF64_Header hdr = {0};
    read_elf64_header(file, &hdr);

    struct ProgramHeader* phdrs = malloc(sizeof(struct ProgramHeader) * hdr.e_phnum);
    if (!phdrs) {
        fprintf(stderr, "Failed to allocate memory!");
        goto fshellcode;
    }
    read_elf64_program_headers(file, hdr.e_phoff, hdr.e_phnum, phdrs);

    fseek(file, 0, SEEK_END);
    uint64_t elfsize = ftell(file);
    rewind(file);

    fseek(shellcode, 0, SEEK_END);
    uint64_t scsize = ftell(shellcode);
    rewind(shellcode);

    uint8_t* shellcode_ptr = malloc(scsize + 12);
    if (!shellcode_ptr) {
        fprintf(stderr, "Failed to allocate memory!");
        goto fphdrs;
    }
    fread(shellcode_ptr, scsize, 1, shellcode);
    patch_jump(shellcode_ptr + scsize, hdr.e_entry);
    rewind(shellcode);
    fwrite(shellcode_ptr, scsize + 12, 1, shellcode);
    exit(0);

    fseek(file, 0, SEEK_END);
    fwrite(shellcode_ptr, scsize + 12, 1, file);

    uint64_t file_offset = elfsize - scsize;
    uint64_t memory_offset = 0xC00000000 + file_offset;

    for (uint32_t i = 0; i < hdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_NOTE) continue;

        phdrs[i].p_type = PT_LOAD;
        phdrs[i].p_flags = PF_R | PF_X;
        phdrs[i].pf_offset = file_offset;
        phdrs[i].p_vaddr = memory_offset;
        phdrs[i].p_memsz += scsize + 12;
        phdrs[i].p_filesz += scsize + 12;
        hdr.e_entry = memory_offset;
        break;
    }

    write_elf64_program_headers(file, hdr.e_phoff, hdr.e_phnum, phdrs);
    write_elf64_header(file, &hdr);

    free(shellcode_ptr);
    fphdrs:
    free(phdrs);
    fshellcode:
    fclose(shellcode);
    fclose:
    fclose(file);
}