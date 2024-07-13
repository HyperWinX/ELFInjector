#pragma once

#include <stddef.h>
#include <stdint.h>

enum e_type : uint16_t {
    ET_NONE     =   0,
    ET_REL      =   1,
    ET_EXEC     =   2,
    ET_DYN      =   3,
    ET_CORE     =   4,
    ET_LOPROC   =   0xFF00,
    ET_HIPROC   =   0xFFFF
};

enum e_machine : uint16_t {
    EM_NONE     =   0,
    EM_M32      =   1,
    EM_SPARC    =   2,
    EM_386      =   3,
    EM_68K      =   4,
    EM_88K      =   5,
    EM_860      =   7,
    EM_MIPS     =   8
};

enum e_version : uint16_t {
    EV_NONE     =   0,
    EV_CURRENT  =   1
};

enum e_ident_idx : size_t {
    EI_MAG0     =   0,
    EI_MAG1     =   1,
    EI_MAG2     =   2,
    EI_MAG3     =   3,
    EI_CLASS    =   4,
    EI_DATA     =   5,
    EI_VERSION  =   6,
    EI_PAD      =   7,
    EI_NIDENT   =   16
};

enum e_ident_ei : uint8_t {
    ELFCLASSNONE=   0,
    ELFCLASS32  =   1,
    ELFCLASS64  =   2
};

// Program headers
#define PROGRAM_HEADER_SIZE ((size_t)0x38)
#define PT_NULL             ((uint32_t)0x0)
#define PT_LOAD             ((uint32_t)0x1)
#define PT_DYNAMIC          ((uint32_t)0x2)
#define PT_INTERP           ((uint32_t)0x3)
#define PT_NOTE             ((uint32_t)0x4)
#define PT_SHLIB            ((uint32_t)0x5)
#define PT_PHDR             ((uint32_t)0x6)
#define PT_LOPROC           ((uint32_t)0x70000000)
#define PT_HIPROC           ((uint32_t)0x7FFFFFFF)

#define PF_X                ((uint32_t)0b001)
#define PF_W                ((uint32_t)0b010)
#define PF_R                ((uint32_t)0b100)

#define SECTION_HEADER_SIZE ((size_t)0x40)
#define SYMBOL_TABLE_ENTRY_SIZE ((size_t)0x18)
