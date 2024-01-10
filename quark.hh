#pragma once

#include <vector>
#include <optional>
#include <capstone/capstone.h>

#include "elfio/elfio.hpp"

// Disassembled instruction part of the instruction list.
struct qk_inst {
    // assumes instructions are 4 bytes
    uint32_t data;
    size_t size;

    cs_insn insn;

    int64_t target_addr; // temporary
    struct qk_inst* target;

    bool original;
    bool has_reloc;

    size_t offset;
    size_t orig_offset;

    struct qk_inst* next;
    struct qk_inst* prev;
};

// Editable code section.
struct qk_code {
    ELFIO::section* section;
    size_t index;
    struct qk_rela* rela;

    struct qk_inst* inst_front;
    struct qk_inst* inst_back;
    size_t inst_size;
    size_t rebound_size;

    bool rebound;

    void push_back(struct qk_inst* inst);
    void insert_after(struct qk_inst* n, struct qk_inst* new_inst);
    void insert_before(struct qk_inst* n, struct qk_inst* new_inst);
    void fill_offsets(char* data);
    void check_rebound();
    void encode();
};

struct qk_reloc_code {
    struct qk_inst* inst;
};

struct qk_reloc_value {
    struct qk_inst* inst; // may be null if not a code offset
    struct qk_inst* sym_start;
    struct qk_inst* value;
};

struct qk_reloc_other {

};

struct qk_reloc_new {
    struct qk_inst* inst;
    unsigned short type;

    // has symbol if str is non-null (symbol name)
    const char* str;
    struct qk_inst* value;
    ELFIO::Elf_Half shndx;
    unsigned char info;
};

enum {
    QK_RELOC_OTHER = 0,
    QK_RELOC_CODE  = 1,
    QK_RELOC_VALUE = 2,
    QK_RELOC_NEW   = 3,
};

// Editable relocation.
struct qk_reloc {
    unsigned kind;
    union {
        struct qk_reloc_code code;
        struct qk_reloc_value value;
        struct qk_reloc_other other;
        struct qk_reloc_new new_;
    } r;
};

// Section full of relocation entries.
struct qk_rela {
    ELFIO::section* section;
    std::vector<struct qk_reloc> relocs;

    void encode(ELFIO::elfio& reader, ELFIO::section* strsec, ELFIO::section* symtab);
};

// Editable symbol.
struct qk_sym {
    struct qk_inst* start;
    struct qk_inst* end;
    size_t index;
    struct qk_code* code;
};

// Editable symbol table.
struct qk_symtab {
    ELFIO::section* section;
    std::vector<struct qk_sym> syms;

    void encode(struct qk_elf* elf);
    std::optional<struct qk_sym> get_code_symbol(size_t index);
};

struct qk_elf {
    ELFIO::elfio& reader;
    std::vector<struct qk_code*> codes;
    std::vector<struct qk_rela*> relas;
    ELFIO::section* strtab;
    struct qk_symtab symtab;

    csh cs_handle;

    void load_relocs();
    void load_code();
    void load_symbols();
    void encode(const char* outname);
};

struct qk_elf qk_readelf(ELFIO::elfio& reader, csh handle);
