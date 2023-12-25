#pragma once

#include <stdint.h>
#include <vector>
#include <capstone/capstone.h>

#include "elfio/elfio.hpp"

struct inst {
    uint32_t data;
    cs_insn insn;
    size_t size;

    int64_t _target_addr;
    struct inst* target;

    bool has_reloc;
    bool original;

    size_t offset;
    size_t rebound_offset;

    struct inst* next;
    struct inst* prev;
};

struct exsec {
    ELFIO::section* section;
    struct rela* rela;
    size_t index;

    struct inst* inst_front;
    struct inst* inst_back;
    size_t inst_size;
    size_t orig_size;

    bool needs_rebound;

    void push_back(struct inst* inst);
    void insert_after(struct inst* n, struct inst* new_inst);
    void insert_before(struct inst* n, struct inst* new_inst);
    void encode();
};

struct reloc {
    struct inst* inst;

    bool new_reloc;
    unsigned short type;

    // has symbol if str is non-null (symbol name)
    const char* str;
    struct inst* value;
    ELFIO::Elf_Half shndx;
    unsigned char info;
};

struct rela {
    ELFIO::section* rela;
    std::vector<struct reloc> relocs;
    void encode(ELFIO::elfio& reader, ELFIO::section* strsec, ELFIO::section* symtab);
};

struct sym {
    struct inst* start;
    struct inst* end;
    size_t index;
    struct exsec* exsec;
};

struct symtab {
    ELFIO::section* symtab;
    std::vector<struct sym> syms;
    void encode(struct elf* elf);
};

struct elf {
    ELFIO::elfio& reader;
    ELFIO::section* strsec;
    std::vector<struct exsec*> exsecs;
    std::vector<struct rela*> relas;
    struct symtab symtab;
    csh handle;

    void encode(const char* outname);
};

struct elf quark_readelf(ELFIO::elfio& reader, csh handle);
