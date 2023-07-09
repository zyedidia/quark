#pragma once

#include <stdint.h>
#include <vector>

#include "elfio/elfio.hpp"

struct inst {
    uint32_t data;
    size_t size;

    bool has_reloc;

    size_t offset;

    struct inst* next;
    struct inst* prev;
};

struct exsec {
    ELFIO::section* section;
    ELFIO::section* rela;
    size_t index;

    struct inst* inst_front;
    struct inst* inst_back;
    size_t inst_size;

    void push_back(struct inst* inst);
    void insert_after(struct inst* n, struct inst* new_inst);
    void insert_before(struct inst* n, struct inst* new_inst);
    void encode();
};

struct reloc {
    struct inst* inst;
};

struct rela {
    ELFIO::section* rela;
    std::vector<struct reloc> relocs;
    void encode(ELFIO::elfio& reader);
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
    void encode(ELFIO::elfio& reader);
};

struct elf {
    ELFIO::elfio& reader;
    std::vector<struct exsec*> exsecs;
    std::vector<struct rela> relas;
    struct symtab symtab;

    void encode(const char* outname);
};

struct elf quark_readelf(ELFIO::elfio& reader);