#pragma once

#include <assert.h>

#include "quark.hh"

struct builder {
    struct elf* elf;
    struct exsec* exsec;
    struct inst* cur;

    void locate(struct inst* i);
    void add_reloc(struct reloc reloc);
    struct inst* insert_after(struct inst* i);
    struct inst* insert_before(struct inst* i);
    struct inst* insert_rtcall_before(const char* fn);
    struct inst* insert_call_before(const char* fn);
};

struct builder* new_builder(struct elf* elf, struct exsec* s);

struct inst_dat {
    uint32_t data;
    size_t size;
};
struct inst* new_inst(struct inst_dat i);
