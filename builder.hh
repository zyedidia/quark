#pragma once

#include <assert.h>

#include "quark.hh"

struct qk_builder {
    struct qk_elf* elf;
    struct qk_code* code;
    struct qk_inst* cur;

    void locate(struct qk_inst* i);
    void add_reloc(struct qk_reloc reloc);
    struct qk_inst* insert_after(struct qk_inst* i);
    struct qk_inst* insert_before(struct qk_inst* i);
    struct qk_inst* insert_rtcall_before(const char* fn);
    struct qk_inst* insert_call_before(const char* fn);
};

struct qk_builder* new_builder(struct qk_elf* elf, struct qk_code* s);

struct qk_inst_dat {
    uint32_t data;
    size_t size;
};
struct qk_inst* new_inst(struct qk_inst_dat i);
