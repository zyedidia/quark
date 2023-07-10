#pragma once

#include "quark.hh"

struct builder {
    struct elf* elf;
    struct exsec* exsec;
    struct inst* cur;

    void locate(struct inst* i);
    struct inst* insert_after(struct inst* i);
    struct inst* insert_before(struct inst* i);
    struct inst* insert_rtcall_before(const char* fn);
};

struct builder* new_builder(struct elf* elf, struct exsec* s);
