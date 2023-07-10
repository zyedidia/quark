#include "builder.hh"

#include <assert.h>

struct builder* new_builder(struct elf* elf, struct exsec* s) {
    struct builder* b = (struct builder*) malloc(sizeof(struct builder));
    assert(b);
    *b = (struct builder){
        .elf = elf,
        .exsec = s,
        .cur = s->inst_front,
    };
    return b;
}

void builder::locate(struct inst* i) {
    this->cur = i;
}

struct inst* builder::insert_after(struct inst* i) {
    this->exsec->insert_after(this->cur, i);
    this->cur = i;
    return this->cur;
}

struct inst* builder::insert_before(struct inst* i) {
    this->exsec->insert_before(this->cur, i);
    this->cur = i;
    return this->cur;
}

struct inst_dat {
    uint32_t data;
    size_t size;
};

static struct inst* new_inst(struct inst_dat i) {
    struct inst* alloc = (struct inst*) calloc(1, sizeof(struct inst));
    assert(alloc);
    alloc->data = i.data;
    alloc->size = i.size;
    return alloc;
}

struct inst* builder::insert_rtcall_before(const char* fn) {
    struct inst_dat ops[] = {
        {0x1141, 2},     // addi sp, sp, -16
        {0xe006, 2},     // sd ra, 0(sp)
        {0xe446, 2},     // sd a7, 8(sp)
        {0x00000897, 4}, // auipc a7, 0x0
        {0x0008b883, 4}, // ld a7, 0(a7)
        {0x00000097, 4}, // auipc ra, 0x0
        {0x000080e7, 4}, // jalr ra
        {0x6082, 2},     // ld ra, 0(sp)
        {0x68a2, 2},     // ld a7, 8(sp)
        {0x0141, 2},     // addi sp, sp, 16
    };

    // TODO:
    // insert R_RISCV_GOT_HI20 pointing at 'auipc a7' with symbol 'fn'
    // insert R_RISCV_PCREL_LO12_I pointing at 'ld a7' with symbol '.L0'
    // insert R_RISCV_RELAX pointing at 'ld a7'
    // insert R_RISCV_CALL pointing at 'auipc ra' with symbol __quark_wrapper
    // insert R_RISCV_RELAX pointing at 'auipc ra'
    // insert symbol '.L0' pointing at 'auipc a7' (LOCAL, current section)
    // insert symbol 'fn' (GLOBAL, UND)
    // insert symbol '__quark_wrapper' (GLOBAL, UND)

    this->insert_before(new_inst(ops[0]));
    for (size_t i = 1; i < sizeof(ops)/sizeof(struct inst_dat); i++) {
        this->insert_after(new_inst(ops[i]));
    }
    return this->cur;
}
