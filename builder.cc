#include "builder.hh"
#include "reloc.hh"
#include "assemble.hh"

#include <elf.h>
#include <assert.h>

struct inst* new_inst(struct inst_dat i) {
    struct inst* alloc = (struct inst*) calloc(1, sizeof(struct inst));
    assert(alloc);
    alloc->data = i.data;
    alloc->size = i.size;
    return alloc;
}

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

struct inst* builder::insert_call_before(const char* fn) {
    struct inst* inst = this->insert_before(new_inst({arm64_bl(0), 4}));

    // TODO: if exsec->rela does not exist, create a new rela section for this exsec

    assert(this->exsec->rela);

    this->exsec->rela->relocs.push_back((struct reloc){
        .inst = inst,
        .new_reloc = true,
        .type = R_AARCH64_CALL26,
        .str = fn,
        .value = NULL,
        .shndx = SHN_UNDEF,
        .info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE),
    });

    return this->cur;
}

struct inst* builder::insert_rtcall_before(const char* fn) {
    struct inst_dat ops[] = {
        {0xa8bf23fe, 4}, // stp x30, x8, [sp], -16
        {0x90000008, 4}, // adrp x8, fn
        {0xf9400108, 4}, // ldr x8, [x8]
        {0x94000000, 4}, // bl __quark_rtcall
        {0xa9c123fe, 4}, // ldp x30, x8, [sp, 16]!
    };

    struct reloc_info {
        unsigned short type;
        size_t idx;

        const char* str;
        ssize_t value_idx;
        unsigned char info;
        ELFIO::Elf_Half shndx;
    };

    struct reloc_info relocs[] = {
        {R_AARCH64_ADR_GOT_PAGE, 1, fn, -1, ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE), SHN_UNDEF},
        {R_AARCH64_LD64_GOT_LO12_NC, 2, fn, -1, ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE), SHN_UNDEF},
        {R_AARCH64_CALL26, 3, "__quark_wrapper", -1, ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE), SHN_UNDEF},
    };

    std::vector<inst*> insts;

    struct inst* inst = new_inst(ops[0]);
    this->insert_before(inst);
    insts.push_back(inst);
    for (size_t i = 1; i < sizeof(ops)/sizeof(struct inst_dat); i++) {
        inst = new_inst(ops[i]);
        this->insert_after(inst);
        insts.push_back(inst);
    }

    for (size_t i = 0; i < sizeof(relocs)/sizeof(struct reloc_info); i++) {
        struct reloc_info rinf = relocs[i];
        this->exsec->rela->relocs.push_back((struct reloc){
            .inst = insts[rinf.idx],
            .new_reloc = true,
            .type = rinf.type,
            .str = rinf.str,
            .value = rinf.value_idx != -1 ? insts[rinf.value_idx] : NULL,
            .shndx = rinf.shndx,
            .info = rinf.info,
        });
    }

    return this->cur;
}
