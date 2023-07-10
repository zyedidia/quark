#include "builder.hh"
#include "reloc.hh"

#include <elf.h>
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

    struct reloc_info {
        unsigned char type;
        size_t idx;

        const char* str;
        ssize_t value_idx;
        unsigned char info;
        ELFIO::Elf_Half shndx;
    };

    // insert R_RISCV_GOT_HI20 pointing at 'auipc a7' with symbol 'fn'
    // insert R_RISCV_PCREL_LO12_I pointing at 'ld a7' with symbol '.L0'
    // insert R_RISCV_RELAX pointing at 'ld a7'
    // insert R_RISCV_CALL pointing at 'auipc ra' with symbol __quark_wrapper
    // insert R_RISCV_RELAX pointing at 'auipc ra'
    // insert symbol '.L0' pointing at 'auipc a7' (LOCAL, current section)
    // insert symbol 'fn' (GLOBAL, UND)
    // insert symbol '__quark_wrapper' (GLOBAL, UND)

    struct reloc_info relocs[] = {
        {R_RISCV_GOT_HI20, 3, fn, -1, ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE), SHN_UNDEF},
        {R_RISCV_PCREL_LO12_I, 4, ".L0", 3, ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE), (ELFIO::Elf_Half) this->exsec->index},
        {R_RISCV_RELAX, 4, NULL, -1, 0, 0},
        {R_RISCV_CALL, 5, "__quark_wrapper", -1, ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE), SHN_UNDEF},
        {R_RISCV_RELAX, 5, NULL, -1, 0, 0},
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
