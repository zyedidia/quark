#include "builder.hh"
#include "arm64.hh"

#include <elf.h>
#include <assert.h>

using namespace ELFIO;

struct qk_inst* new_inst(struct qk_inst_dat i) {
    struct qk_inst* alloc = new qk_inst();
    assert(alloc);
    alloc->data = i.data;
    alloc->size = i.size;
    return alloc;
}

struct qk_builder* new_builder(struct qk_elf* elf, struct qk_code* s) {
    struct qk_builder* b = new qk_builder();
    assert(b);
    *b = (struct qk_builder){
        .elf = elf,
        .code = s,
        .cur = s->inst_front,
    };
    return b;
}

void qk_builder::add_reloc(struct qk_reloc reloc) {
    if (!code->rela) {
        section* sec = elf->reader.sections.add(code->section->get_name() + ".rela");
        sec->set_type(SHT_RELA);
        sec->set_info(code->section->get_index());
        sec->set_flags(SHF_INFO_LINK);
        sec->set_entry_size(elf->reader.get_default_entry_size(SHT_RELA));
        sec->set_link(elf->symtab.section->get_index());
        code->rela = new qk_rela();
        assert(code->rela);
        code->rela->section = sec;
        elf->relas.push_back(code->rela);
    }
    code->rela->relocs.push_back(reloc);
}

void qk_builder::locate(struct qk_inst* i) {
    cur = i;
}

struct qk_inst* qk_builder::insert_after(struct qk_inst* i) {
    code->insert_after(cur, i);
    cur = i;
    return cur;
}

struct qk_inst* qk_builder::insert_before(struct qk_inst* i) {
    code->insert_before(cur, i);
    cur = i;
    return cur;
}

struct qk_inst* qk_builder::insert_call_before(const char* fn) {
    struct qk_inst* inst = insert_before(new_inst({arm64_bl(0), 4}));

    add_reloc((struct qk_reloc){
        .kind = QK_RELOC_NEW,
        .r = {
            .new_ = (struct qk_reloc_new){
                .inst = inst,
                .type = R_AARCH64_CALL26,
                .str = fn,
                .value = NULL,
                .shndx = SHN_UNDEF,
                .info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE),
            },
        },
    });

    return cur;
}

struct qk_inst* qk_builder::insert_rtcall_before(const char* fn) {
    struct qk_inst_dat ops[] = {
        {0xa9bf23fe, 4}, // stp x30, x8, [sp, -16]!
        {0x90000008, 4}, // adrp x8, fn
        {0xf9400108, 4}, // ldr x8, [x8]
        {0x94000000, 4}, // bl __quark_rtcall
        {0xa8c123fe, 4}, // ldp x30, x8, [sp], 16
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

    std::vector<struct qk_inst*> insts;

    struct qk_inst* inst = new_inst(ops[0]);
    insert_before(inst);
    insts.push_back(inst);
    for (size_t i = 1; i < sizeof(ops) / sizeof(struct qk_inst_dat); i++) {
        inst = new_inst(ops[i]);
        insert_after(inst);
        insts.push_back(inst);
    }

    for (size_t i = 0; i < sizeof(relocs) / sizeof(struct reloc_info); i++) {
        struct reloc_info rinf = relocs[i];
        add_reloc((struct qk_reloc){
            .kind = QK_RELOC_NEW,
            .r = {
                .new_ = (struct qk_reloc_new){
                    .inst = insts[rinf.idx],
                    .type = rinf.type,
                    .str = rinf.str,
                    .value = rinf.value_idx != -1 ? insts[rinf.value_idx] : NULL,
                    .shndx = rinf.shndx,
                    .info = rinf.info,
                },
            },
        });
    }

    return cur;
}
