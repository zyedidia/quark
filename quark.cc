#include <assert.h>

#include "quark.hh"
#include "arm64.hh"

using namespace ELFIO;

static section* find_section(elfio& reader, unsigned type) {
    for (size_t i = 0; i < reader.sections.size(); i++) {
        section* sec = reader.sections[i];
        if (sec->get_type() == type) {
            return sec;
        }
    }
    return NULL;
}

struct qk_elf qk_readelf(elfio& reader, csh handle) {
    struct qk_elf elf = (struct qk_elf){
        .reader = reader,
        .cs_handle = handle,
    };
    elf.symtab.section = find_section(reader, SHT_SYMTAB);
    elf.strtab = find_section(reader, SHT_STRTAB);

    elf.load_code();
    elf.load_symbols();
    elf.load_relocs();

    return elf;
}

static struct qk_inst* find_inst(struct qk_inst* inst, size_t offset) {
    while (inst) {
        if (offset >= inst->offset && offset < inst->offset + inst->size) {
            return inst;
        }
        inst = inst->next;
    }
    return NULL;
}

void qk_elf::load_relocs() {
    for (size_t i = 0; i < reader.sections.size(); i++) {
        section* sec = reader.sections[i];
        if (sec->get_type() != SHT_RELA) {
            continue;
        }

        struct qk_code* code = NULL;
        size_t info = sec->get_info();
        if (info >= 0 && info < reader.sections.size() && (reader.sections[info]->get_flags() & SHF_EXECINSTR) != 0) {
            // this is a rela section for a code section, find the code section
            for (struct qk_code* s : codes) {
                if (s->index == info) {
                    code = s;
                    break;
                }
            }
        }

        struct qk_rela* rela = new qk_rela();
        assert(rela);
        rela->section = sec;

        if (code)
            code->rela = rela;

        relocation_section_accessor rela_accessor(reader, sec);
        for (size_t j = 0; j < rela_accessor.get_entries_num(); j++) {
            Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            rela_accessor.get_entry(j, offset, symbol, type, addend);

            struct qk_reloc reloc;

            auto sym = symtab.get_symbol(symbol);
            if (sym.has_value()) {
                // relocation is in a code section
                reloc.kind = QK_RELOC_VALUE;
                struct qk_inst* inst = sym.value().start;
                ELFIO::Elf_Sxword n = 0;
                while (inst && n < addend) {
                    n += inst->size;
                    inst = inst->next;
                }
                reloc.r.value = (struct qk_reloc_value){
                    .value = inst,
                };
                if (code) {
                    reloc.r.value.inst = find_inst(code->inst_front, offset);
                }
            } else if (code) {
                // code relocation
                reloc.kind = QK_RELOC_CODE;
                struct qk_inst* inst = find_inst(code->inst_front, offset);
                assert(inst);
                reloc.r.code = (struct qk_reloc_code){
                    .inst = inst,
                };
            } else {
                reloc.kind = QK_RELOC_OTHER;
            }

            rela->relocs.push_back(reloc);
        }

        relas.push_back(rela);
    }
}

void qk_elf::load_code() {
    for (size_t i = 0; i < reader.sections.size(); i++) {
        section* sec = reader.sections[i];
        if ((sec->get_flags() & SHF_EXECINSTR) != 0) {
            struct qk_code* code = new qk_code();
            assert(code);
            *code = (struct qk_code){
                .section = sec,
                .index = i,
            };

            Elf_Xword size = sec->get_size();
            const char* data = sec->get_data();

            std::vector<struct qk_inst*> insts;

            size_t n = 0;
            while (n < size) {
                cs_insn* insn = NULL;
                size_t addr = n;
                // assumes instructions are 4 bytes
                size_t count = cs_disasm(cs_handle, (uint8_t*) &data[n], 4, addr, 0, &insn);
                size_t length = 4;
                if (count != 1) {
                    // assumes instructions are 4 bytes
                    fprintf(stderr, "failed to disassemble %x at %lx\n", *((uint32_t*) &data[n]), addr);
                } else {
                    length = insn->size;
                }

                struct qk_inst* inst = new qk_inst();
                assert(inst);

                inst->original = true;

                memcpy(&inst->data, &data[n], length);
                inst->size = length;
                inst->offset = n;

                inst->target_addr = -1;
                if (insn) {
                    inst->insn = *insn;
                    inst->target_addr = arm64_branch_target(inst->insn);

                    // TODO: detect if rebound table is necessary
                }

                code->push_back(inst);
                n += length;
                insts.push_back(inst);
            }

            // assumes instructions are 4 bytes
            const size_t INST_SIZE = 4;
            for (auto& inst : insts) {
                if (inst->target_addr != -1) {
                    inst->target = insts[inst->target_addr / INST_SIZE];
                }
            }

            if (code->rebound) {
                code->rebound_size = code->inst_size;
            }

            codes.push_back(code);
        }
    }
}

void qk_elf::load_symbols() {
    if (!symtab.section)
        return;

    symbol_section_accessor syma(reader, symtab.section);
    for (size_t i = 0; i < syma.get_symbols_num(); i++) {
        std::string name;
        Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind, type, other;
        ELFIO::Elf_Half section_index;
        syma.get_symbol(i, name, value, size, bind, type, section_index, other);
        if (section_index != SHN_COMMON && section_index < reader.sections.size() &&
                (reader.sections[section_index]->get_flags() & SHF_EXECINSTR) != 0) {
            // Symbol points inside a code section.
            struct qk_code* code = NULL;
            struct qk_inst* inst = NULL;
            for (auto& s : this->codes) {
                if (s->index == section_index) {
                    code = s;
                    inst = s->inst_front;
                }
            }
            if (!inst) {
                // code section has no code?
                continue;
            }
            struct qk_inst* start = NULL;
            struct qk_inst* end = NULL;
            size_t endidx = value + size;
            while (inst) {
                if (value >= inst->offset && value < inst->offset + inst->size) {
                    start = inst;
                    assert(value == inst->offset);
                }
                if (endidx >= inst->offset && endidx < inst->offset + inst->size) {
                    end = inst;
                    assert(endidx == inst->offset);
                    break;
                }
                inst = inst->next;
            }
            assert(start);
            symtab.syms.push_back((struct qk_sym){
                .start = start,
                .end = end,
                .index = i,
                .code = code,
            });
        } else {
            // Symbol does not point into a code section.
            symtab.syms.push_back((struct qk_sym){
                .start = NULL,
                .index = i,
            });
        }
    }
}

void qk_elf::encode(const char* outname) {
    for (auto& s : codes) {
        s->encode();
    }
    for (auto& r : relas) {
        r->encode(reader, strtab, symtab.section);
    }
    symtab.encode(this);

    reader.save(outname);
}

void qk_code::fill_offsets(char* data) {
    size_t n = 0;
    size_t r = 0;
    struct qk_inst* inst = inst_front;
    while (inst) {
        inst->offset = n + rebound_size;

        if (rebound_size > 0 && inst->original) {
            uint32_t b = arm64_b((n - r + rebound_size) / 4);
            memcpy(&data[r], &b, inst->size);
            r += inst->size;
        }

        n += inst->size;
        inst = inst->next;
    }
}

void qk_code::encode() {
    if (rebound && inst_size == rebound_size) {
        // Needed a rebound table, but the section wasn't modified so we don't
        // need it after all.
        rebound_size = 0;
        rebound = false;
    }

    char* data = (char*) calloc(1, rebound_size + inst_size);
    assert(data);

    fill_offsets(data);

    size_t n = rebound_size;
    struct qk_inst* inst = inst_front;
    while (inst) {
        if (inst->target) {
            inst->data = arm64_branch_reassemble(inst->insn, inst->data, inst->target->offset - inst->offset);
        }
        memcpy(&data[n], &inst->data, inst->size);
        n += inst->size;
        inst = inst->next;
    }
    section->set_data((const char*) data, rebound_size + inst_size);
}

void qk_rela::encode(elfio& reader, ELFIO::section* strtab, ELFIO::section* symtab) {
    ELFIO::relocation_section_accessor relaa(reader, section);
    ELFIO::string_section_accessor stra(strtab);
    ELFIO::symbol_section_accessor syma(reader, symtab);
    for (size_t i = 0; i < relocs.size(); i++) {
        struct qk_reloc& reloc = relocs[i];
        switch (reloc.kind) {
        case QK_RELOC_OTHER:
            break;
        case QK_RELOC_VALUE:
            // TODO: encode qk_reloc_value
            break;
        case QK_RELOC_CODE:
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            relaa.get_entry(i, offset, symbol, type, addend);
            relaa.set_entry(i, reloc.r.code.inst->offset, symbol, type, addend);
            break;
        case QK_RELOC_NEW:
            auto& r = reloc.r.new_;
            if (r.str) {
                ELFIO::Elf_Word str_index = stra.add_string(r.str);
                ELFIO::Elf_Word sym_index = syma.add_symbol(str_index, r.value ? r.value->offset : 0, 0, r.info, 0, r.shndx);
                relaa.add_entry(r.inst->offset, sym_index, r.type, 0);
            } else {
                relaa.add_entry(r.inst->offset, STN_UNDEF, r.type, 0);
            }
            break;
        }
    }
}

void qk_symtab::encode(struct qk_elf* elf) {
    if (!section)
        return;

    symbol_section_accessor syma(elf->reader, section);
    for (size_t i = 0; i < syms.size(); i++) {
        if (syms[i].start == NULL) {
            continue;
        }
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind, type, other;
        ELFIO::Elf_Half section_index;
        syma.get_symbol(syms[i].index, name, value, size, bind, type, section_index, other);
        size_t start = syms[i].start->offset;
        if (!syms[i].end) {
            size = syms[i].code->inst_size - start;
        } else {
            size = syms[i].end->offset - start;
        }
        syma.set_symbol(syms[i].index, start, size);
    }
    syma.arrange_local_symbols([&](ELFIO::Elf_Xword first, ELFIO::Elf_Xword second) {
        for (auto& r : elf->relas) {
            relocation_section_accessor access(elf->reader, r->section);
            access.swap_symbols(first, second);
        }
    });
}

void qk_code::push_back(struct qk_inst* n) {
    n->next = NULL;
    n->prev = inst_back;
    if (inst_back)
        inst_back->next = n;
    else
        inst_front = n;
    inst_back = n;
    inst_size += n->size;
}

void qk_code::insert_after(struct qk_inst* n, struct qk_inst* inst) {
    inst->next = n->next;
    inst->prev = n;
    if (n->next) {
        n->next->prev = inst;
    } else {
        inst_back = inst;
    }
    n->next = inst;
    inst_size += inst->size;
}

void qk_code::insert_before(struct qk_inst* n, struct qk_inst* inst) {
    inst->next = n;
    inst->prev = n->prev;
    if (n->prev) {
        n->prev->next = inst;
    } else {
        inst_front = inst;
    }
    n->prev = inst;
    inst_size += inst->size;
}

std::optional<struct qk_sym> qk_symtab::get_symbol(size_t index) {
    for (auto& sym : syms) {
        if (sym.index == index) {
            return sym;
        }
    }
    return {};
}
