#include <assert.h>

#include "quark.hh"
#include "assemble.hh"

#include <elf.h>
#include <capstone/capstone.h>

struct elf quark_readelf(ELFIO::elfio& reader, csh handle) {
    struct elf elf = (struct elf){
        .reader = reader,
        .handle = handle,
    };

    ELFIO::Elf_Half n_sec = reader.sections.size();

    ELFIO::section* symsec = NULL;
    for (size_t i = 0; i < n_sec; i++) {
        ELFIO::section* ssec = reader.sections[i];
        if (ssec->get_type() == SHT_SYMTAB) {
            symsec = ssec;
            break;
        }
    }
    // assert(symsec);
    elf.symtab.symtab = symsec;

    for (size_t i = 0; i < n_sec; i++) {
        ELFIO::section* ssec = reader.sections[i];
        if (ssec->get_type() == SHT_STRTAB) {
            elf.strsec = ssec;
            break;
        }
    }
    // assert(elf.strsec);

    for (size_t i = 0; i < n_sec; i++) {
        ELFIO::section* psec = reader.sections[i];
        if ((psec->get_flags() & SHF_EXECINSTR) != 0) {
            ELFIO::section* relasec = NULL;
            for (size_t j = 0; j < n_sec; j++) {
                ELFIO::section* rsec = reader.sections[j];
                if (rsec->get_type() == SHT_RELA && rsec->get_info() == i) {
                    relasec = rsec;
                    break;
                }
            }

            struct exsec* exsec = (struct exsec*) malloc(sizeof(struct exsec));
            assert(exsec);
            *exsec = (struct exsec){
                .section = psec,
                .rela = NULL,
                .index = i,
                .inst_front = NULL,
                .inst_back = NULL,
                .inst_size = 0,
            };

            ELFIO::Elf_Xword size = psec->get_size();
            const char* data = psec->get_data();

            std::vector<struct inst*> insts;

            size_t n = 0;
            while (n < size) {
                cs_insn* insn = NULL;
                size_t addr = n;
                size_t count = cs_disasm(elf.handle, (uint8_t*) &data[n], 4, addr, 0, &insn);
                if (count != 1) {
                    fprintf(stderr, "failed to disassemble %x at %lx", *((uint32_t*) &data[n]), addr);
                }
                size_t length = 4;

                struct inst* inst = (struct inst*) calloc(1, sizeof(struct inst));
                assert(inst);

                inst->original = true;

                memcpy(&inst->data, &data[n], length);
                inst->size = length;
                inst->offset = n;

                int64_t target = -1;

                if (insn != NULL) {
                    inst->insn = insn[0];

                    cs_detail* detail = inst->insn.detail;
                    switch (inst->insn.id) {
                    case ARM64_INS_B:
                        target = detail->arm64.operands[0].imm;
                        break;
                    case ARM64_INS_BL:
                        target = detail->arm64.operands[0].imm;
                        break;
                    case ARM64_INS_CBZ:
                        target = detail->arm64.operands[1].imm;
                        break;
                    case ARM64_INS_CBNZ:
                        target = detail->arm64.operands[1].imm;
                        break;
                    case ARM64_INS_TBZ:
                        target = detail->arm64.operands[2].imm;
                        break;
                    case ARM64_INS_TBNZ:
                        target = detail->arm64.operands[2].imm;
                        break;
                    case ARM64_INS_BR:
                        exsec->needs_rebound = true;
                        break;
                    }
                }

                inst->_target_addr = target;

                exsec->push_back(inst);
                n += length;

                insts.push_back(inst);
            }

            const size_t INST_SIZE = 4;
            for (struct inst* inst : insts) {
                if (inst->_target_addr != -1) {
                    inst->target = insts[inst->_target_addr / INST_SIZE];
                }
            }

            if (exsec->needs_rebound) {
                exsec->orig_size = exsec->inst_size;
            }

            elf.exsecs.push_back(exsec);

            if (relasec != NULL) {
                struct rela* relap = (struct rela*) calloc(1, sizeof(struct rela));
                assert(relap);
                relap->rela = relasec;

                ELFIO::relocation_section_accessor rela(reader, relasec);
                for (size_t i = 0; i < rela.get_entries_num(); i++) {
                    Elf64_Addr offset;
                    ELFIO::Elf_Word symbol;
                    ELFIO::Elf_Word type;
                    ELFIO::Elf_Sxword addend;
                    rela.get_entry(i, offset, symbol, type, addend);

                    struct inst* inst = exsec->inst_front;
                    while (inst) {
                        if (offset >= inst->offset && offset < inst->offset + inst->size) {
                            struct reloc reloc = (struct reloc){
                                .inst = inst,
                            };
                            assert(offset == inst->offset);
                            inst->has_reloc = true;
                            relap->relocs.push_back(reloc);
                            break;
                        }
                        inst = inst->next;
                    }
                }
                elf.relas.push_back(relap);
                exsec->rela = relap;
            }
        }
    }

    if (!symsec)
        return elf;

    ELFIO::symbol_section_accessor syma(reader, symsec);
    for (size_t i = 0; i < syma.get_symbols_num(); i++) {
        std::string name;
        Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind, type, other;
        ELFIO::Elf_Half section_index;
        syma.get_symbol(i, name, value, size, bind, type, section_index, other);
        if (section_index != SHN_COMMON && section_index < n_sec && (reader.sections[section_index]->get_flags() & SHF_EXECINSTR) != 0) {
            struct exsec* exsec = NULL;
            struct inst* inst = NULL;
            for (auto& s : elf.exsecs) {
                if (s->index == section_index) {
                    exsec = s;
                    inst = s->inst_front;
                }
            }
            if (!inst) {
                continue;
            }
            assert(inst);
            struct inst* start = NULL;
            struct inst* end = NULL;
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
            elf.symtab.syms.push_back((struct sym){
                .start = start,
                .end = end,
                .index = i,
                .exsec = exsec,
            });
        } else {
            elf.symtab.syms.push_back((struct sym){
                .start = NULL,
                .index = i,
            });
        }
    }

    return elf;
}

void elf::encode(const char* outname) {
    for (auto& s : this->exsecs) {
        s->encode();
    }
    for (auto& r : this->relas) {
        r->encode(this->reader, this->strsec, this->symtab.symtab);
    }
    this->symtab.encode(this);
    reader.save(outname);
}

void exsec::insert_after(struct inst* n, struct inst* inst) {
    inst->next = n->next;
    inst->prev = n;
    if (n->next) {
        n->next->prev = inst;
    } else {
        this->inst_back = inst;
    }
    n->next = inst;
    this->inst_size += inst->size;
}

void exsec::insert_before(struct inst* n, struct inst* inst) {
    inst->next = n;
    inst->prev = n->prev;
    if (n->prev) {
        n->prev->next = inst;
    } else {
        this->inst_front = inst;
    }
    n->prev = inst;
    this->inst_size += inst->size;
}

void exsec::push_back(struct inst* n) {
    n->next = NULL;
    n->prev = this->inst_back;
    if (this->inst_back)
        this->inst_back->next = n;
    else
        this->inst_front = n;
    this->inst_back = n;
    this->inst_size += n->size;
}

void exsec::encode() {
    char* data = (char*) calloc(this->inst_size + this->orig_size, 1);
    assert(data);

    size_t n = 0;
    size_t r = 0;
    struct inst* inst = this->inst_front;
    while (inst) {
        inst->offset = n + orig_size;
        inst->rebound_offset = r;

        if (needs_rebound) {
            if (inst->original) {
                uint32_t bl = arm64_bl((n - r + orig_size) / 4);
                memcpy(&data[r], &bl, inst->size);
                r += inst->size;
            }
        }

        n += inst->size;
        inst = inst->next;
    }

    n = r;
    inst = this->inst_front;
    while (inst) {
        if (inst->target != NULL) {
            inst->data = reassemble(inst->insn, inst->data, inst->target->offset - inst->offset);
        }
        memcpy(&data[n], &inst->data, inst->size);
        n += inst->size;
        inst = inst->next;
    }
    this->section->set_data((const char*) data, this->inst_size + this->orig_size);
}

void rela::encode(ELFIO::elfio& reader, ELFIO::section* strsec, ELFIO::section* symtab) {
    ELFIO::relocation_section_accessor rela(reader, this->rela);
    ELFIO::string_section_accessor stra(strsec);
    ELFIO::symbol_section_accessor syma(reader, symtab);
    for (size_t i = 0; i < this->relocs.size(); i++) {
        struct reloc& r = this->relocs[i];
        if (r.new_reloc) {
            if (r.str) {
                ELFIO::Elf_Word str_index = stra.add_string(r.str);
                ELFIO::Elf_Word sym_index = syma.add_symbol(str_index, r.value ? r.value->offset : 0, 0, r.info, 0, r.shndx);
                rela.add_entry(r.inst->offset, sym_index, r.type, 0);
            } else {
                rela.add_entry(r.inst->offset, STN_UNDEF, r.type, 0);
            }
        } else {
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            rela.get_entry(i, offset, symbol, type, addend);
            rela.set_entry(i, r.inst->offset, symbol, type, addend);
        }
    }
}

void symtab::encode(struct elf* elf) {
    if (!this->symtab)
        return;

    ELFIO::symbol_section_accessor syma(elf->reader, this->symtab);
    for (size_t i = 0; i < this->syms.size(); i++) {
        if (this->syms[i].start == NULL) {
            continue;
        }
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind, type, other;
        ELFIO::Elf_Half section_index;
        syma.get_symbol(this->syms[i].index, name, value, size, bind, type, section_index, other);
        size_t start = this->syms[i].start->offset;
        if (!this->syms[i].end) {
            size = this->syms[i].exsec->inst_size - start;
        } else {
            size = this->syms[i].end->offset - start;
        }
        syma.set_symbol(this->syms[i].index, start, size);
    }
    syma.arrange_local_symbols([&](ELFIO::Elf_Xword first, ELFIO::Elf_Xword second) {
        for (auto& r : elf->relas) {
            ELFIO::relocation_section_accessor access(elf->reader, r->rela);
            access.swap_symbols(first, second);
        }
    });
}
