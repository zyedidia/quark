#include <stdio.h>
#include <assert.h>
#include <capstone/capstone.h>

#include "elfio/elfio.hpp"
#include "quark.hh"
#include "builder.hh"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cout << "Usage: quark <elf_file> <output_file>" << std::endl;
        return 1;
    }

    ELFIO::elfio reader;

    if (!reader.load(argv[1])) {
        std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
        return 2;
    }

    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        std::cout << "Could not open arm64 disassembler" << std::endl;
        return 3;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    assert(reader.get_class() == ELFIO::ELFCLASS64);
    assert(reader.get_encoding() == ELFIO::ELFDATA2LSB);
    assert(reader.get_type() == ELFIO::ET_REL);

    const uint64_t INST_RET = 0xd65f03c0;

    struct elf elf = quark_readelf(reader, handle);

    ELFIO::Elf64_Addr _value;
    ELFIO::Elf_Xword _size;
    unsigned char _bind, _type, _other;
    ELFIO::Elf_Half _section_index;
    ELFIO::symbol_section_accessor syma(elf.reader, elf.symtab.symtab);
    if (syma.get_symbol("quark_notouch", _value, _size, _bind, _type, _section_index, _other)) {
        printf("found quark_notouch\n");
        goto done;
    }

    for (auto& sec : elf.exsecs) {
        struct builder* b = new_builder(&elf, sec);
        struct inst* inst = sec->inst_front;
        while (inst) {
            if (inst->data == INST_RET) {
                b->locate(inst);
                // b->insert_rtcall_before("on_return");
                b->insert_before(new_inst((struct inst_dat){
                    .data = 0xd503201f,
                    .size = 4,
                }));
            }
            inst = inst->next;
        }
        free(b);
    }

done:
    elf.encode(argv[2]);

    cs_close(&handle);

    return 0;
}

#ifdef __cplusplus
extern "C"
#endif
const char* __asan_default_options() { return "detect_leaks=0"; }
