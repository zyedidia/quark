#include <stdio.h>
#include <assert.h>

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

    assert(reader.get_class() == ELFIO::ELFCLASS64);
    assert(reader.get_encoding() == ELFIO::ELFDATA2LSB);
    assert(reader.get_type() == ELFIO::ET_REL);

    const uint32_t INST_RET = 0x8082;

    struct elf elf = quark_readelf(reader);
    for (auto& sec : elf.exsecs) {
        struct builder* b = new_builder(&elf, sec);
        struct inst* inst = sec->inst_front;
        while (inst) {
            if (inst->data == INST_RET) {
                b->locate(inst);
                b->insert_rtcall_before("__quark_callback");
            }
            inst = inst->next;
        }
        free(b);
    }
    elf.encode(argv[2]);

    return 0;
}

#ifdef __cplusplus
extern "C"
#endif
const char* __asan_default_options() { return "detect_leaks=0"; }
