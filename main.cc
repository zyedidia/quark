#include <stdio.h>
#include <assert.h>

#include "elfio/elfio.hpp"
#include "quark.hh"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: quark <elf_file>" << std::endl;
        return 1;
    }

    ELFIO::elfio reader;

    if (!reader.load(argv[1])) {
        std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
        return 2;
    }

    struct inst nop = (struct inst){
        .data = 0x00000013,
        .size = sizeof(uint32_t),
    };

    assert(reader.get_class() == ELFIO::ELFCLASS64);
    assert(reader.get_encoding() == ELFIO::ELFDATA2LSB);
    assert(reader.get_type() == ELFIO::ET_REL);

    struct elf elf = quark_readelf(reader);
    for (auto& sec : elf.exsecs) {
        if (sec->inst_front) {
            sec->insert_after(sec->inst_front, &nop);
        }
    }
    elf.encode("out.o");

    return 0;
}

#ifdef __cplusplus
extern "C"
#endif
const char* __asan_default_options() { return "detect_leaks=0"; }
