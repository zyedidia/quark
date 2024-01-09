#include <stdio.h>
#include <assert.h>
#include <capstone/capstone.h>

#include "elfio/elfio.hpp"
#include "quark.hh"

using namespace ELFIO;

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    elfio reader;

    if (!reader.load(argv[1])) {
        fprintf(stderr, "unable to load file %s\n", argv[1]);
        return 1;
    }

    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "could not open arm64 disassembler\n");
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    assert(reader.get_class() == ELFIO::ELFCLASS64);
    assert(reader.get_encoding() == ELFIO::ELFDATA2LSB);
    assert(reader.get_type() == ELFIO::ET_REL);

    struct qk_elf elf = qk_readelf(reader, handle);

    elf.encode(argv[2]);
    cs_close(&handle);

    return 0;
}

#ifdef __cplusplus
extern "C"
#endif
const char* __asan_default_options() { return "detect_leaks=0"; }
