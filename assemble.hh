#pragma once

#include <capstone/capstone.h>
#include <assert.h>

#include "bits.hh"

static inline uint32_t reassemble(cs_insn insn, uint32_t data, int64_t imm) {
    switch (insn.id) {
    case ARM64_INS_B:
        if (insn.detail->arm64.cc != ARM64_CC_INVALID) {
            // b.cond
            return bits_set(data, 24, 5, imm >> 2);
        } else {
            // b.uncond
            return bits_set(data, 25, 0, imm >> 2);
        }
    case ARM64_INS_BL:
        return bits_set(data, 25, 0, imm >> 2);
    case ARM64_INS_CBZ:
        return bits_set(data, 24, 5, imm >> 2);
    case ARM64_INS_CBNZ:
        return bits_set(data, 24, 5, imm >> 2);
    case ARM64_INS_TBZ:
        return bits_set(data, 19, 5, imm >> 2);
    case ARM64_INS_TBNZ:
        return bits_set(data, 19, 5, imm >> 2);
    default:
        assert(0);
        return 0;
    }
}

static inline uint32_t arm64_bl(uint32_t imm) {
    return 0x94000000 | imm;
}
