#pragma once

#include <assert.h>
#include <capstone/capstone.h>

#include "bits.hh"

static inline int64_t arm64_branch_target(cs_insn insn) {
    cs_detail* detail = insn.detail;
    switch (insn.id) {
    case ARM64_INS_B:
        return detail->arm64.operands[0].imm;
    case ARM64_INS_BL:
        return detail->arm64.operands[0].imm;
    case ARM64_INS_CBZ:
        return detail->arm64.operands[1].imm;
    case ARM64_INS_CBNZ:
        return detail->arm64.operands[1].imm;
    case ARM64_INS_TBZ:
        return detail->arm64.operands[2].imm;
    case ARM64_INS_TBNZ:
        return detail->arm64.operands[2].imm;
    }
    return -1;
}

static inline uint32_t arm64_branch_reassemble(cs_insn insn, uint32_t data, int64_t imm) {
    imm = imm >> 2;
    switch (insn.id) {
    case ARM64_INS_B:
        if (insn.detail->arm64.cc != ARM64_CC_INVALID) {
            // b.cond
            imm = imm & bits_mask(23 - 5 + 1);
            return bits_set(data, 23, 5, imm);
        } else {
            // b.uncond
            imm = imm & bits_mask(25 - 0 + 1);
            return bits_set(data, 25, 0, imm);
        }
    case ARM64_INS_BL:
        imm = imm & bits_mask(25 - 0 + 1);
        return bits_set(data, 25, 0, imm);
    case ARM64_INS_CBZ:
        imm = imm & bits_mask(23 - 5 + 1);
        return bits_set(data, 23, 5, imm);
    case ARM64_INS_CBNZ:
        imm = imm & bits_mask(23 - 5 + 1);
        return bits_set(data, 23, 5, imm);
    case ARM64_INS_TBZ:
        imm = imm & bits_mask(18 - 5 + 1);
        return bits_set(data, 18, 5, imm);
    case ARM64_INS_TBNZ:
        imm = imm & bits_mask(18 - 5 + 1);
        return bits_set(data, 18, 5, imm);
    default:
        assert(0);
        return 0;
    }
}

static inline uint32_t arm64_bl(uint32_t imm) {
    return 0x94000000 | imm;
}

static inline uint32_t arm64_b(uint32_t imm) {
    return 0x14000000 | imm;
}
