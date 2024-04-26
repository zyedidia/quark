#pragma once

#include <assert.h>
#include <capstone/capstone.h>

#include "bits.hh"

static inline bool arm64_is_adr(cs_insn insn) {
    return insn.id == AArch64_INS_ADR;
}

static inline int64_t arm64_target(cs_insn insn) {
    cs_detail* detail = insn.detail;
    switch (insn.id) {
    case AArch64_INS_B:
        return detail->aarch64.operands[0].imm;
    case AArch64_INS_BL:
        return detail->aarch64.operands[0].imm;
    case AArch64_INS_CBZ:
        return detail->aarch64.operands[1].imm;
    case AArch64_INS_CBNZ:
        return detail->aarch64.operands[1].imm;
    case AArch64_INS_TBZ:
        return detail->aarch64.operands[2].imm;
    case AArch64_INS_TBNZ:
        return detail->aarch64.operands[2].imm;
    }
    return -1;
}

static inline uint32_t arm64_reassemble(cs_insn insn, uint32_t data, int64_t imm) {
    switch (insn.id) {
    case AArch64_INS_B:
        imm = imm >> 2;
        if (insn.detail->aarch64.cc != AArch64CC_Invalid) {
            // b.cond
            imm = imm & bits_mask(23 - 5 + 1);
            return bits_set(data, 23, 5, imm);
        } else {
            // b.uncond
            imm = imm & bits_mask(25 - 0 + 1);
            return bits_set(data, 25, 0, imm);
        }
    case AArch64_INS_BL:
        imm = imm >> 2;
        imm = imm & bits_mask(25 - 0 + 1);
        return bits_set(data, 25, 0, imm);
    case AArch64_INS_CBZ:
        imm = imm >> 2;
        imm = imm & bits_mask(23 - 5 + 1);
        return bits_set(data, 23, 5, imm);
    case AArch64_INS_CBNZ:
        imm = imm >> 2;
        imm = imm & bits_mask(23 - 5 + 1);
        return bits_set(data, 23, 5, imm);
    case AArch64_INS_TBZ:
        imm = imm >> 2;
        imm = imm & bits_mask(18 - 5 + 1);
        return bits_set(data, 18, 5, imm);
    case AArch64_INS_TBNZ:
        imm = imm >> 2;
        imm = imm & bits_mask(18 - 5 + 1);
        return bits_set(data, 18, 5, imm);
    case AArch64_INS_ADR:
        data = bits_set(data, 30, 29, bits_get(imm, 1, 0));
        data = bits_set(data, 23, 5, bits_get(imm, 20, 2));
        return data;
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

static inline uint32_t arm64_adr_imm(uint32_t insn) {
    return (bits_get(insn, 23, 5) << 2) | bits_get(insn, 30, 29);
}
