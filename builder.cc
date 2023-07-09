#include "builder.hh"

#include <assert.h>

struct builder* new_builder(struct elf* elf, struct exsec* s) {
    struct builder* b = (struct builder*) malloc(sizeof(struct builder));
    assert(b);
    *b = (struct builder){
        .elf = elf,
        .exsec = s,
        .cur = s->inst_front,
    };
    return b;
}

void builder::locate(struct inst* i) {
    this->cur = i;
}

struct inst* builder::insert_after(struct inst* i) {
    this->exsec->insert_after(this->cur, i);
    this->cur = i;
    return this->cur;
}

struct inst* builder::insert_before(struct inst* i) {
    this->exsec->insert_before(this->cur, i);
    this->cur = i;
    return this->cur;
}
