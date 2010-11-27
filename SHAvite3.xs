#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "src/sha3nist.c"
#include "src/shavite3.c"

typedef hashState *Digest__SHAvite3;

MODULE = Digest::SHAvite3    PACKAGE = Digest::SHAvite3

PROTOTYPES: ENABLE

SV *
shavite3_224 (...)
ALIAS:
    shavite3_224 = 224
    shavite3_256 = 256
    shavite3_384 = 384
    shavite3_512 = 512
PREINIT:
    hashState ctx;
    int i;
    unsigned char *data;
    unsigned char *result;
    STRLEN len;
CODE:
    if (Init(&ctx, ix) != SUCCESS)
        XSRETURN_UNDEF;
    for (i = 0; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(&ctx, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    Newx(result, ix >> 3, unsigned char);
    if (Final(&ctx, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, ix >> 3);
    Safefree(result);
OUTPUT:
    RETVAL

Digest::SHAvite3
new (class, hashsize)
    SV *class
    int hashsize
CODE:
    Newx(RETVAL, 1, hashState);
    if (Init(RETVAL, hashsize) != SUCCESS)
        XSRETURN_UNDEF;
OUTPUT:
    RETVAL

Digest::SHAvite3
clone (self)
    Digest::SHAvite3 self
CODE:
    Newx(RETVAL, 1, hashState);
    Copy(self, RETVAL, 1, hashState);
OUTPUT:
    RETVAL

void
reset (self)
    Digest::SHAvite3 self
PPCODE:
    if (Init(self, self->hashbitlen) != SUCCESS)
        XSRETURN_UNDEF;
    XSRETURN(1);

int
hashsize(self)
    Digest::SHAvite3 self
ALIAS:
    algorithm = 1
CODE:
    RETVAL = self->hashbitlen;
OUTPUT:
    RETVAL

void
add (self, ...)
    Digest::SHAvite3 self
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    for (i = 1; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(self, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    XSRETURN(1);

void
_add_bits (self, msg, bitlen)
    Digest::SHAvite3 self
    SV *msg
    int bitlen
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    if (! bitlen)
        XSRETURN(1);
    data = (unsigned char *)(SvPV(msg, len));
    if (bitlen > len << 3)
        bitlen = len << 3;
    if (Update(self, data, bitlen) != SUCCESS)
        XSRETURN_UNDEF;
    XSRETURN(1);

SV *
digest (self)
    Digest::SHAvite3 self
PREINIT:
    unsigned char *result;
CODE:
    Newx(result, self->hashbitlen >> 3, unsigned char);
    if (Final(self, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, self->hashbitlen >> 3);
    Init(self, self->hashbitlen);
    Safefree(result);
OUTPUT:
    RETVAL

void
DESTROY (self)
    Digest::SHAvite3 self
CODE:
    Safefree(self);
