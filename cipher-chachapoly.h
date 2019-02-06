/* $OpenBSD: cipher-chachapoly.h,v 1.4 2014/06/24 01:13:21 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef CHACHA_POLY_AEAD_H
#define CHACHA_POLY_AEAD_H

#include <sys/types.h>
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
#include <openssl/evp.h>
#else
#include "chacha.h"
#endif
#include "poly1305.h"

#define CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

struct chachapoly_ctx {
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	EVP_CIPHER_CTX *main_evp, *header_evp;
#else
	struct chacha_ctx main_ctx, header_ctx;
#endif
#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
	EVP_MD_CTX *mctx;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *key;
#endif
};

int	chachapoly_init(struct chachapoly_ctx *cpctx,
    const u_char *key, u_int keylen, int do_encrypt)
    __attribute__((__bounded__(__buffer__, 2, 3)));
int	chachapoly_crypt(struct chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, const u_char *src, u_int len, u_int aadlen, u_int authlen,
    int do_encrypt);
int	chachapoly_get_length(struct chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));
int	chachapoly_done(struct chachapoly_ctx *cpctx);

#endif /* CHACHA_POLY_AEAD_H */
