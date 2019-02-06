/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD: cipher-chachapoly.c,v 1.8 2016/08/03 05:41:57 djm Exp $ */

#include "includes.h"

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

int
chachapoly_init(struct chachapoly_ctx *ctx,
    const u_char *key, u_int keylen, int do_encrypt)
{
	int ret = 0;
#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
	static const u_char poly_key[POLY1305_KEYLEN] = "\xc8\xaf\xaa\xc3\x31\xee\x37\x2c\xd6\x08\x2d\xe1\x34\x94\x3b\x17\x47\x10\x13\x0e\x9f\x6f\xea\x8d\x72\x29\x38\x50\xa6\x67\xd8\x6c";
	u_char poly_tag[POLY1305_TAGLEN];
	size_t tag_len = POLY1305_TAGLEN;
#endif

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return SSH_ERR_INVALID_ARGUMENT;
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	if ((ctx->main_evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ctx->header_evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, NULL,
				do_encrypt)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, NULL,
				do_encrypt)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#else
	chacha_keysetup(&ctx->main_ctx, key, 256);
	chacha_keysetup(&ctx->header_ctx, key + 32, 256);
#endif
#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
	if (!(ctx->key = EVP_PKEY_new_mac_key(EVP_PKEY_POLY1305, NULL, poly_key, sizeof(poly_key))))
		goto out;
	if (!(ctx->mctx = EVP_MD_CTX_new()))
		goto out;
	if (EVP_DigestSignInit(ctx->mctx, &ctx->pctx, NULL, NULL, ctx->key) <= 0)
		goto out;
	/* Sanity check */
	if (EVP_DigestSignFinal(ctx->mctx, NULL, &tag_len) <= 0) {
		ctx->pctx = NULL;
		goto out; /* pretend openssl/poly1305 is not supported */
	}
	if (tag_len != POLY1305_TAGLEN) {
		ctx->pctx = NULL;
		goto out;
	}
	if (EVP_DigestSignFinal(ctx->mctx, poly_tag, &tag_len) <= 0) {
		ctx->pctx = NULL;
		goto out;
	}
	if (memcmp(poly_tag, "\x47\x10\x13\x0e\x9f\x6f\xea\x8d\x72\x29\x38\x50\xa6\x67\xd8\x6c", sizeof(poly_tag)) != 0) {
		ctx->pctx = NULL;
		goto out;
	}
#endif
out:
	if (ret != 0)
		chachapoly_done(ctx);
	return ret;
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	u_char seqbuf[16];
	int r = SSH_ERR_LIBCRYPTO_ERROR;
#else
	u_char seqbuf[8];
	int r = SSH_ERR_INTERNAL_ERROR;
	const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
#endif
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	memset(seqbuf + 0, 0, 8);
	POKE_U64(seqbuf + 8, seqnr);
	if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, do_encrypt))
		goto out;
	if (EVP_Cipher(ctx->main_evp, poly_key, (u_char *)poly_key, sizeof(poly_key)) < 0)
		goto out;
#else
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_key, poly_key, sizeof(poly_key));
#endif

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
		/* avoid openssl poly1305 setup overhead for short messages */
		if (aadlen + len >= 512 && ctx->pctx != NULL) {
			size_t tag_len = POLY1305_TAGLEN;
			if (EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(poly_key), (void *)poly_key) <= 0)
				goto out;
			if (EVP_DigestSignUpdate(ctx->mctx, src, aadlen + len) <= 0)
				goto out;
#if 0
			if (EVP_DigestSignFinal(ctx->mctx, NULL, &tag_len) <= 0)
				goto out;
			if (tag_len != POLY1305_TAGLEN)
				goto out;
#endif
			if (EVP_DigestSignFinal(ctx->mctx, expected_tag, &tag_len) <= 0)
				goto out;
		} else
#endif
		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	if (aadlen) {
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
		if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, do_encrypt))
			goto out;
		if (EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0)
			goto out;
#else
		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
#endif
	}

	/* Set Chacha's block counter to 1 */
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	seqbuf[0] = 1;
	if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, do_encrypt))
		goto out;
	if (EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0)
		goto out;
#else
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);
#endif

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
		/* avoid openssl poly1305 setup overhead for short messages */
		if (aadlen + len >= 512 && ctx->pctx != NULL) {
			size_t tag_len = POLY1305_TAGLEN;

			if (EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_MAC_KEY, sizeof(poly_key), (void *)poly_key) <= 0)
				goto out;
			if (EVP_DigestSignUpdate(ctx->mctx, dest, aadlen + len) <= 0)
				goto out;
#if 0
			if (EVP_DigestSignFinal(ctx->mctx, NULL, &tag_len) <= 0)
				goto out;
			if (tag_len != POLY1305_TAGLEN)
				goto out;
#endif
			if (EVP_DigestSignFinal(ctx->mctx, dest + aadlen + len, &tag_len) <= 0)
				goto out;
		} else
#endif
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	memset(seqbuf + 0, 0, 8);
	POKE_U64(seqbuf + 8, seqnr);
	if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 0))
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, 4) < 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
#else
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
#endif
	*plenp = PEEK_U32(buf);
	return 0;
}

int	chachapoly_done(struct chachapoly_ctx *cpctx) {
#if defined(WITH_OPENSSL) && defined(EVP_PKEY_POLY1305)
	/* cpctx->pctx should not be freed */
	EVP_MD_CTX_free(cpctx->mctx);
	EVP_PKEY_free(cpctx->key);
#endif
#if defined(WITH_OPENSSL) && defined(HAVE_EVP_CHACHA20)
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	cpctx->main_evp = cpctx->header_evp = NULL;
#else
	explicit_bzero(cpctx, sizeof(*cpctx));
#endif
	return 0;
}
