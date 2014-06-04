/*
 * Copyright (C) 2004, 2005, 2007, 2009, 2013, 2014  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1999-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*%
 * ChaCha based random number generator derived from OpenBSD.
 *
 * The original copyright follows:
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
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

/*! \file */

#include <config.h>

#include <stdlib.h>
#include <time.h>		/* Required for time(). */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <isc/magic.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/mem.h>
#include <isc/entropy.h>
#include <isc/random.h>
#include <isc/string.h>
#include <isc/util.h>

#define RNG_MAGIC			ISC_MAGIC('R', 'N', 'G', 'x')
#define VALID_RNG(r)			ISC_MAGIC_VALID(r, RNG_MAGIC)

#define KEYSTREAM_ONLY
#include "chacha_private.h"

#define CHACHA_KEYSIZE 32
#define CHACHA_IVSIZE 8
#define CHACHA_BLOCKSIZE 64
#define CHACHA_BUFFERSIZE (16 * CHACHA_BLOCKSIZE)

/* ChaCha RNG state */
struct isc_rng {
	unsigned int	magic;
	isc_mem_t	*mctx;
	chacha_ctx	cpctx;
	isc_uint8_t	buffer[CHACHA_BUFFERSIZE];
	size_t		have;
	unsigned int	references;
	int		count;
	isc_entropy_t	*entropy;	/*%< entropy source */
	isc_mutex_t	lock;
};

static isc_once_t once = ISC_ONCE_INIT;

static void
initialize_rand(void) {
#ifndef HAVE_ARC4RANDOM
	unsigned int pid = getpid();

	/*
	 * The low bits of pid generally change faster.
	 * Xor them with the high bits of time which change slowly.
	 */
	pid = ((pid << 16) & 0xffff0000) | ((pid >> 16) & 0xffff);

	srand((unsigned)time(NULL) ^ pid);
#endif
}

static void
initialize(void) {
	RUNTIME_CHECK(isc_once_do(&once, initialize_rand) == ISC_R_SUCCESS);
}

void
isc_random_seed(isc_uint32_t seed) {
	initialize();

#ifndef HAVE_ARC4RANDOM
	srand(seed);
#elif defined(HAVE_ARC4RANDOM_ADDRANDOM)
	arc4random_addrandom((u_char *) &seed, sizeof(isc_uint32_t));
#else
	/*
	 * If arcrandom() is available and no corresponding seeding
	 * function arc4random_addrandom() is available, no seeding is
	 * done on such platforms (e.g., OpenBSD 5.5). This is because
	 * the OS itself is supposed to seed the RNG and it is assumed
	 * that no explicit seeding is required.
	 */
#endif
}

void
isc_random_get(isc_uint32_t *val) {
	REQUIRE(val != NULL);

	initialize();

#ifndef HAVE_ARC4RANDOM
	/*
	 * rand()'s lower bits are not random.
	 * rand()'s upper bit is zero.
	 */
#if RAND_MAX >= 0xfffff
	/* We have at least 20 bits.  Use lower 16 excluding lower most 4 */
	*val = ((rand() >> 4) & 0xffff) | ((rand() << 12) & 0xffff0000);
#elif RAND_MAX >= 0x7fff
	/* We have at least 15 bits.  Use lower 10/11 excluding lower most 4 */
	*val = ((rand() >> 4) & 0x000007ff) | ((rand() << 7) & 0x003ff800) |
		((rand() << 18) & 0xffc00000);
#else
#error RAND_MAX is too small
#endif
#else
	*val = arc4random();
#endif
}

isc_uint32_t
isc_random_jitter(isc_uint32_t max, isc_uint32_t jitter) {
	isc_uint32_t rnd;

	REQUIRE(jitter < max || (jitter == 0 && max == 0));

	if (jitter == 0)
		return (max);

	isc_random_get(&rnd);
	return (max - rnd % jitter);
}

static void
chacha_reinit(isc_rng_t *rng, isc_uint8_t *buffer, size_t n) {
	REQUIRE(rng != NULL);

	if (n < CHACHA_KEYSIZE + CHACHA_IVSIZE)
		return;

	chacha_keysetup(&rng->cpctx, buffer, CHACHA_KEYSIZE * 8, 0);
	chacha_ivsetup(&rng->cpctx, buffer + CHACHA_KEYSIZE);
}

isc_result_t
isc_rng_create(isc_mem_t *mctx, isc_entropy_t *entropy, isc_rng_t **rngp) {
	union {
		unsigned char rnd[128];
		isc_uint32_t rnd32[32];
	} rnd;
	isc_result_t result;
	isc_rng_t *rng;

	REQUIRE(mctx != NULL);
	REQUIRE(rngp != NULL && *rngp == NULL);

	if (entropy != NULL) {
		/*
		 * We accept any quality of random data to avoid blocking.
		 */
		result = isc_entropy_getdata(entropy, rnd.rnd,
					     sizeof(rnd), NULL, 0);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	} else {
		int i;
		for (i = 0; i < 32; i++)
			isc_random_get(&rnd.rnd32[i]);
	}

	rng = isc_mem_get(mctx, sizeof(*rng));
	if (rng == NULL)
		return (ISC_R_NOMEMORY);

	chacha_reinit(rng, rnd.rnd, sizeof(rnd.rnd));

	rng->have = 0;
	memset(rng->buffer, 0, CHACHA_BUFFERSIZE);

	/* Create lock */
	result = isc_mutex_init(&rng->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, rng, sizeof(*rng));
		return (result);
	}

	/* Attach to memory context */
	rng->mctx = NULL;
	isc_mem_attach(mctx, &rng->mctx);

	/* Local non-algorithm initializations. */
	rng->count = 0;
	rng->entropy = entropy; /* don't have to attach */
	rng->references = 1;
	rng->magic = RNG_MAGIC;

	*rngp = rng;

	return (ISC_R_SUCCESS);
}

void
isc_rng_attach(isc_rng_t *source, isc_rng_t **targetp) {
	REQUIRE(VALID_RNG(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	LOCK(&source->lock);
	source->references++;
	UNLOCK(&source->lock);

	*targetp = (isc_rng_t *)source;
}

static void
destroy(isc_rng_t **rngp) {
	isc_rng_t *rng = *rngp;

	REQUIRE(VALID_RNG(rng));

	isc_mutex_destroy(&rng->lock);
	rng->magic = 0;
	isc_mem_putanddetach(&rng->mctx, rng, sizeof(isc_rng_t));
	*rngp = NULL;
}

void
isc_rng_detach(isc_rng_t **rngp) {
	isc_rng_t *rng = *rngp;
	isc_boolean_t dest = ISC_FALSE;

	REQUIRE(VALID_RNG(rng));

	LOCK(&rng->lock);

	INSIST(rng->references > 0);
	rng->references--;
	if (rng->references == 0)
		dest = ISC_TRUE;

	if (dest)
		destroy(rngp);
	else {
		UNLOCK(&rng->lock);
		*rngp = NULL;
	}
}

static void
chacha_rekey(isc_rng_t *rng, u_char *dat, size_t datlen) {
	REQUIRE(VALID_RNG(rng));

#ifndef KEYSTREAM_ONLY
	memset(rng->buffer, 0, CHACHA_BUFFERSIZE);
#endif

	/* Fill buffer with the keystream. */
	chacha_encrypt_bytes(&rng->cpctx, rng->buffer, rng->buffer,
			     CHACHA_BUFFERSIZE);

	/* Mix in optional user provided data. */
	if (dat != NULL) {
		size_t i, m;

		m = ISC_MIN(datlen, CHACHA_KEYSIZE + CHACHA_IVSIZE);
		for (i = 0; i < m; i++)
			rng->buffer[i] ^= dat[i];
	}

	/* Immediately reinit for backtracking resistance. */
	chacha_reinit(rng, rng->buffer,
		      CHACHA_KEYSIZE + CHACHA_IVSIZE);
	memset(rng->buffer, 0, CHACHA_KEYSIZE + CHACHA_IVSIZE);
	rng->have = CHACHA_BUFFERSIZE - CHACHA_KEYSIZE - CHACHA_IVSIZE;
}

static inline isc_uint16_t
chacha_getuint16(isc_rng_t *rng) {
	isc_uint16_t val;

	REQUIRE(VALID_RNG(rng));

	if (rng->have < sizeof(val))
		chacha_rekey(rng, NULL, 0);

	memcpy(&val, rng->buffer + CHACHA_BUFFERSIZE - rng->have,
	       sizeof(val));
	/* Clear the copied region. */
	memset(rng->buffer + CHACHA_BUFFERSIZE - rng->have,
	       0, sizeof(val));
	rng->have -= sizeof(val);

	return (val);
}

static void
chacha_stir(isc_rng_t *rng) {
	union {
		unsigned char rnd[128];
		isc_uint32_t rnd32[32];
	} rnd;
	isc_result_t result;

	REQUIRE(VALID_RNG(rng));

	if (rng->entropy != NULL) {
		/*
		 * We accept any quality of random data to avoid blocking.
		 */
		result = isc_entropy_getdata(rng->entropy, rnd.rnd,
					     sizeof(rnd), NULL, 0);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	} else {
		int i;
		for (i = 0; i < 32; i++)
			isc_random_get(&rnd.rnd32[i]);
	}

	chacha_rekey(rng, rnd.rnd, sizeof(rnd.rnd));

	/*
	 * The OpenBSD implementation explicit_bzero()s the random seed
	 * rnd.rnd at this point, but it may not be required here. This
	 * memset() may also be optimized away by the compiler as
	 * rnd.rnd is not used further.
	 */
	memset(rnd.rnd, 0, sizeof(rnd.rnd));

	/* Invalidate the buffer too. */
	rng->have = 0;
	memset(rng->buffer, 0, CHACHA_BUFFERSIZE);

	/*
	 * Derived from OpenBSD's implementation.  The rationale is not clear,
	 * but should be conservative enough in safety, and reasonably large
	 * for efficiency.
	 */
	rng->count = 1600000;
}

isc_uint16_t
isc_rng_random(isc_rng_t *rng) {
	isc_uint16_t result;

	REQUIRE(VALID_RNG(rng));

	LOCK(&rng->lock);

	rng->count -= sizeof(isc_uint16_t);
	if (rng->count <= 0)
		chacha_stir(rng);
	result = chacha_getuint16(rng);

	UNLOCK(&rng->lock);

	return (result);
}

isc_uint16_t
isc_rng_uniformrandom(isc_rng_t *rng, isc_uint16_t upper_bound) {
	isc_uint16_t min, r;

	REQUIRE(VALID_RNG(rng));

	if (upper_bound < 2)
		return (0);

	/*
	 * Ensure the range of random numbers [min, 0xffff] be a multiple of
	 * upper_bound and contain at least a half of the 16 bit range.
	 */

	if (upper_bound > 0x8000)
		min = 1 + ~upper_bound; /* 0x8000 - upper_bound */
	else
		min = (isc_uint16_t)(0x10000 % (isc_uint32_t)upper_bound);

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = isc_rng_random(rng);
		if (r >= min)
			break;
	}

	return (r % upper_bound);
}
