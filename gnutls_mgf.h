#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <nettle/nettle-meta.h>

/*!
 * MGF1, Mask Generation Function based on a hash function.
 *
 * \see RFC 2437, section 10.2.1
 *
 * \param[out] mask      Resulting mask.
 * \param[in]  mask_len  Requested length of the mask.
 * \param[in]  seed      Seed.
 * \param[in]  seed_len  Length of the seed.
 * \param[in]  hash      Hash function.
 */
void mgf_nettle(uint8_t *mask, size_t mask_len,
		const uint8_t *seed, size_t seed_len,
		const struct nettle_hash *hash);
