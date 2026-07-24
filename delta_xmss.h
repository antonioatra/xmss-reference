/*
 * delta_xmss.h — Delta encoding of XMSS authentication paths.
 *
 * Public API of Delta-XMSS, as described in the paper "Delta-XMSS:
 * Incremental State Optimization for Post-Quantum Hash-Based
 * Signatures" (SBSeg 2026). See delta_xmss.c for the algorithm
 * details and the mapping to the paper (Algorithms 1-2, Lemma 1).
 *
 * Convention used throughout: `idx` is the PREVIOUS leaf index and
 * `sm` is the serialized XMSS signature (RFC 8391 layout) of idx+1.
 * The authentication paths of idx and idx+1 differ exactly in levels
 * 0..nu(idx), where nu(idx) is the number of trailing ones in idx.
 */

#ifndef DELTA_XMSS_H
#define DELTA_XMSS_H

#include <stdint.h>
#include "params.h"

/* Number of trailing ones */
unsigned int delta_nu(uint32_t idx);

/* Returns a pointer to the authentication path inside a signed message */
const unsigned char *delta_get_auth_path(const xmss_params *params,
                                         const unsigned char *sm);

/* Returns the leaf index stored in a signed message sm. */
uint32_t delta_get_idx(const xmss_params *params, const unsigned char *sm);

/* copy the (nu+1) changed nodes from sm into delta */
void delta_encode(const xmss_params *params,
                  unsigned char *delta, unsigned int *delta_len,
                  const unsigned char *sm, uint32_t idx);

/* update cache with the changed nodes; levels above nu stay untouched */
void delta_decode(const xmss_params *params,
                  unsigned char *cache,
                  const unsigned char *delta,
                  uint32_t idx);

#endif /* DELTA_XMSS_H */