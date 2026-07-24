/*
 * delta_xmss.c — Delta encoding of XMSS authentication paths.
 * Implements the Delta-XMSS scheme described in the paper
 * "Delta-XMSS: Incremental State Optimization for Post-Quantum
 * Hash-Based Signatures" (SBSeg 2026).
 *
 *   delta_nu() — computes nu(idx), the number of trailing
 *                    ones in the binary representation of idx
 *   delta_encode() — Algorithm 1 of the paper. Selects the
 *                    nu(idx)+1 nodes that differ between the
 *                    authentication paths of idx and idx+1
 *   delta_decode() — Algorithm 2 of the paper. Reconstructs
 *                    A_{idx+1} from the cached A_idx and the
 *                    received delta (correctness: Lemma 1)
 */

#include <string.h>
#include <stdint.h>
#include "delta_xmss.h"
#include "params.h"


/*
 * nu(idx): number of trailing ones in the binary representation of idx.
 * This is the highest tree level at which the paths of idx and idx+1
 * differ at exactly nu(idx)+1 nodes (levels 0..nu) change between them.
 * nu(idx) = 0 for every even idx, i.e. for half of all indices.
 */
unsigned int delta_nu(uint32_t idx)
{
    unsigned int count = 0;

    while (idx & 1) {
        idx >>= 1;
        count++;
    }
    return count;
}


/*
 * Returns a pointer to the authentication path inside a serialized
 * XMSS signature sm. By RFC 8391, the signature layout is:
 *   | index | randomness R | WOTS+ signature | auth path |
 * so the path starts after index_bytes + n + wots_sig_bytes.
 */
const unsigned char *delta_get_auth_path(const xmss_params *params, const unsigned char *sm)
{
    return sm + params->index_bytes + params->n + params->wots_sig_bytes;
}


/*
 * Extracts the leaf index from a serialized XMSS signature sm
 * (big-endian, first index_bytes bytes of the signature).
 */
uint32_t delta_get_idx(const xmss_params *params, const unsigned char *sm)
{
    uint32_t idx = 0;

    for (unsigned int i = 0; i < params->index_bytes; i++) {
        idx = (idx << 8) | sm[i];
    }
    return idx;
}


/*
 * DeltaEncode (Algorithm 1 of the paper) — sender.
 *
 * `sm` is the freshly produced signature for leaf idx+1; `idx` is the
 * previous leaf index (the paper's encoder extracts idx+1 from the
 * signature and subtracts 1). The authentication paths of idx and
 * idx+1 differ exactly in levels 0..nu(idx), so only those nu(idx)+1
 * nodes of A_{idx+1} are copied into `delta`.
 *
 * Output: `delta` holds (nu+1)*n bytes and *delta_len is set accordingly.
 * Transmission cost is therefore 32*(nu(idx)+1) bytes for n = 32,
 * versus tree_height*n bytes (320 for h' = 10) for the full path.
 */
void delta_encode(const xmss_params *params, unsigned char *delta, 
                  unsigned int *delta_len, const unsigned char *sm, uint32_t idx)
{
    unsigned int v = delta_nu(idx);
    const unsigned char *auth = delta_get_auth_path(params, sm);

    for (unsigned int j = 0; j <= v; j++) {
        memcpy(delta + j * params->n, auth + j * params->n, params->n);
    }
    *delta_len = (v + 1) * params->n;
}


/*
 * DeltaDecode (Algorithm 2 of the paper) — receiver.
 *
 * `cache` holds the full authentication path A_idx of the previous
 * index (tree_height * n bytes, fixed size). Overwriting levels
 * 0..nu(idx) with the received delta yields exactly A_{idx+1}: all
 * levels above nu(idx) are unchanged between consecutive indices
 * (correctness proven by induction in Lemma 1).
 */
void delta_decode(const xmss_params *params, unsigned char *cache, 
                  const unsigned char *delta, uint32_t idx)
{
    unsigned int v = delta_nu(idx);

    for (unsigned int j = 0; j <= v; j++) {
        memcpy(cache + j * params->n, delta + j * params->n, params->n);
    }
}