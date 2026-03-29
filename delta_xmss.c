#include <string.h>
#include <stdint.h>
#include "delta_xmss.h"
#include "params.h"

unsigned int delta_nu(uint32_t idx)
{
    unsigned int count = 0;

    while (idx & 1) {
        idx >>= 1;
        count++;
    }
    return count;
}

const unsigned char *delta_get_auth_path(const xmss_params *params, const unsigned char *sm)
{
    return sm + params->index_bytes + params->n + params->wots_sig_bytes;
}

uint32_t delta_get_idx(const xmss_params *params, const unsigned char *sm)
{
    uint32_t idx = 0;

    for (unsigned int i = 0; i < params->index_bytes; i++) {
        idx = (idx << 8) | sm[i];
    }
    return idx;
}

// Take the node inside sm and copy it to delta 
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


// Pass the nodes that differ into the path stored in cache 
void delta_decode(const xmss_params *params, unsigned char *cache, 
                  const unsigned char *delta, uint32_t idx)
{
    unsigned int v = delta_nu(idx);

    for (unsigned int j = 0; j <= v; j++) {
        memcpy(cache + j * params->n, delta + j * params->n, params->n);
    }
}