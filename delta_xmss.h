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