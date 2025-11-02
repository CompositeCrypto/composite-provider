#include "composite_key.h"

COMPOSITE_KEY * COMPOSITE_KEY_new(void);

int COMPOSITE_KEY_keygen(COMPOSITE_KEY *key, const char * const algorithm) {
    return 0;
}


void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {
    return;
}

int COMPOSITE_KEY_get0_components(const COMPOSITE_KEY  * const key, 
                                 EVP_PKEY      ** const ml_dsa_key,
                                 EVP_PKEY      ** const trad_key) {
    return 0;
}


int COMPOSITE_KEY_set0_components(COMPOSITE_KEY * key, 
                                  EVP_PKEY      * ml_dsa_key,
                                  EVP_PKEY      * trad_key) {
    return 0;
}