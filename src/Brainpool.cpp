#include "Brainpool.h"

void Brainpool::createKey() {
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1))) {
        printf("Failed to create key curve\n");
        return;
    }

    if (1 != EC_KEY_generate_key(key)) {
        printf("Failed to generate key\n");
        return;
    }
}


void Brainpool::setPublicKey() {
    public_key = EC_KEY_get0_public_key(key);
}


void Brainpool::setSecret(EC_KEY *key, const EC_POINT *peer_pub_key,
                                     size_t *secret_len) {
    int field_size;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    *secret_len = (field_size + 7) / 8;

    if (nullptr == (secret = (unsigned char *)OPENSSL_malloc(*secret_len))) {
        printf("Failed to allocate memory for secret");
        return;
    }

    *secret_len = ECDH_compute_key(secret, *secret_len,
                                   peer_pub_key, key, NULL);

    if (*secret_len <= 0) {
        OPENSSL_free(secret);
        return;
    }
}


EC_KEY* Brainpool::getKey() {
    return key;
}


const EC_POINT *Brainpool::getPublicKey() {
    return public_key;
}


unsigned char *Brainpool::getSecret() {
    return secret;
}
