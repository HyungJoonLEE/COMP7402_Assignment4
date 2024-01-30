#include "Brainpool.h"


Brainpool::Brainpool(string name) {
    _name = name;
    private_key = nullptr;
    public_key = nullptr;
    shared_secret_key = nullptr;
}


void Brainpool::generateKeys() {
    this->setPrivateKey();
    assert(this->getPrivateKey() != nullptr);

    this->setPublicKey();
    assert(this->getPublicKey() != nullptr);
}


void Brainpool::setPrivateKey() {
    if (NULL == (private_key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1))) {
        printf("Failed to create key curve\n");
        return;
    }

    // Creates a new ec private (and optional a new public) key.
    if (1 != EC_KEY_generate_key(private_key)) {
        printf("Failed to generate key\n");
        return;
    }
}


void Brainpool::setPublicKey() {
    public_key = EC_KEY_get0_public_key(private_key);
}


void Brainpool::setSecret(EC_KEY *key, const EC_POINT *peer_pub_key,
                                     size_t *secret_len) {
    int field_size;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    *secret_len = (field_size + 7) / 8;

    if (nullptr == (shared_secret_key = (unsigned char *)OPENSSL_malloc(*secret_len))) {
        printf("Failed to allocate memory for secret");
        return;
    }

    *secret_len = ECDH_compute_key(shared_secret_key, *secret_len,
                                   peer_pub_key, key, NULL);

    if (*secret_len <= 0) {
        OPENSSL_free(shared_secret_key);
        return;
    }
}


EC_KEY* Brainpool::getPrivateKey() {
    return private_key;
}


const EC_POINT *Brainpool::getPublicKey() {
    return public_key;
}


unsigned char *Brainpool::getSecret() {
    return shared_secret_key;
}


void Brainpool::printKeys() {
    cout.setf(ios::hex | ios::uppercase | ios::showbase);
    cout << _name  << endl;


    cout.unsetf(ios::hex | ios::uppercase | ios::showbase);
//    cout << "Private Key: " << private_key << endl;
//    cout << "Public  Key: " << public_key << endl;
//    cout << "Shared Secret Key: " << shared_secret_key << endl;
}


void Brainpool::exchangePublicKey(Brainpool* &bp, size_t &len) {
    setSecret(this->getPrivateKey(), bp->getPublicKey(), &len);
    assert(this->getSecret() != nullptr);
}

