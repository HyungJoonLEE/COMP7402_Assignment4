#include "Brainpool.h"

int main(int argc, char *argv[]) {
    size_t alice_secret_len, bob_secret_len;

    auto *alice = new Brainpool("Alice");
    auto *bob = new Brainpool("Bob");

    // generate private, public key
    alice->generateKeys();
    bob->generateKeys();

    // shared secret key: exchange their public keys
    alice->exchangePublicKey(bob, alice_secret_len);
    bob->exchangePublicKey(alice, bob_secret_len);
    assert(alice_secret_len == bob_secret_len);


    for (int i = 0; i < alice_secret_len; i++) {
        assert(alice->getSecret()[i] == bob->getSecret()[i]);

    }


    EC_KEY_free(alice->getPrivateKey());
    EC_KEY_free(bob->getPrivateKey());
    OPENSSL_free(alice->getSecret());
    OPENSSL_free(bob->getSecret());

    delete(alice);
    delete(bob);
    return 0;
}