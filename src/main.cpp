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
    assertSharedSecretKey(alice, bob, alice_secret_len, bob_secret_len);

    // print each keys
    alice->printKeys();
    bob->printKeys();

    thread alice_thread(, &bob)
    thread bob_thread(, &bob)






    freeKeys(alice);
    freeKeys(bob);

    delete(alice);
    delete(bob);
    return 0;
}