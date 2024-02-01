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

    thread alice_thread(&Brainpool::aliceThread, alice);
    thread bob_thread(&Brainpool::bobThread, bob);
    alice_thread.join();
    bob_thread.join();

//    const std::string iv = "1234567890123456";
//    const std::string message = "hello world";
//    // 32 bytes (256 bits key)
//    std::vector<uint8_t> key(alice->getSecret(), alice->getSecret() + 32);
//
//
//    const aes256_cbc encryptor(str_to_bytes(iv));
//    std::vector<uint8_t> enc_result;
//    encryptor.encrypt(key, str_to_bytes(message), enc_result);
//
//    std::vector<uint8_t> dec_result;
//    encryptor.decrypt(key, enc_result, dec_result);
//
//    std::cout << bytes_to_str(dec_result) << std::endl;
    // output: hello world



    freeKeys(alice);
    freeKeys(bob);

    delete(alice);
    delete(bob);
    return 0;
}