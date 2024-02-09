//
// Created by hj on 2/9/24.
//
#include "aes256_cbc.h"

void aes256_cbc::encrypt(const vector<uint8_t> &key, const vector<uint8_t> &message, vector<uint8_t> &output) const {
    output.resize(message.size() * AES_BLOCK_SIZE);
    int inlen = message.size();
    int outlen = 0;
    size_t total_out = 0;

    EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
    throw_if_error(1, __FILE__, __LINE__);


    const vector<uint8_t> enc_key = key;

    int res;
    res = EVP_EncryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), m_iv.data());
    throw_if_error(res, __FILE__, __LINE__);
    res = EVP_EncryptUpdate(ctx.get(), output.data(), &outlen, message.data(), inlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;
    res = EVP_EncryptFinal(ctx.get(), output.data()+total_out, &outlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;

    output.resize(total_out);
}


void aes256_cbc::decrypt(const vector<uint8_t> &key, const vector<uint8_t> &message, vector<uint8_t> &output) const {
    output.resize(message.size() * 3);
    int outlen, inlen = 0;
    int res;
    size_t total_out = 0;
    vector<uint8_t> target_message;
    vector<uint8_t> iv;

    EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
    throw_if_error();


    const vector<uint8_t> enc_key = key;


    iv = m_iv;
    target_message = message;

    inlen = target_message.size();

    res = EVP_DecryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), iv.data());
    throw_if_error(res, __FILE__, __LINE__);
    res = EVP_DecryptUpdate(ctx.get(), output.data(), &outlen, target_message.data(), inlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;
    res = EVP_DecryptFinal(ctx.get(), output.data()+outlen, &outlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;

    output.resize(total_out);
}

