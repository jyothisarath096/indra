#define main reyzin_reference_original_main
#include "ed25519.cpp"
#undef main

#include <iostream>
#include <sstream>
#include <string>

static str from_token(const std::string &token) {
    return token == "-" ? str() : str(token.c_str());
}

static std::string hex_string(const str &value) {
    char *encoded = value.toHexString();
    std::string result(encoded);
    delete[] encoded;
    return result;
}

static bool proof_to_hash_checked(const str &proof, str &beta) {
    if (proof.len != 80) return false;
    bool valid = false;
    pointEd25519 gamma = proof.slice(0, 32).toECPoint(valid);
    if (!valid) return false;
    const str suite_string(static_cast<unsigned char>(4));
    beta = (suite_string || '\3' || str(gamma * cofactor) || '\0').hash();
    return true;
}

int main() {
    initialize();
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        std::string command;
        input >> command;
        if (command == "prove") {
            std::string seed_hex, alpha_hex;
            input >> seed_hex >> alpha_hex;
            str seed(seed_hex.c_str());
            str alpha = from_token(alpha_hex);
            str public_key = EdDSA_KeyGen(seed);
            str proof = EdVRF_Prove(seed, alpha, true, false);
            str beta;
            if (!proof_to_hash_checked(proof, beta)) {
                std::cout << "ERR\n";
            } else {
                std::cout << "OK " << hex_string(public_key) << ' '
                          << hex_string(proof) << ' ' << hex_string(beta) << '\n';
            }
        } else if (command == "verify") {
            std::string pk_hex, alpha_hex, proof_hex, beta_hex;
            input >> pk_hex >> alpha_hex >> proof_hex >> beta_hex;
            str public_key(pk_hex.c_str());
            str alpha = from_token(alpha_hex);
            str proof(proof_hex.c_str());
            str expected_beta(beta_hex.c_str());
            str actual_beta;
            bool accepted = proof.len == 80 && public_key.len == 32 &&
                            expected_beta.len == 64 &&
                            EdVRF_Verify(proof, public_key, alpha, true) &&
                            proof_to_hash_checked(proof, actual_beta) &&
                            actual_beta.len == expected_beta.len &&
                            std::memcmp(actual_beta.s, expected_beta.s,
                                        actual_beta.len) == 0;
            std::cout << (accepted ? "ACCEPT" : "REJECT") << '\n';
        } else if (command == "proof_to_hash") {
            std::string proof_hex;
            input >> proof_hex;
            str proof(proof_hex.c_str());
            str beta;
            if (proof_to_hash_checked(proof, beta)) {
                std::cout << "OK " << hex_string(beta) << '\n';
            } else {
                std::cout << "ERR\n";
            }
        } else {
            std::cout << "ERR\n";
        }
        std::cout.flush();
    }
}
