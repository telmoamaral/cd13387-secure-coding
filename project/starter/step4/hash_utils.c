#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <time.h>

#define SALT_LENGTH 2
#define MAX_PASSWORD_LENGTH 50

// Function to convert bytes to a hexadecimal string
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// Function to hash password with SHA-256
void hash_password(const char* password, const unsigned char* salt, char* hashed_password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Make buffer for salted password long enough for longest password and salt
    char salted_password[MAX_PASSWORD_LENGTH + SALT_LENGTH];

    // Prepend the salt to the password
    memcpy(salted_password, salt, SALT_LENGTH);

    // Append password to the salt using a safe function and null termination
    strncpy(salted_password + SALT_LENGTH, password, sizeof(password) - 1);
    salted_password[SALT_LENGTH + sizeof(password) - 1] = '\0';

    // Hash the salted password
    SHA256((unsigned char*)salted_password, strlen(salted_password), hash);

    // Convert the hash to a hexadecimal string
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, hashed_password);
}

void generate_salt(unsigned char* salt, size_t length) {
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }

    for (size_t i = 0; i < length; i++) {
        salt[i] = (unsigned char)(rand() % 256);
    }
}
