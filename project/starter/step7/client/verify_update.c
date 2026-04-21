#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define ROOT_CA_CERTIFICATE "rootCA.crt"
#define CERTIFICATE "software_update.crt"
#define SIGNATURE "software_update.sig"
#define DATA "software_update.bin"
#define CHECKSUM "software_update.checksum"
#define BUF_SIZE 4096

// Function to verify that a certificate is signed by a root certificate
int verify_certificate(const char* cert_fn, const char* root_cert_fn) {
    OpenSSL_add_all_algorithms();

    // Load certificate to verify
    FILE *fp_cert = fopen(cert_fn, "r");
    if (!fp_cert) {
        printf("Failed to open %s.\n", cert_fn);
        return 1;
    }
    X509 *cert = PEM_read_X509(fp_cert, NULL, NULL, NULL);
    fclose(fp_cert);

    // Load root certificate
    FILE *fp_root_cert = fopen(root_cert_fn, "r");
    if (!fp_root_cert) {
        printf("Failed to open %s.\n", root_cert_fn);
        return 1;
    }
    X509 *root_cert = PEM_read_X509(fp_root_cert, NULL, NULL, NULL);
    fclose(fp_root_cert);

    // Create trust store and add root certificate
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, root_cert);

    // Create verification context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    // Verify
    int ret = X509_verify_cert(ctx);

    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(root_cert);

    if (ret == 1) {
        printf("Successfully verified that %s is signed by %s.\n",
            cert_fn, root_cert_fn);
        return 0;    
    }    
    else {
        int err = X509_STORE_CTX_get_error(ctx);
        printf("Error: could not verify that %s is signed by %s: %s\n",
            cert_fn, root_cert_fn, X509_verify_cert_error_string(err));
        return 1;
    }    
}

// Function to verify the digital signature of some data using a certificate
int verify_signature(const char* sign_fn, const char* data_fn, const char* cert_fn) {
    // Load certificate
    FILE *fp_cert = fopen(cert_fn, "r");
    if (!fp_cert) {
        printf("Failed to open %s.\n", cert_fn);
        return 1;
    }
    X509 *cert = PEM_read_X509(fp_cert, NULL, NULL, NULL);
    fclose(fp_cert);

    // Extract public key
    EVP_PKEY *public_key = X509_get_pubkey(cert);

    // Read signature
    FILE *fp_sign = fopen(sign_fn, "rb");
    if (!fp_sign) {
        printf("Failed to open %s.\n", sign_fn);
        return 1;
    }
    fseek(fp_sign, 0, SEEK_END);
    long sign_len = ftell(fp_sign);
    rewind(fp_sign);
    unsigned char *sign = malloc(sign_len);
    fread(sign, 1, sign_len, fp_sign);
    fclose(fp_sign);

    // Read original data
    FILE *fp_data = fopen(data_fn, "rb");
    if (!fp_data) {
        printf("Failed to open %s.\n", data_fn);
        return 1;
    }
    fseek(fp_data, 0, SEEK_END);
    long data_len = ftell(fp_data);
    rewind(fp_data);
    unsigned char *data = malloc(data_len);
    fread(data, 1, data_len, fp_data);
    fclose(fp_data);

    // Create verification context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    // Initialize verification
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key);

    // Feed data
    EVP_DigestVerifyUpdate(ctx, data, data_len);

    // Verify signature
    int ret = EVP_DigestVerifyFinal(ctx, sign, sign_len);

    // Cleanup
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    X509_free(cert);
    free(sign);
    free(data);

    if (ret == 1) {
        printf("Successfully verified %s of %s using %s.\n",
            sign_fn, data_fn, cert_fn);
        return 0;
    }
    else if (ret != 1) {
        printf("Error: could not verify %s of %s using %s.\n",
            sign_fn, data_fn, cert_fn);
        return 1;
    }
}

// Function to verify that a given checksum matches the checksum of some data
int verify_checksum(const char* checksum_fn, const char* data_fn) {
    // Open data
    FILE *fp_data = fopen(data_fn, "rb");
    if (!fp_data) {
        printf("Failed to open %s.\n", data_fn);
        return 1;
    }

    // Create verification context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    // Create data buffer
    unsigned char buffer[BUF_SIZE];
    size_t len;

    // Load data
    while ((len = fread(buffer, 1, BUF_SIZE, fp_data)) > 0) {
        EVP_DigestUpdate(ctx, buffer, len);
    }

    fclose(fp_data);

    // Compute checksum
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    // Convert computed checksum to hexadecimal
    char computed_hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(&computed_hex[i * 2], "%02x", digest[i]);
    }
    computed_hex[digest_len * 2] = '\0';

    // Read expected checksum in hexadecimal
    FILE *fp_checksum = fopen(checksum_fn, "r");
    if (!fp_checksum) {
        printf("Failed to open %s.\n", checksum_fn);
        return 1;
    }    
    char expected_hex[EVP_MAX_MD_SIZE * 2 + 1];
    fscanf(fp_checksum, "%s", expected_hex);
    fclose(fp_checksum);

    // Compare computed checksum with expected checksum
    if (strcmp(expected_hex, computed_hex) == 0) {
        printf("Successfully verified that checksum of %s matches %s.\n",
            data_fn, checksum_fn);
        return 0;
    }
    else {
        printf("Error: could not verify that checksum of %s matches %s.\n",
            data_fn, checksum_fn);
        return 1;
    }
}

int main() {
    if (verify_certificate(CERTIFICATE, ROOT_CA_CERTIFICATE) != 0) {
        return 1;
    }

    if (verify_signature(SIGNATURE, DATA, CERTIFICATE) != 0) {
        return 1;
    }

    if (verify_checksum(CHECKSUM, DATA) != 0) {
        return 1;
    }

    printf("All verifications were successful.\n");
    return 0;
}
