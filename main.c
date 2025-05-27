#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define WOLFSSL_TROPIC01
#include <wolfssl/wolfcrypt/port/tropicsquare/tropic01.h>

#define RNG_SIZE 32  // 256-bit random output

// Ed25519 test constants
#define TEST_MESSAGE_SIZE 64
#define ED25519_KEY_SIZE 32
#define ED25519_SIG_SIZE 64

/* Function prototypes */
int test_ed25519_key_generation(WC_RNG* rng);
int test_ed25519_sign_message(WC_RNG* rng);
int test_ed25519_verify_message(WC_RNG* rng);
void print_hex_buffer(const char* label, const byte* buffer, word32 size);

/**
 * Test Ed25519 key generation functionality
 */
int test_ed25519_key_generation(WC_RNG* rng)
{
    int ret;
    ed25519_key key;
    byte pubKey[ED25519_KEY_SIZE];
    word32 pubKeyLen = ED25519_KEY_SIZE;
    
    printf("\n=== Ed25519 Key Generation Test ===\n");
    
    /* Initialize the Ed25519 key structure */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_init failed with code %d\n", ret);
        return ret;
    }
    printf("✓ Ed25519 key structure initialized successfully\n");
    
    /* Generate Ed25519 key pair */
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_make_key failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("✓ Ed25519 key pair generated successfully\n");
    
    /* Export public key for display */
    ret = wc_ed25519_export_public(&key, pubKey, &pubKeyLen);
    if (ret != 0) {
        printf("WARNING: Could not export public key for display (code %d)\n", ret);
    } else {
        print_hex_buffer("Generated Public Key", pubKey, pubKeyLen);
    }
    
    /* Clean up */
    wc_ed25519_free(&key);
    printf("✓ Ed25519 key generation test completed successfully\n");
    
    return 0;
}

/**
 * Test Ed25519 message signing functionality
 */
int test_ed25519_sign_message(WC_RNG* rng)
{
    int ret;
    ed25519_key key;
    byte message[TEST_MESSAGE_SIZE];
    byte signature[ED25519_SIG_SIZE];
    word32 sigLen = ED25519_SIG_SIZE;
    


    printf("\n=== Ed25519 Message Signing Test ===\n");
    
    /* Initialize key structure */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_init failed with code %d\n", ret);
        return ret;
    }
    key.devId = WOLF_TROPIC01_DEVID;
    printf("DEV_ID: %d\n", key.devId);
    /* Generate key pair */
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_make_key failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("✓ Key pair generated for signing test\n");
    printf("DEV_ID: %d\n", key.devId);
    /* Generate test message */
    ret = wc_RNG_GenerateBlock(rng, message, TEST_MESSAGE_SIZE);
    if (ret != 0) {
        printf("ERROR: Failed to generate test message with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    print_hex_buffer("Test Message", message, TEST_MESSAGE_SIZE);
    
    /* Sign the message */
    printf("DEV_ID: %d\n", key.devId);
    ret = wc_ed25519_sign_msg(message, TEST_MESSAGE_SIZE, signature, &sigLen, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_sign_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("✓ Message signed successfully\n");
    printf("Signature length: %d bytes\n", sigLen);
    print_hex_buffer("Generated Signature", signature, sigLen);
    
    /* Clean up */
    wc_ed25519_free(&key);
    printf("✓ Ed25519 message signing test completed successfully\n");
    
    return 0;
}

/**
 * Test Ed25519 signature verification functionality
 */
int test_ed25519_verify_message(WC_RNG* rng)
{
    int ret;
    ed25519_key key;
    byte message[TEST_MESSAGE_SIZE];
    byte signature[ED25519_SIG_SIZE];
    byte tampered_message[TEST_MESSAGE_SIZE];
    word32 sigLen = ED25519_SIG_SIZE;
    int verify_result = 0;
    
    printf("\n=== Ed25519 Signature Verification Test ===\n");
    
    /* Initialize key structure */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_init failed with code %d\n", ret);
        return ret;
    }
    
    /* Generate key pair */
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_make_key failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("✓ Key pair generated for verification test\n");
    
    /* Generate and sign test message */
    ret = wc_RNG_GenerateBlock(rng, message, TEST_MESSAGE_SIZE);
    if (ret != 0) {
        printf("ERROR: Failed to generate test message with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    
    ret = wc_ed25519_sign_msg(message, TEST_MESSAGE_SIZE, signature, &sigLen, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_sign_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("✓ Test message signed for verification\n");
    
    /* Test 1: Verify valid signature */
    ret = wc_ed25519_verify_msg(signature, sigLen, message, TEST_MESSAGE_SIZE, 
                                &verify_result, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_verify_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    
    if (verify_result == 1) {
        printf("✓ Valid signature verification PASSED\n");
    } else {
        printf("ERROR: Valid signature verification FAILED\n");
        wc_ed25519_free(&key);
        return -1;
    }
    
    /* Test 2: Verify tampered message (should fail) */
    memcpy(tampered_message, message, TEST_MESSAGE_SIZE);
    tampered_message[0] ^= 0x01; // Flip one bit
    
    verify_result = 0;
    ret = wc_ed25519_verify_msg(signature, sigLen, tampered_message, TEST_MESSAGE_SIZE, 
                                &verify_result, &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_verify_msg failed on tampered message with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    
    if (verify_result == 0) {
        printf("✓ Tampered message verification correctly FAILED\n");
    } else {
        printf("ERROR: Tampered message verification unexpectedly PASSED\n");
        wc_ed25519_free(&key);
        return -1;
    }
    
    /* Clean up */
    wc_ed25519_free(&key);
    printf("✓ Ed25519 signature verification test completed successfully\n");
    
    return 0;
}

/**
 * Helper function to print hexadecimal buffer contents
 */
void print_hex_buffer(const char* label, const byte* buffer, word32 size)
{
    printf("%s (%d bytes):\n", label, size);
    for (word32 i = 0; i < size; i++) {
        printf("%02X", buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        } else if ((i + 1) % 4 == 0) {
            printf(" ");
        }
    }
    if (size % 16 != 0) {
        printf("\n");
    }
}

int main(void)
{
    int ret;
    WC_RNG rng;
    Aes aes[1]; // Array to hold AES context
    byte aes_key[WC_AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 
                                        0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B,
                                        0x0C, 0x0D, 0x0E, 0x0F}; // Example AES key
    byte iv[WC_AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03,   
                                  0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B,
                                  0x0C, 0x0D, 0x0E, 0x0F}; // Example IV
    byte msg[WC_AES_BLOCK_SIZE] = {0x01, 0x02, 0x03, 0x04, 
                                    0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C,
                                    0x0D, 0x0E, 0x0F, 0x10}; // Example plaintext message
    byte cipher[WC_AES_BLOCK_SIZE]; // Buffer for ciphertext
    byte plain[WC_AES_BLOCK_SIZE]; // Buffer for decrypted plaintext
    byte output[RNG_SIZE];

    printf("wolfSSL Crypto Callback Test Application\n");
    printf("========================================\n");
    
    wolfSSL_Debugging_ON(); 
    
    /* wolfCrypt initialization */
    if ((ret = wolfCrypt_Init()) != 0) {
        char error_msg[80];
        wc_ErrorString(ret, error_msg);
        printf("wolfCrypt_Init failed: %s (code %d)\n", error_msg, ret);
        return EXIT_FAILURE;
    }
    printf("wolfCrypt initialized successfully\n");

    /* Register our crypto callback */
    printf("Registering crypto callback with device ID %d...\n", 
           WOLF_TROPIC01_DEVID);
    ret = wc_CryptoCb_RegisterDevice(WOLF_TROPIC01_DEVID, Tropic01_CryptoCb, NULL);
    if (ret != 0) {
        printf("Failed to register crypto callback: %d\n", ret);
        return EXIT_FAILURE;
    }
    printf("Crypto callback registered successfully\n");

    // Initialize RNG
    if ((ret = wc_InitRng_ex(&rng, NULL, WOLF_TROPIC01_DEVID)) != 0) {
        printf("RNG initialization failed: %d\n", ret);
        return EXIT_FAILURE;
    }

    // Generate random data
    if ((ret = wc_RNG_GenerateBlock(&rng, output, RNG_SIZE)) != 0) {
        printf("RNG generation failed: %d\n", ret);
        wc_FreeRng(&rng);
        return EXIT_FAILURE;
    }
    
    // Print generated bytes
    printf("Generated %d random bytes:\n", RNG_SIZE);
    for (int i = 0; i < RNG_SIZE; i++) {
        printf("%02X", output[i]);
        if ((i+1) % 16 == 0) printf("\n");
        else if ((i+1) % 4 == 0) printf(" ");
    }
    printf("\n");
    printf("RNG test completed successfully\n");

    
    printf("\nAES test starting:\n");
    ret = wc_AesInit(aes, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, (byte*)aes_key,
                WC_AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, cipher, msg, WC_AES_BLOCK_SIZE);
        }
        wc_AesFree(aes);
    }
    if (ret != 0) {
        printf("AES encryption failed: %d\n", ret);
        wc_FreeRng(&rng);
        return EXIT_FAILURE;
    }
    printf("AES test completed successfully\n");

    
    /* Run Ed25519 Tests */
    
    printf("\nED25519 COMPREHENSIVE TESTING SUITE\n");
    
    
     /* Test 1: Key Generation */
    
    ret = test_ed25519_key_generation(&rng);
    if (ret != 0) {
        printf("Ed25519 key generation test FAILED with code %d\n", ret);
        wc_FreeRng(&rng);
        wolfCrypt_Cleanup();
        return EXIT_FAILURE;
    }
    
    /* Test 2: Message Signing */
    ret = test_ed25519_sign_message(&rng);
    if (ret != 0) {
        printf("Ed25519 message signing test FAILED with code %d\n", ret);
        wc_FreeRng(&rng);
        wolfCrypt_Cleanup();
        return EXIT_FAILURE;
    }
    
    /* Test 3: Signature Verification */
    ret = test_ed25519_verify_message(&rng);
    if (ret != 0) {
        printf("Ed25519 signature verification test FAILED with code %d\n", ret);
        wc_FreeRng(&rng);
        wolfCrypt_Cleanup();
        return EXIT_FAILURE;
    }
    
    printf("\n🎉 ALL ED25519 TESTS PASSED SUCCESSFULLY! 🎉\n");


    // Cleanup
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();
    
    return EXIT_SUCCESS;
}
