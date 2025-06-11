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

/* Default factory pairing keys for engineering samples
        (to be replaced with project keys)*/
static byte g_pkey_index =  PAIRING_KEY_SLOT_INDEX_0;
static byte g_sh0priv[] = {0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,
                            0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,
                            0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,
                            0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b};

static byte g_sh0pub[]  = {0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,
                            0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,
                            0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,
                            0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54};


/* Empty keys / IV and test messages */

static byte aes_key[WC_AES_BLOCK_SIZE] = {0};
static byte iv[WC_AES_BLOCK_SIZE] = {0};

/* Example message to encrypt */
static byte msg[WC_AES_BLOCK_SIZE] = {0x01, 0x02, 0x03, 0x04,
                                0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C,
                                0x0D, 0x0E, 0x0F, 0x10};
/* Buffer for ciphertext */
static byte cipher[WC_AES_BLOCK_SIZE];
/* Buffer for decrypted plaintext */
byte plain[WC_AES_BLOCK_SIZE];
static byte output[RNG_SIZE];

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
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key); /* Need to verify */
    if (ret != 0) {
        printf("ERROR: wc_ed25519_make_key failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("\033[32m✓ Ed25519 key pair generated successfully\033[0m\n");

    /* Export public key for display */
    ret = wc_ed25519_export_public(&key, pubKey, &pubKeyLen);
    if (ret != 0) {
        printf(
            "WARNING: Could not export public key for display (code %d)\n",
            ret);
    } else {
        print_hex_buffer("Generated Public Key", pubKey, pubKeyLen);
    }

    /* Clean up */
    wc_ed25519_free(&key);
    printf("\033[32m✓ Ed25519 key generation test completed successfully\033[0m\n");

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

    /* Generate test message */
    ret = wc_RNG_GenerateBlock(rng, message, TEST_MESSAGE_SIZE);
    if (ret != 0) {
        printf("ERROR: Failed to generate test message with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    print_hex_buffer("Test Message", message, TEST_MESSAGE_SIZE);

    /* Sign the message */

    ret = wc_ed25519_sign_msg(message,
                              TEST_MESSAGE_SIZE,
                              signature,
                              &sigLen,
                              &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_sign_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    printf("\033[32m✓ Message signed successfully\033[0m\n");
    printf("Signature length: %d bytes\n", sigLen);
    print_hex_buffer("Generated Signature", signature, sigLen);

    /* Clean up */
    wc_ed25519_free(&key);
    printf("\033[32m✓ Ed25519 message signing test completed successfully\033[0m\n");

    return 0;
}

/**
 * Test Ed25519 signature verification functionality
 */
int test_ed25519_verify_message(WC_RNG* rng)
{
    int ret;
    ed25519_key key;
    byte message[TEST_MESSAGE_SIZE] = "This is a test message for Ed25519 signing and verification.";
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

    key.devId = WOLF_TROPIC01_DEVID;
    printf("DEV_ID: %d\n", key.devId);
    /* Generate and sign test message */

    ret = wc_RNG_GenerateBlock(rng, message, TEST_MESSAGE_SIZE);
    if (ret != 0) {
        printf("ERROR: Failed to generate test message with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }

    ret = wc_ed25519_sign_msg(message,
                             32,
                             signature,
                             &sigLen,
                             &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_sign_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }
    wc_ed25519_free(&key);
    printf("\033[32m✓ Test message signed for verification\033[0m\n");

    /* Test 1: Verify valid signature */
     ret = wc_ed25519_init(&key);
    key.devId = WOLF_TROPIC01_DEVID;
    if (ret != 0) {
        printf("ERROR: wc_ed25519_init failed with code %d\n", ret);
        return ret;
    }
    ret = wc_ed25519_verify_msg(signature,
                                sigLen,
                                message,
                                32,
                                &verify_result,
                                &key);
    if (ret != 0) {
        printf("ERROR: wc_ed25519_verify_msg failed with code %d\n", ret);
        wc_ed25519_free(&key);
        return ret;
    }

    if (verify_result == 1) {
        printf("\033[32m✓ Valid signature verification PASSED\033[0m\n");
    } else {
        printf("ERROR: Valid signature verification FAILED\n");
        wc_ed25519_free(&key);
        return -1;
    }

    /* Test 2: Verify tampered message (should fail) */
    printf("\n=== Ed25519 Signature Verification Tampered Test ===\n");

    memcpy(tampered_message, message, TEST_MESSAGE_SIZE);
    tampered_message[0] ^= 0x01; /* Flip one bit */

    verify_result = 0;
    ret = wc_ed25519_verify_msg(signature,
                                sigLen,
                                tampered_message,
                                TEST_MESSAGE_SIZE,
                                &verify_result,
                                &key);

    if (verify_result == 0) {
        printf("\033[32m✓ Tampered verification correctly FAILED\033[0\n");
    } else {
        printf("ERROR: Tampered message verification unexpectedly PASSED\n");
        wc_ed25519_free(&key);
        return -1;
    }

    /* Clean up */
    wc_ed25519_free(&key);
    printf("\033[32m✓ Ed25519 verification completed successfully\033[0m\n");

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
    Aes aes_enc[1];
    Aes aes_dec[1];

    printf("TROPIC01 Crypto Callbacks for WolfSSL - Test Application\n");
    printf("=========================================================\n");

    wolfSSL_Debugging_ON();

    ret = Tropic01_SetPairingKeys(g_pkey_index, g_sh0pub, g_sh0priv);
    if (ret != 0) {
        printf("Failed to set pairing keys: %d\n", ret);
        return EXIT_FAILURE;
    }
    /* wolfCrypt initialization */
    if ((ret = wolfCrypt_Init()) != 0) {
        char error_msg[80];
        wc_ErrorString(ret, error_msg);
        printf("wolfCrypt_Init failed: %s (code %d)\n", error_msg, ret);
        return EXIT_FAILURE;
    }
    printf("wolfCrypt initialized successfully\n");

    /* Register TROPIC01 crypto callback */

    printf("Registering crypto callback with device ID %06X...\n",
           WOLF_TROPIC01_DEVID);
    ret = wc_CryptoCb_RegisterDevice(WOLF_TROPIC01_DEVID,
                                     Tropic01_CryptoCb,
                                     NULL);
    if (ret != 0) {
        printf("Failed to register crypto callback: %d\n", ret);
        return EXIT_FAILURE;
    }
    printf("Crypto callback registered successfully\n");

    /* Initialize RNG */
    if ((ret = wc_InitRng_ex(&rng, NULL, WOLF_TROPIC01_DEVID)) != 0) {
        printf("RNG initialization failed: %d\n", ret);
        return EXIT_FAILURE;
    }


    if ((ret = wc_RNG_GenerateBlock(&rng, output, RNG_SIZE)) != 0) {
        printf("RNG generation failed: %d\n", ret);
        wc_FreeRng(&rng);
        return EXIT_FAILURE;
    }

    printf("Generated %d random bytes:\n", RNG_SIZE);
    for (int i = 0; i < RNG_SIZE; i++) {
        printf("%02X", output[i]);
        if ((i+1) % 16 == 0) printf("\n");
        else if ((i+1) % 4 == 0) printf(" ");
    }
    printf("\n\033[32mRNG test completed successfully\033[0m\n");
    printf("\nAES test starting:\n");
    ret = wc_AesInit(aes_enc, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        /*Set empty keys - real keys are retrieved from TROPIC01*/
        ret = wc_AesSetKey(aes_enc, (byte*)aes_key,
                WC_AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes_enc, cipher, msg, WC_AES_BLOCK_SIZE);
        }
        wc_AesFree(aes_enc);
    }
    if (ret != 0) {
        printf("AES encryption failed: %d\n", ret);
        wc_FreeRng(&rng);
        return EXIT_FAILURE;
    }
    printf("Plain message:\n");
    for (int i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        printf("%02X ", msg[i]);
    }
    printf("\nEncrypted message:\n");
    for (int i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        printf("%02X ", cipher[i]);
    }
    printf("\nTrying to decrypt...\n");
    ret = wc_AesInit(aes_dec, NULL, WOLF_TROPIC01_DEVID);

    if (ret == 0) {
        /*Set empty keys - real keys are retrieved from TROPIC01*/
        ret = wc_AesSetKey(aes_dec, (byte*)aes_key,
                WC_AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(aes_dec, plain, cipher, WC_AES_BLOCK_SIZE);
        }
        wc_AesFree(aes_dec);
    }
    if (ret != 0) {
        printf("AES decryption failed: %d\n", ret);
        wc_FreeRng(&rng);
        return EXIT_FAILURE;
    }
    printf("Decrypted message:\n");
    for (int i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        printf("%02X ", plain[i]);
    }
    printf("\n\033[32mAES test completed successfully\033[0m\n");


    /* Run Ed25519 Tests */
    printf("\nED25519 TESTING SUITE\n");

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
        printf("Ed25519 verification test FAILED with code %d\n", ret);
        wc_FreeRng(&rng);
        wolfCrypt_Cleanup();
        return EXIT_FAILURE;
    }

    printf("\033[32m\n🎉 ALL ED25519 TESTS PASSED SUCCESSFULLY! 🎉\033[0m\n");


    // Cleanup
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return EXIT_SUCCESS;
}
