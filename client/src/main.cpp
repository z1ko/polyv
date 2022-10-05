
#define POLYV_USE_ENCRYPTED_SECTION
#define POLYV_IMPLEMENTATION
#include <polyv.h>

#include <time.h> // time()

/// Main entry point of the malware 
int POLYV_ENCRYPTED payload(int argc, char* argv[]) {
    printf("Hello, Hidden!\n");

    

    return 0;
}

int main(int argc, char* argv[]) {

    printf("Key (hex):");
    for(size_t i = 0; i < POLYV_KEY_SIZE; i++) {
        if (i % 32 == 0) printf("\n\t");
        printf("%02x ", ((unsigned char*)polyv_symmetric_key)[i]);
    }
    printf("\n");

    // Decrypt and launch payload
    {
        // If the program has not been ignited then the key is all zero 
        // and encrypting/decrypting does nothing!
        polyv_self_sxor(polyv_symmetric_key, POLYV_KEY_SIZE);
        payload(argc, argv);
        polyv_self_sxor(polyv_symmetric_key, POLYV_KEY_SIZE);
    }

    // This should crash
    payload(argc, argv);
    return 0;
}