
#define POLYV_USE_ENCRYPTION
#define POLYV_IMPLEMENTATION
#include <polyv.hpp>

#include <time.h> // time()

namespace polyv::hidden {
    
/// Main entry point of the malware 
int POLYV_ENCRYPTED payload(int argc, char* argv[]) {
    printf("Hello, Hidden!\n");
    return 0;
}

} // namespace polyv::hidden 

int main(int argc, char* argv[]) {

    polyv::keybyte key[POLYV_KEY_SIZE];
    
    // Simulate an igniter
    {
        srand(time(0));
        for(size_t i = 0; i < POLYV_KEY_SIZE; i++)
            key[i] = 0xFF & (i ^ rand());

        polyv::loader::sxor(key, POLYV_KEY_SIZE);
    }

    printf("Key:");
    for(size_t i = 0; i < POLYV_KEY_SIZE; i++) {
        if (i % 16 == 0) printf("\n\t");
        printf("%2x ", key[i]);
    }
    printf("\n\n");

    // Decrypt and launch payload
    {
        polyv::loader::sxor_lock lock(key, POLYV_KEY_SIZE);
        polyv::hidden::payload(argc, argv);
    }

    return 0;
}