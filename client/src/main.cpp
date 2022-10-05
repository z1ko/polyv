
#define POLYV_USE_ENCRYPTED_SECTION
#define POLYV_IMPLEMENTATION
#include <polyv.h>

#include <dirent.h>

/// Main entry point of the malware 
int POLYV_ENCRYPTED payload(int argc, char* argv[]) {
    printf("Hello, Hidden!\n");

    DIR *dir;
    if (!(dir = opendir(".")))
        return -1;

    char path[1024];
    struct dirent* entry;

    printf("Directories:\n");
    while((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR)
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
        
        printf("  %s\n", entry->d_name);
    }

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
    //payload(argc, argv);
    
    return 0;
}