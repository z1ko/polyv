#pragma once

#include <stddef.h>     // size_t
#include <elf.h>        // Elf64_Ehdr, Elf64_Shdr, ...

/// Name of the encrypted .text section
#define POLYV_ENCRYPTED_SECTION ".etext"
/// Name of the decryptiong key section
#define POLYV_KEY_SECTION ".ekey"

/// All functions with this attribute will be encrypted,
/// they become callable only after decrypting the .encrypted section
#ifdef POLYV_USE_ENCRYPTED_SECTION
    #define POLYV_ENCRYPTED __attribute__ ((section (POLYV_ENCRYPTED_SECTION)))
#else
    #define POLYV_ENCRYPTED
#endif

/// All functions with this attribute are part of the attack surface because
/// they cannot be encrypted
#define POLYV_LOADER

/// Attribute used to place the key in its separate section,
/// this allows to easy changes to its value
#define POLYV_KEY __attribute__ ((section (POLYV_KEY_SECTION)))

/// Size of the symmetric encryption/decryption key
#define POLYV_KEY_SIZE 256

/// Key used for the decryption
extern POLYV_KEY char polyv_symmetric_key[POLYV_KEY_SIZE];

/// Comodity data for handling an open elf file  
typedef struct
{
    size_t size;
    char* bytes;

    Elf64_Ehdr* header;
    Elf64_Shdr* sections;
    const char* shstrtab;
    
} elf64;

/// Apply symmetric xor to the memory region with the provided key
void POLYV_LOADER polyv_sxor(char* memory, size_t size, char* key, size_t key_size); 

#ifdef POLYV_USE_ENCRYPTED_SECTION

/// Apply symmetric xor with the provided key on the .encrypt section
void POLYV_LOADER polyv_self_sxor(char* key, size_t key_size);

#endif

/// Maps an ELF file to memory given its filepath
bool POLYV_ENCRYPTED polyv_load_elf64(elf64* elf, const char* filepath);
/// Unmaps an ELF file 
void POLYV_ENCRYPTED polyv_unload_elf64(const elf64* elf);

/// Mutate an ELF file by sxoring its encrypted section if present and saving the used key
/// If the key is NULL the a new one will be generated using /dev/random
int POLYV_ENCRYPTED polyv_mutate_elf64(const char* filename, char* key, size_t key_size);

/// Rounds up n to the next page aligned value 
size_t POLYV_ENCRYPTED polyv_page_align(size_t n, size_t page_size);
/// Retrive the header of a section given its name 
const Elf64_Shdr* POLYV_ENCRYPTED polyv_lookup_section(const elf64* elf, const char* name);

// =============================================================================================
// =============================================================================================

#ifdef POLYV_IMPLEMENTATION

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

POLYV_KEY char polyv_symmetric_key[POLYV_KEY_SIZE];

void POLYV_LOADER polyv_sxor(char* memory, size_t size, char* key, size_t key_size) {
    size_t key_i = 0;
    for(size_t i = 0; i < size; i++, key_i = (key_i + 1) % key_size)
        memory[i] = memory[i] ^ key[key_i];
}

#ifdef POLYV_USE_ENCRYPTED_SECTION

// Linker symbols used to locate the payload section
extern char __load_start_etext, __load_stop_etext;

void POLYV_LOADER polyv_self_sxor(char* key, size_t key_size) {

    size_t section_beg = (size_t)&__load_start_etext;
    size_t section_end = (size_t)&__load_stop_etext;

    const size_t page_size = getpagesize();
    const size_t section_delta = section_end - section_beg;
    size_t section_size = section_delta;

    if (section_size % page_size != 0)
        section_size = section_delta + (section_delta % page_size);

    // Enable writing of the section
    void* section_page = (void*)(section_beg - (section_beg % page_size));
    mprotect(section_page, section_size, PROT_EXEC | PROT_WRITE | PROT_READ);

    // Apply symmetric XOR with provided key
    char* section = (char*)(section_beg);
    polyv_sxor(section, section_delta, key, key_size);

    // Disable writing of the section
    mprotect(section_page, section_size, PROT_EXEC | PROT_READ);
}

#endif

bool POLYV_ENCRYPTED polyv_load_elf64(elf64* elf, const char* filepath) {

    // Load file
    int fd = open(filepath, O_RDWR);
    if (fd <= 0)
        return false;

    struct stat sb;
    if (fstat(fd, &sb) < 0) 
        return false;

    // Map file to memory for read and write
    char* elf_base = (char*)mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_base == MAP_FAILED) return false;
    close(fd);

    elf->size  = sb.st_size;
    elf->bytes = elf_base;

    elf->header   = (Elf64_Ehdr*)(elf_base);
    elf->sections = (Elf64_Shdr*)(elf_base + elf->header->e_shoff);
    elf->shstrtab = (const char*)(elf_base + elf->sections[elf->header->e_shstrndx].sh_offset);

    return true;
}
 
void POLYV_ENCRYPTED polyv_unload_elf64(const elf64* elf) {
    munmap(elf->bytes, elf->size);
}

int POLYV_ENCRYPTED polyv_mutate_elf64(const char* filename, char* key, size_t key_size) {

    elf64 elf;
    if (!polyv_load_elf64(&elf, filename)) 
        return -1;

    // Returns encrypted sections if its present
    const Elf64_Shdr* etext_header = polyv_lookup_section(&elf, POLYV_ENCRYPTED_SECTION);
    const Elf64_Shdr* ekey_header  = polyv_lookup_section(&elf, POLYV_KEY_SECTION);
    if (etext_header == NULL || ekey_header == NULL) 
        return -2;

    char* etext = (char*)(elf.bytes + etext_header->sh_offset);
    char* ekey  = (char*)(elf.bytes + ekey_header->sh_offset);

    // Apply first sxor with old stored key to remove encryption
    polyv_sxor(etext, etext_header->sh_size, ekey, POLYV_KEY_SIZE);

    // Generate new key if it was not provided
    char nkey[POLYV_KEY_SIZE];
    if (key == NULL) {

        ssize_t bytes = 0;
        while(bytes != POLYV_KEY_SIZE) {
            ssize_t res = getrandom((void*)nkey, POLYV_KEY_SIZE, 0);
            if (res == -1) return -3;
            bytes += res;
        }

        key = nkey;
    }

#if 1
    // Remove all zeros and ones from the key to help against degradation
    for (size_t i = 0; i < POLYV_KEY_SIZE; i++)
        if (nkey[i] == 0x00 || nkey[i] == 0xFF)
            nkey[i] = 0xAA;
#endif

    /// Apply second sxor with the new key and store it
    polyv_sxor(etext, etext_header->sh_size, nkey, POLYV_KEY_SIZE);
    memcpy(ekey, nkey, POLYV_KEY_SIZE);

    polyv_unload_elf64(&elf);
    return 0;
}

size_t POLYV_ENCRYPTED polyv_page_align(size_t n, size_t page_size) {
    return (n + (page_size - 1)) & ~(page_size - 1);
}

const Elf64_Shdr* POLYV_ENCRYPTED polyv_lookup_section(const elf64* elf, const char* name) {
    for (Elf64_Half i = 0; i < elf->header->e_shnum; i++) {
        const char* section_name = elf->shstrtab + elf->sections[i].sh_name;
        if (strcmp(name, section_name) == 0)
            if (elf->sections[i].sh_size != 0)
                return elf->sections + i;
    }
    return NULL;
}

#endif