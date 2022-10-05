#pragma once

#include <stddef.h>     // size_t
#include <elf.h>        // Elf64_Ehdr, Elf64_Shdr, ...

/// All functions with this attribute will be encrypted,
/// they become callable only after decrypting the .encrypted section
#ifdef POLYV_USE_ENCRYPTION
    #define POLYV_ENCRYPTED __attribute__ ((section (".encrypted")))
#else
    #define POLYV_ENCRYPTED
#endif

/// Attribute used to place the key in its separate section,
/// this allows to easy changes to its value
#define POLYV_KEY __attribute__ ((section (".key")))

/// Size of the symmetric encryption/decryption key
#define POLYV_KEY_SIZE 1024

// Basic ASM instructions
#define POLYV_MORPH_PUSRAX ".byte 0x50\n\t"             // push rax
#define POLYV_MORPH_PUSRBX ".byte 0x53\n\t"             // push rbx
#define POLYV_MORPH_POPRAX ".byte 0x58\n\t"             // pop rax
#define POLYV_MORPH_POPRBX ".byte 0x5B\n\t"             // pop rbx
#define POLYV_MORPH_REXNOP ".byte 0x48,0x87,0xc0\n\t"   // xchg rax,rax

/// Declares code section to be filled with random ASM junk
#define POLYV_MORPH_JUNK            \
__asm__ __volatile__ (              \
    POLYV_MORPH_PUSRBX              \
    POLYV_MORPH_PUSRAX              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_REXNOP              \
    POLYV_MORPH_POPRAX              \
    POLYV_MORPH_POPRBX              \
);

/// Contains generic data structures
namespace polyv {

using keybyte = unsigned char;
inline POLYV_KEY keybyte symmetric_key[POLYV_KEY_SIZE];

/// Comodity data for handling an open elf file  
struct elf64
{
    size_t size;
    void* bytes;

    Elf64_Ehdr* header;
    Elf64_Shdr* sections;
    const char* shstrtab;
};

} // namespace poly 

/// Contains all functions used to decrypt the encrypted section
namespace polyv::loader {
    
/// Apply symmetric xor with the provided key and the .encrypt section
void sxor(keybyte* key, size_t key_size);

/// RAII class implementing a scoped decryption/encryption
/// perturbating the provided key at the end of the scope
class sxor_lock {

    keybyte* _key;
    size_t _key_size;

public:
    sxor_lock();
    sxor_lock(keybyte* key, size_t key_size);
    virtual ~sxor_lock();
};

} // namespace polyv::loader 

/// Contains usefull hidden functions 
namespace polyv::hidden {

/// Maps an ELF file to memory given its filepath
const elf64* POLYV_ENCRYPTED load_elf64(const char* filepath);
/// Unmaps an ELF file 
void POLYV_ENCRYPTED unload_elf64(const elf64* elf);

/// Rounds up n to the next page aligned value 
size_t POLYV_ENCRYPTED page_align(size_t n, size_t page_size);
/// Retrive the header of a section given its name 
const Elf64_Shdr* POLYV_ENCRYPTED lookup_section(const elf64* elf, const char* name);

} // namespace polyv::hidden

#ifdef POLYV_IMPLEMENTATION

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

// Linker symbols used to locate the payload section
extern char __load_start_encrypted, __load_stop_encrypted;

namespace polyv::loader {

void sxor(keybyte* key, size_t key_size) {

    size_t section_beg = (size_t)&__load_start_encrypted;
    size_t section_end = (size_t)&__load_stop_encrypted;

    POLYV_MORPH_JUNK

    const size_t page_size = getpagesize();
    const size_t section_delta = section_end - section_beg;
    size_t section_size = section_delta;

    POLYV_MORPH_JUNK

    if (section_size % page_size != 0)
        section_size = section_delta + (section_delta % page_size);

    // Enable writing of the section
    void* section_page = (void*)(section_beg - (section_beg % page_size));
    mprotect(section_page, section_size, PROT_EXEC | PROT_WRITE | PROT_READ);
    char* section = (char*)(section_beg);

    POLYV_MORPH_JUNK

    // Apply symmetric XOR with provided key
    size_t key_i = 0;
    for(size_t i = 0; i < section_delta; i++, key_i = (key_i + 1) % POLYV_KEY_SIZE)
        section[i] = section[i] ^ key[key_i];

    POLYV_MORPH_JUNK

    // Disable writing of the section
    mprotect(section_page, section_size, PROT_EXEC | PROT_READ);

    POLYV_MORPH_JUNK
}

sxor_lock::sxor_lock() 
: sxor_lock(symmetric_key, POLYV_KEY_SIZE) { } 

sxor_lock::sxor_lock(keybyte* key, size_t key_size)
: _key{key}, _key_size{key_size} 
{
    POLYV_MORPH_JUNK

    sxor(_key, _key_size);
}

sxor_lock::~sxor_lock() 
{
    POLYV_MORPH_JUNK

    for(size_t i = 0; i < _key_size; i++)
        _key[i] += 0x1;

    sxor(_key, _key_size);
}

} // namespace polyv::loader 

namespace polyv::hidden {

const elf64* POLYV_ENCRYPTED load_elf64(const char* filepath) {

    // Load file
    int fd = open(filepath, O_RDWR);
    if (fd <= 0)
        return nullptr;

    struct stat sb;
    if (fstat(fd, &sb) < 0) 
        return nullptr;

    // Map file to memory
    unsigned char* elf_base = (unsigned char*)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_base == MAP_FAILED) return nullptr;
    close(fd);

    elf64* elf = new elf64;
    elf->size  = sb.st_size;
    elf->bytes = elf_base;

    elf->header   = (Elf64_Ehdr*)elf_base;
    elf->sections = (Elf64_Shdr*)(elf_base + elf->header->e_shoff);
    elf->shstrtab = (const char*)(elf_base + elf->sections[elf->header->e_shstrndx].sh_offset);

    return elf;
}
 
void POLYV_ENCRYPTED unload_elf64(const elf64* elf) {
    munmap(elf->bytes, elf->size);
}

size_t POLYV_ENCRYPTED page_align(size_t n, size_t page_size) {
    return (n + (page_size - 1)) & ~(page_size - 1);
}

const Elf64_Shdr* POLYV_ENCRYPTED lookup_section(const elf64* elf, const char* name) {
    for (Elf64_Half i = 0; i < elf->header->e_shnum; i++) {
        const char* section_name = elf->shstrtab + elf->sections[i].sh_name;
        if (strcmp(name, section_name) == 0)
            if (elf->sections[i].sh_size != 0)
                return elf->sections + i;
    }
    return nullptr;
}

} // namespace polyv::hidden

#endif