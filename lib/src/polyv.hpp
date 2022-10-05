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
#define POLYV_KEY_SIZE 4

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
