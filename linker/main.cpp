
#include <payload.hpp>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

struct Elf64 {
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* sections;
    const char* shstrtab;
};

// Find a section header by its name
const Elf64_Shdr* lookup_section(const Elf64& elf, const char* name) {
    for (Elf64_Half i = 0; i < elf.ehdr->e_shnum; i++) {
        const char* section_name = elf.shstrtab + elf.sections[i].sh_name;
        if (strcmp(name, section_name) == 0)
            if (elf.sections[i].sh_size != 0)
                return elf.sections + i;
    }
    return nullptr;
}

const size_t page_align(size_t n) {
    const size_t page_size = getpagesize();
    return (n + (page_size - 1)) & ~(page_size - 1);
}

// Linker symbols used to locate the payload section
extern char __load_start_encrypted, __load_stop_encrypted;

int main(int argc, char** argv) {
    
    int(*fn)(int) = (int(*)(int))(&__load_start_encrypted);
    int x = fn(1);

    size_t payload_beg = (size_t)&__load_start_encrypted;
    size_t payload_end = (size_t)&__load_stop_encrypted;
    size_t payload_dif = payload_end - payload_beg;

    const size_t page_size = getpagesize();
    void* section_ptr = (void*)(payload_beg - (payload_beg % page_size));

    size_t section_size = payload_dif;
    if (section_size % page_size != 0)
        section_size = payload_dif + (payload_dif % page_size);

    // Enable writing of the section
    if (mprotect(section_ptr, section_size, PROT_EXEC | PROT_WRITE | PROT_READ))
        return -1;

    // Destroy hidden section
    memset((void*)payload_beg, 0xFFFFFFFF, section_size);

    // Should crash!
    int y = add1(1);

    // Open self elf
    int fd = open(argv[0], O_RDONLY);
    if (fd <= 0) return -1;

    struct stat sb;
    if (fstat(fd, &sb) < 0) 
        return -1;

    // Map file to memory
    unsigned char* elf_base = (unsigned char*)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_base == MAP_FAILED)
        return -1;

    close(fd);


    Elf64 elf;
    elf.ehdr = (Elf64_Ehdr*)elf_base;

    elf.sections = (Elf64_Shdr*)(elf_base + elf.ehdr->e_shoff);
    elf.shstrtab = (const char*)(elf_base + elf.sections[elf.ehdr->e_shstrndx].sh_offset);

    // Payload data
    const Elf64_Shdr* payload_shdr = lookup_section(elf, ".xpayload");
    if (payload_shdr == nullptr)
        return -1;

    // Allocate executable memory region for payload
    unsigned char* payload = (unsigned char*)mmap(NULL, page_align(payload_shdr->sh_size), 
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS, -1, 0);

    // Copy payload from file to RAM and allow execution
    memcpy(payload, elf_base + payload_shdr->sh_offset, payload_shdr->sh_size);

    return add4(-4);
}