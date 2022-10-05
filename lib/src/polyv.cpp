#include <polyv.hpp>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

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