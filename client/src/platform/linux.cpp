#include <crypt.hpp>
#include <payload.hpp>

#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

namespace polyv::crypt {
    
/// Decrypt the xpayload section of the executable    
int decrypt(key& global_key) {

    const size_t beg = (size_t)(hidden::payload_beg);
    const size_t end = (size_t)(hidden::payload_end);

    // Get the size of payload using the function labels
    const size_t section_delta = end - beg; 
    const size_t page_size = getpagesize();

    // Allign to page boundary
    void* section_ptr = (void*)(beg - (beg % page_size));

    size_t section_size = section_delta;
    if (section_size % page_size != 0)
        section_size = section_delta + (section_delta % page_size);
    
    // Enable writing of the section
    if (mprotect(section_ptr, section_size, PROT_EXEC | PROT_WRITE | PROT_READ))
        return -1;

    // Decrypt payload section
    unsigned char* section = (unsigned char*)(beg);

#if 0
    printf("Before: \n");
    for(size_t i = 0; i < section_delta; i++)
        printf("%x ", section[i]);
    printf("\n");
#endif

    xor_fn(section, section_delta, global_key);

#if 0
    printf("After: \n");
    for(size_t i = 0; i < section_delta; i++)
        printf("%x ", section[i]);
    printf("\n");
#endif

    // Disable writing of the section
    if (mprotect(section_ptr, section_size, PROT_EXEC | PROT_READ))
        return -1;

    return 0;
}

/// Encrypt the xpayload section of the executable
int encrypt(key& global_key) {
    return decrypt(global_key);
}

} // namespace polyv::crypt
