#include <crypt.hpp>

namespace polyv::crypt {
    
int xor_fn(unsigned char* data, size_t bytes, key& key) {
    size_t key_i = 0;
    for(size_t i = 0; i < bytes; i++, key_i = (key_i + 1) % key.size())
        data[i] = data[i] ^ key[key_i];

    return 0;
}

guard::guard(key& key) : _key{key} {
    decrypt(key);
}
 
guard::~guard() {

    // Change key by incrementing each byte
    for (size_t i = 0; i < _key.size(); i++)
        _key[i] += 0x1;

    encrypt(_key);
}

} // namespace polyv::cryp 
