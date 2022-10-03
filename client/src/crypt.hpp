#pragma once

/// Size in bytes of the global key
#define POLYV_KEY_SIZE 4 //64

#include <array>

/// Contains all code that allow the encryption/descryption of the payload
namespace polyv::crypt {

/// Key structure
using key = std::array<unsigned char, POLYV_KEY_SIZE>;

/// XOR algorithm used in encryption and decryption
/// @param bytes size of the data to XOR
/// @param data data to XOR
/// @param key key used for the XOR
int xor_fn(unsigned char* data, size_t bytes, key& key);

/// Decrypt the xpayload section of the executable    
int decrypt(key& global_key);

/// Encrypt the xpayload section of the executable
int encrypt(key& global_key);

/// RAII class used to decrypt and encrypt automatically
/// the hidden section, it also changes the key at every use 
class guard {

    // Key used during decryption that will be changed at the end
    key& _key;

public:
    /// Decrypt the hidden section
    /// @param key key used to decrypt
    guard(key& key);

    /// Encrypt the hidden section modifying the key 
    virtual ~guard();
};

} // namespace polyv::crypt