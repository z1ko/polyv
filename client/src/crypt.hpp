#pragma once

/// Functions that are not encrypted
#define POLYV_UNENCRYPTED

/// Size in bytes of the global key
#define POLYV_KEY_SIZE 4 //64

#include <array>

/// Contains all code that allow the encryption/descryption of the payload
namespace polyv {

using key_byte = unsigned char;
using key = std::array<key_byte, POLYV_KEY_SIZE>;

/// XOR algorithm used in encryption and decryption
int POLYV_UNENCRYPTED xor_fn(unsigned char* data, size_t bytes, key_byte* key);

/// Decrypt the xpayload section of the executable    
int POLYV_UNENCRYPTED decrypt(key_byte* key);

/// Encrypt the xpayload section of the executable
int POLYV_UNENCRYPTED encrypt(key_byte* key);

} // namespace polyv