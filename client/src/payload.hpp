#pragma once

/// Attribute describing a crypted function in the xpayload section
#define POLYV_XPAYLOAD_SECTION __attribute__ ((section (".xpayload")))
// Signals that a function cannot be accesed before decrypting the .xpayload section
#define POLYV_ENCRYPTED

#define POLYV_HIDDEN_SECTION_BEG int payload_beg() { return 0xDEAD; }
#define POLYV_HIDDEN_SECTION_END int payload_end() { return 0xBEEF; }

#define POLYV_HIDDEN_SECTION(hidden_code)       \
namespace polyv::hidden                         \
{                                               \
    POLYV_HIDDEN_SECTION_BEG                    \
    hidden_code                                 \
    POLYV_HIDDEN_SECTION_END                    \
                                                \
} // namespace polyv::hidden

/// Contains all code that will be crypted 
namespace polyv::hidden {

/// Function used as a label to declare the beginning of the crypted section
int POLYV_ENCRYPTED payload_beg() POLYV_XPAYLOAD_SECTION;

/// Entry point of the malware, mut be at the top of .cpp file in hidden_code
int POLYV_ENCRYPTED payload(int argc, char* argv[]) POLYV_XPAYLOAD_SECTION;

/// Function used as a label to declare the end of the crypted section
int POLYV_ENCRYPTED payload_end() POLYV_XPAYLOAD_SECTION;

} // namespace polyv::hidden
