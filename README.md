# Polyv - Polymorphic Malware Framework

This project aims to create a simple polymorph malware framework that enable the used to create encrypted payloads.

## Usage - Header only library

To use the library just import the polyv.hpp header and generate the implementation.

```c++
#define POLYV_IMPLEMENTATION
#include <polyv.hpp>
```

To enable the encryption system you must enable the *POLYV_USE_ENCRYPTION* compiler directive before importing the library header and use the provided linker script (encrypted.ld). A simple cmake template is available in the example folder.

```c++
#define POLYV_USE_ENCRYPTION
```

## Components

The projects consists in 3 executables:

| Executable    | Folder  | Description |
| -             | -       | -           |
| polyv_client  | client/ |Main polymorph malware launching the payload |
| polyv_server  | server/ |Command and Control server |
| polyv_ignite  | ignite/ |Used to ignite the malware with the first key

Standard usage is to customize the payload of polyv_client and then igniting it using polyv_ignite.

```bash
echo 'first_key' | ./polyv_ignite polyv_client
./polyv_client
```

## Payload

The payload of Polyv connects to the C2 server and sends informations about the machine, it allows the opening of a reverse shell if requested.

## Propagation

The malware propagates in the infected host system by simply copying itself above all ELF file it finds in the file tree. When the infected application is launched the parassite polyv_client executes his payload and then forks the infected application to mimic a normal execution. 

## Platform

For now the only supported platform is UNIX, but a Windows version is in the making.