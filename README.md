# Example implementation of a performant encryption of files with OpenSSL

# Prerequisites
Run `sudo apt install -y build-essential libssl-dev`

# Build

Run `mkdir build && cmake .. && make`

## Considerations
* C & CPP
* OpenSSL
* AES GCM Encryption with AAD & TAG
* Framed Encrypted Files
* POSIX Filedescriptors
* Multithreading

# Sources
https://github.com/bawejakunal/AES-GCM-256/blob/master/AES.c
https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
https://github.com/Pithikos/C-Thread-Pool
https://en.cppreference.com/w/cpp/language/pimpl
