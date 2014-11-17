
                                AES-GCM v1.0

This set of files is a full implementation of the Galois/Counter Mode (GCM) 
authenticated encryption (AE) cryptographic system using the 128-bit block 
Rijndael cipher. It was developed by Steve Gibson of GRC.com as a component 
of the public domain SQRL -- Secure Quick Reliable Login -- system. Because 
all other existing AES-GCM libraries were available only under various GPL 
or other licenses, this library was developed to give SQRL a license-free 
public domain solution.

Enclosed with the original file set is the National Institute of Standards 
and Technology (NIST) AES-GCM validation test suite which fully exercises 
the library by running 47,250 test encryptions and decryptions with full 
verification of all results. Needless to say, this code passes these tests. 

ALL OF THESE FILES ARE HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE BENEFIT 
OF ALL.  THIS CODE MAY BE USED AND MODIFIED FOR ANY REASON AND ANY PURPOSE. 
 
These files also include a full implementation of the AES/Rijndael cipher. 
However, since GCM implements a counter-mode cipher, AES is only used in 
encryption (and not decryption) mode. The aes.h header is set to eliminate 
decryption support at a savings of approximately 3k of library size. If AES 
decryption is required, the appropriate #define may be set in aes.h. 

The following files are enclosed:

gcm.c           - GCM AE implementation
gcm.h           - gcm function declarations and other plumbing
aes.c           - general purpose AES/Rijndael cipher implementation
aes.h           - aes function declarations and other plumbing

Note that those four files are used to build the gcm.lib statically linked
library. Under windows, without compression, it is 11,330 bytes. (It 
compresses to less than half that size.)

gcmtest.c       - GCMTEST utility which runs the AES-GCM implementation 
                  through the entire NIST validation test suite.

Note that gcmtest can either be linked to the static library, or compiled 
along with the aes and gcm files to build a monolithic executable.

Pre-compiled Windows binaries for the above are available in the archive's 
Windows subdirectory:

gcm.lib         - 32-bit Windows statically linkable aes-gcm library.
gcmtest.exe     - 32-bit Windows executable aes-gcm NIST validator.

Note that the GCMTEST utility must have access to the NIST validation test 
vectors. The original six test vector files are downloadable directly from 
NIST at:

http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip

The six original test vector files are:

gcmEncryptExtIV128.rsp  - 128-bit encryption tests with IV and auth tags
gcmEncryptExtIV192.rsp  - 192-bit       "       "       "       " 
gcmEncryptExtIV256.rsp  - 256-bit       "       "       "       "
gcmDecrypt128.rsp       - 128-bit decryption test with good and bad auth
gcmDecrypt192.rsp       - 192-bit       "       "       "       "
gcmDecrypt256.rsp       - 256-bit       "       "       "       "

In order to use these test vector files with the enclosed GCMTEST NIST 
validation test utility, the files must be processed into a binary file. 
The enclosed "rsp_processor.pl" PERL script fully performs the processing 
of these six files to produce a single "gcm_test_vectors.bin" output file.

THESE FILES are provided within this archive's gcm_test_vectors directory.
The GCMTEST utility assumes that the "gcm_test_vectors.bin" file will be
present in the same directory as the "gcmtest.exe" executable.


                           /* end of readme */

