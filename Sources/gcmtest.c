/******************************************************************************
*
* THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
*
* This program runs the entire suite of 47,250 National Institute of Standards
* and Technology (NIST) AES-GCM test vectors to thoroughly verify the correct
* operation of GRC's implementation of the standard AES-GCM authenticated
* encryption cipher.
*
*          This program was created by Steven M. Gibson of GRC.com.
*
* It is intended for general purpose use, but was written in support of GRC's
* reference implementation of the SQRL (Secure Quick Reliable Login) client.
*
* See: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
*
* NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
* REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
*
*******************************************************************************/

/*
  This program reads, and is driven by, a pre-compiled binary file which must
  first be created by processing the six 'rsp' files contained in the NIST ZIP
  (see the link above).  This processing is performed by the "rsp_processor.pl"
  PERL code which produces the "gcm_test_vectors.bin" file.

  The NIST 'rsp' files (see referenced and enclosed ZIP file) contain groups
  of 15 sets of hexadecimal format input and output strings. Each group of 15
  tests the behavior of the GCM cipher with differing lengths of parameters.

  For example, a section of the 256-bit encryption test looks like this:

  [Keylen = 256]
  [IVlen = 96]
  [PTlen = 128]
  [AADlen = 128]
  [Taglen = 120]

  Count = 0
  Key = 7f7168a406e7c1ef0fd47ac922c5ec5f659765fb6aaa048f7056f6c6b5d8513d
  IV = b8b5e407adc0e293e3e7e991
  PT = b706194bb0b10c474e1b2d7b2278224c
  AAD = ff7628f6427fbcef1f3b82b37404e116
  CT = 8fada0b8e777a829ca9680d3bf4f3574
  Tag = daca354277f6335fc8bec90886da70

  The header block specifies the lengths of the various parameters and is
  then followed by 15 sets of parameters of that length numbered by the
  0-based "Count" from 0 to 14.

  The abbreviations have the following meanings (all lengths are in bits):

  Keylen    key length
  IVlen     initialization vector length
  PTlen     plaintext length
  AADlen    associated data length
  Taglen    authentication tag length

  Count     count (0-14) of the data within the parameter set
  Key       key data
  IV        initialization vector data
  PT        plaintext data
  AAD       associated authenticated data
  CT        ciphertext data
  Tag       authentication tag data

  ---------------------------------------------------------------------------

  The file compiled by the "rsp_processor.pl" PERL file consists of a series of
  variable-length blocks with one block per test. The blocks have the following
  format (all lengths are in byte counts):

  block_type    - one byte block type
  key_length    - one byte key length
  key           - key
  iv_length     - one byte initialization vector length
  iv            - initialization vector
  aad_length    - one byte associated authenticated data length
  aad           - associated authenticated data
  pt_length     - one byte plaintext data length
  pt            - plaintext data
  ct_length     - one byte ciphertext data length
  ct            - ciphertext data
  tag_length    - one byte authentication tag length
  tag           - authentication tag

  Four block types are defined:

  0: end-of-file. This signals that all blocks have been processed.
  1: data encryption. Plaintext is encrypted, ciphertext & auth tag are verified.
  2: data decryption. Ciphertext is decrypted, Plaintext & auth tag are verified.
  3: data decryption with AUTH FAILURE. Ciphertext is decrypted, failure verified.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "gcm.h"    // define the various AES-GCM library functions 
#include "detect_platform.h"

static uint testcount = 0;


/*******************************************************************************
 *
 *  PRINT_WITH_COMMAS
 *
 *  This is a quick hack to print positive decimal numbers with thousands
 *  separators.  It calls itself recursively to print from left-to-right
 *  whenever the value is >1000 and thus needs a comma.
 */
void print_with_commas( uint num ) {
    if( num < 1000 )
        printf( "%d", num );
    else {
        print_with_commas( num/1000 );
        printf( ",%03d", num%1000 );
    }
}


/*******************************************************************************
 *
 *  VERIFY_GCM_ENCRYPTION
 *
 *  Handles block type 0:  This is the first of the three routines, called by
 *  VERIFY_GCM, which reads the "gcm_test_vectors.bin" file block by block.
 *  It invokes the AES-GCM library "gcm_crypt_and_tag" function to encrypt
 *  the provided plaintext, then verifies the returned ciphertext and auth
 *  tag against the correct test vector data provided by the NIST file.
 */
int verify_gcm_encryption(
        const uchar *key,       // pointer to the cipher key
        size_t key_len,         // byte length of the key
        const uchar *iv,        // pointer to the initialization vector
        size_t iv_len,          // byte length of the initialization vector
        const uchar *aad,       // pointer to the non-ciphered additional data
        size_t aad_len,         // byte length of the additional AEAD data
        const uchar *pt,        // pointer to the plaintext SOURCE data
        const uchar *ct,        // pointer to the CORRECT cipher data
        size_t ct_len,          // byte length of the cipher data
        const uchar *tag,       // pointer to the CORRECT tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    uchar ct_buf[256];          // cipher text results for comparison
    uchar tag_buf[16];          // tag result buffer for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // encrypt the NIST-provided plaintext into the local ct_buf and
    // tag_buf ciphertext and authentication tag buffers respectively.
    ret = gcm_crypt_and_tag( &ctx, ENCRYPT, iv, iv_len, aad, aad_len,
                             pt, ct_buf, ct_len, tag_buf, tag_len);
    ret |= memcmp( ct_buf, ct, ct_len );    // verify correct ciphertext
    ret |= memcmp( tag_buf, tag, tag_len ); // verify correct authentication tag

    gcm_zero_ctx( &ctx );       // not really necessary here, but good to do

    return ( ret );             // return any error 'OR' generated above
}


/*******************************************************************************
 *
 *  VERIFY_GCM_DECRYPTION
 *
 *  Handles block type 1:  This is the second of the three routines, called by
 *  VERIFY_GCM, which reads the "gcm_test_vectors.bin" file block by block.
 *  It invokes the AES-GCM library "gcm_auth_decrypt" function to decrypt the
 *  provided ciphertext, then verifies the returned plaintext and auth tag
 *  against the correct test vector data provided by the NIST file.
 */
int verify_gcm_decryption(
        const uchar *key,       // pointer to the cipher key
        size_t key_len,         // byte length of the key
        const uchar *iv,        // pointer to the initialization vector
        size_t iv_len,          // byte length of the initialization vector
        const uchar *aad,       // pointer to the non-ciphered additional data
        size_t aad_len,         // byte length of the additional AEAD data
        const uchar *pt,        // pointer to the plaintext SOURCE data
        const uchar *ct,        // pointer to the CORRECT cipher data
        size_t ct_len,          // byte length of the cipher data
        const uchar *tag,       // pointer to the CORRECT tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    uchar pt_buf[256];          // plaintext results for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // decrypt the NIST-provided ciphertext and auth tag into the local pt_buf 
    ret = gcm_auth_decrypt( &ctx, iv, iv_len, aad, aad_len,
                             ct, pt_buf, ct_len, tag, tag_len);
    ret |= memcmp( pt_buf, pt, ct_len );

    gcm_zero_ctx( &ctx );

    return ( ret );             // return any error 'OR' generated above
}


/*******************************************************************************
 *
 *  VERIFY_BAD_DECRYPTION
 *
 *  Handles block type 2:  This is the third of the three routines, called by
 *  VERIFY_GCM, which reads the "gcm_test_vectors.bin" file block by block.
 *  It invokes the AES-GCM library "gcm_auth_decrypt" function to decrypt the
 *  provided ciphertext, then verifies a AUTHENTICATION FAILURE caused by a
 *  deliberate mismatch in the ciphertext and/or authentication data which was
 *  provided by the NIST file(s).
 */
int verify_bad_decryption(
        const uchar *key,       // pointer to the cipher key
        size_t key_len,         // byte length of the key
        const uchar *iv,        // pointer to the initialization vector
        size_t iv_len,          // byte length of the initialization vector
        const uchar *aad,       // pointer to the non-ciphered additional data
        size_t aad_len,         // byte length of the additional AEAD data
        const uchar *ct,        // pointer to the CORRECT cipher data
        size_t ct_len,          // byte length of the cipher data
        const uchar *tag,       // pointer to the CORRECT tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    uchar pt_buf[256];          // plaintext results for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // decrypt the NIST-provided ciphertext and auth tag into the local pt_buf
    ret = gcm_auth_decrypt( &ctx, iv, iv_len, aad, aad_len,
                             ct, pt_buf, ct_len, tag, tag_len);
    ret ^= GCM_AUTH_FAILURE;    // the fucntion SHOULD FAIL and return the
                                // GCM_AUTH_FAILURE. We XOR it to verify
    gcm_zero_ctx( &ctx );

    return ( ret );             // return any error 'XOR' generated above
}


/*******************************************************************************
 *
 *  VERIFY_GCM
 *
 *  Given a pointer (vd) to an array of test vector records, we run through
 *  them each, one-by-one to verify the proper operation of the AES-GCM mode
 */
int verify_gcm( uchar *vd )
{
    int ret = 0;                // our function return status
    uchar RecordType;           // 0 for end of file
                                // 1 for encrypt and/or auth
                                // 2 for decrypt and/or auth CORRECTLY
                                // 3 for decrypt and/or auth --FAIL--

    // declarations for the lengths and pointers to our test vectorse the le
    size_t key_len, iv_len, aad_len, pt_len, ct_len, tag_len;
    uchar *key, *iv, *aad, *pt, *ct, *tag;

    // each test vector record begins with a single byte to indicate the
    // type of record which follows. A zero indicates the end of the file
    while ((RecordType = *vd++)) {
        // we have a type 1-3 record, so let's get the length
        // and pointers to all of this record's test parameters

        key_len = *vd++;    // get the length of the key sub-record
        key = vd;           // get the pointer to the key
        vd += key_len;      // bump the vector data (vd) pointer past the key

        iv_len = *vd++;     // get the length of the init vector sub-record
        iv = vd;            // get the pointer to the init vector
        vd += iv_len;       // bump the vector data (vd) pointer past the iv

        aad_len = *vd++;    // get the length of the assoc auth data sub-record
        aad = vd;           // get the pointer to the assoc auth data
        vd += aad_len;      // bump the vector data (vd) pointer past the aad

        pt_len = *vd++;     // get the length of the plaintext sub-record
        pt = vd;            // get the pointer to the plaintext
        vd += pt_len;       // bump the vector data (vd) pointer past the plaintext

        ct_len = *vd++;     // get the length of the ciphertext sub-record
        ct = vd;            // get the pointer to the ciphertext
        vd += ct_len;       // bump the vector data (vd) pointer past the ciphertext

        tag_len = *vd++;    // get the length of the auth tag sub-record
        tag = vd;           // get the pointer to the auth tag
        vd += tag_len;      // bump the vector data (vd) pointer past the auth tag

        switch ( RecordType )   // based upon our record type, run a test...
        {
            case 1:     // verify an AES-GCM encryption and/or authentication tagging
                        ret = verify_gcm_encryption( key, key_len, iv, iv_len,
                        aad, aad_len, pt, ct, ct_len, tag, tag_len);
                        break;

            case 2:     // verify an AES-GCM decryption and/or tagged authentication
                        ret = verify_gcm_decryption( key, key_len, iv, iv_len,
                        aad, aad_len, pt, ct, ct_len, tag, tag_len);
                        break;

            case 3:     // verify a FAILED AES-GCM decryption and/or tagged authentication
                        ret = verify_bad_decryption( key, key_len, iv, iv_len,
                        aad, aad_len, ct, ct_len, tag, tag_len);
        }
        if( ret ) break;// if our verification failed, no further testing
		++testcount;    // so far so good, let's count another successful test
    }                   // if 'ret' is still zero, we made it all the way through
    return ( ret );     // without any failures, otherwise, ret indicates the trouble.
}


/*******************************************************************************
 *
 *  LOAD_FILE_INTO_RAM
 *
 *  For ease of processing, this simply reads the entire file of test vector
 *  data into RAM. It sets the provided pointer to the allocation, and returns
 *  the number of bytes read... or an error if problems were encountered.
 */
int load_file_into_ram(const char *filename, uchar **result) 
{ 
    size_t size = 0;                      // the size of ram and file
    FILE *f = fopen(filename, "rb");    // open for binary reading
    if( f == NULL ) {                   // if the open failed...
        *result = NULL;                 // set our file pointer to NULL
        return (-1);                    // -1 means file opening fail 
    } 
    fseek(f, 0, SEEK_END);              // go to the logical EOF
    size = ftell(f);                    // our location == file's size
    fseek(f, 0, SEEK_SET);              // now move back to the front
    
    if ((*result = (uchar *)malloc(size)) == 0 ) // alloc RAM & set our ptr
        return (-2);                    // -2 means memory alloc failed

    if( size != fread(*result, sizeof(char), size, f) ) { // read whole file
        free(*result);                  // if we were unable to read it all
        return (-3);                    // -3 means file reading failed 
    } 
    fclose(f);                          // we have the file, so close it
    return (int)size;                        // return our file size
}


int startTest(const char* vf)
{
    uchar *vd;          // a pointer to our loaded vector data
    int ret = 0;        // our return -- non-zero for any failure
    int datalength;     // length of the vector data file
    
    printf( "\n" );     // give us a blank line beneath the command invocation
    
    gcm_initialize();   // initialize our GCM library once before first use
    
    // attempt to load the test vectors file and report any problems
    switch ( datalength = load_file_into_ram( vf, &vd ) )
    {
        case -1:    printf( "Test vector file \"%s\" not found!\n", vf );
            return datalength;  // return status to OS
            
        case -2:    printf( "Unable to allocate RAM for vector file!\n" );
            return datalength;  // return status to OS
            
        case -3:    printf( "Error reading test vector file into memory!\n" );
            return datalength;  // return status to OS
            
        default:    print_with_commas( datalength );
            printf( " bytes of test vector data read.\n\n" );
    }
    
    // run through and verify all of the NIST AES-GCM test vectors
    ret = verify_gcm( vd );
    
    free( vd ); // release our test vector file allocation
    
    // print the total number of tests that passed.
    print_with_commas( testcount );
    printf( " tests performed.\n\n" );
    
    // and deliver the final test suite outcome.
    printf( "NIST AES-GCM validation test suite: " );
    if( ret )
        printf( "FAILED!!\n" );
    else
        printf( "PASSED!!\n" );
    
    return( ret );  // exit the program returning status to caller
}

/*******************************************************************************
 *
 *  GCMTEST (main)
 *
 *  This reads the entire "gcm_test_vectors.bin" file, which has been created
 *  by the "rsp_processor.pl" PERL utility, to run all 47,250 validation tests
 *  against GRC's AES-GCM authenticated encryption reference library.
 */
#ifndef OSTYPE_iOS
int main( )
{
    const char *vf = "gcm_test_vectors.bin";
    return startTest(vf);
}
#endif
