//
//  AES-GCM_ObjC.m
//  Pods
//
//  Created by Markus Kosmal on 20/11/14.
//
//

#import "AES-GCM_ObjC.h"

extern int aes_gcm_encrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len);

extern int aes_gcm_decrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len);

@implementation AES_GCM_ObjC

+(NSData *) encryptAesGcm: (NSData *) data withKey: (NSData *) key andIV: (NSData *) initializationVector{
    Byte * res[ [data length] ];
    aes_gcm_encrypt(*res, [data bytes], sizeof([data bytes]), [key bytes],  sizeof([key bytes]), [initializationVector bytes], sizeof([initializationVector bytes]));
    return [NSData dataWithBytes:res length:sizeof(res)];
}

+(NSData *) decryptAesGcm: (NSData *) data withKey: (NSData *) key andIV: (NSData *) initializationVector{
    Byte * res[ [data length] ];
    aes_gcm_decrypt(*res, [data bytes], sizeof([data bytes]), [key bytes],  sizeof([key bytes]), [initializationVector bytes], sizeof([initializationVector bytes]));
    return [NSData dataWithBytes:res length:sizeof(res)];
}


@end
