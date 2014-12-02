//
//  AES-GCM_ObjC.h
//  Pods
//
//  Created by Markus Kosmal on 20/11/14.
//
//

#import <Foundation/Foundation.h>

@interface AES_GCM_ObjC : NSObject

+(NSData *) encryptAesGcm: (NSData *) data withKey: (NSData *) key andIV: (NSData *) initializationVector;

+(NSData *) decryptAesGcm: (NSData *) data withKey: (NSData *) key andIV: (NSData *) initializationVector;

@end
