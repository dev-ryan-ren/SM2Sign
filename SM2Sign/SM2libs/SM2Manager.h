//
//  SM2Manager.h
//  SM2Sign
//
//  Created by R on 2019/1/11.
//  Copyright © 2019 R. All rights reserved.
//  


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SM2Manager : NSObject

/**
 生成SM2密钥对
 
 @return 0,1 公钥 2私钥
 */
- (NSArray <NSString *>*)genSM2KeyPairs;

/**
 SM2签名

 @param pritvatekey 私钥
 @param publickey 公钥
 @param originalStr 要签名的原文
 @return 签名后的字符串
 */
- (NSString *) signWithPritvatekey:(NSString *) pritvatekey publickey:(NSString *) publickey originalStr:(NSString *) originalStr;

/**
 SM2验证签名

 @param publickey 公钥
 @param originalStr 要签名的原文
 @param signStr 签名后的字符串
 @param isPublikeySub 是否截取公钥前两位(04)
 @param isBase64 是否裁剪公钥前两位(04)
 @return 通过与否
 */
- (BOOL)vertifySignWithPublickey:(NSString *) publickey originalStr:(NSString *) originalStr signStr:(NSString *)signStr isPublikeySub:(BOOL)isPublikeySub isBase64:(BOOL)isBase64;


/**
 SM2加密

 @param publickey 公钥
 @param originalStr 原文
 @return 加密后的字符串
 */
- (NSString *)encryptWithPublickey:(NSString *)publickey originalStr:(NSString *) originalStr;


/**
 SM2解密

 @param pritvatekey 私钥
 @param cipherText 密文
 @return 解密后的原文
 */
- (NSString *)decryptWithPrivateKey:(NSString *)pritvatekey cipherText:(NSString *)cipherText;

@end

NS_ASSUME_NONNULL_END
