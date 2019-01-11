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
 @return 通过与否
 */
- (BOOL)vertifySignWithPublickey:(NSString *) publickey originalStr:(NSString *) originalStr signStr:(NSString *)signStr;

@end

NS_ASSUME_NONNULL_END
