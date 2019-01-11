//
//  SM2Manager.m
//  SM2Sign
//
//  Created by R on 2019/1/11.
//  Copyright © 2019 R. All rights reserved.
//

#import "SM2Manager.h"

#import "GM_sm2.h"

#import "sm2.h"
#import "sm2ToOC.h"

#import "NSData+HexString.h"

// SM2签名用的UID，两端要一致
#define k_SM2UID @"renhepeng@51signing.com"

// 服务器验签UID
//#define k_SM2UID @"tongyu@51signing.com"

@implementation SM2Manager

#pragma mark -
#pragma mark -  SM2曲线参数
// SM2推荐参数
- (EC_GROUP *)sm2Curve{
    EC_GROUP *sm2p256real = new_ec_group(1,
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                                         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                                         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                                         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                                         "1");
    return sm2p256real;
}

#pragma mark -
#pragma mark -  生成SM2密钥对
- (NSArray <NSString *>*)genSM2KeyPairs {
    
    unsigned char buff[64] = {0};
    unsigned char prikeyBuff[2000] = {0};
    unsigned long priLen = 2000;
    
    GM_GenSM2keypair(prikeyBuff, &priLen, buff);
    
    NSData *pubXD = [NSData dataWithBytes:buff length:32];
    NSData *pubYD = [NSData dataWithBytes:buff+32 length:32];
    NSData *priD = [NSData dataWithBytes:prikeyBuff length:priLen];
    
    NSString *pubX = [pubXD hexStringFromData:pubXD];
    NSString *pubY = [pubYD hexStringFromData:pubYD];
    NSString *pri = [priD hexStringFromData:priD];
    
    return @[pubX,pubY,pri];
}

#pragma mark -
#pragma mark -  SM2 签名
- (NSString *) signWithPritvatekey:(NSString *) pritvatekey publickey:(NSString *) publickey originalStr:(NSString *) originalStr{
    
    NSString *signDataStr = @"";
    unsigned char result[256] = {0};
    unsigned long outlen = 256;
    
    NSString  *px = [publickey substringToIndex:64];
    NSString  *py = [publickey substringFromIndex:64];
    
    EC_GROUP *sm2p256real = [self sm2Curve];
    
    BOOL isSuccess = JZYT_sm2_sign(sm2p256real,
                                   [self ocstringConvcsting:pritvatekey],
                                   [self ocstringConvcsting:px],
                                   [self ocstringConvcsting:py],
                                   [self ocstringConvcsting:k_SM2UID],
                                   "",
                                   [self ocstringConvcsting:originalStr],
                                   "",
                                   [self ocstringConvcsting:[self randHexString]],
                                   "",
                                   "",result,&outlen);
    
    if (isSuccess) {
        NSLog(@"签名成功");
        for (int i = 0; i<256; i++){
            result[i] = result[i];
        }
        
        NSData *signData = [NSData dataWithBytes:(unsigned char *)result length:outlen];
        outlen = [signData length];
        
        signDataStr = [signData hexStringFromData:signData];
    } else {
        NSLog(@"签名失败");
    }
    
    return signDataStr;
}

#pragma mark -
#pragma mark -  SM2验签
- (BOOL)vertifySignWithPublickey:(NSString *) publickey originalStr:(NSString *) originalStr signStr:(NSString *)signStr{
    
    BOOL isSuccess;

    unsigned char result[256];
    unsigned int outlen;
    
    NSData *data = [NSData dataFromHexString:signStr];
    Byte *byteArray =(Byte*)[data bytes];
    for (int i = 0; i<data.length; i++) {
        result[i] = byteArray[i];
    }
    outlen = (unsigned int)[data length];
    NSString  *px = [publickey substringToIndex:64];
    NSString  *py = [publickey substringFromIndex:64];
    
    EC_GROUP *sm2p256real = [self sm2Curve];

    if (!JZYT_sm2_verify(sm2p256real,
                         "",
                         [self ocstringConvcsting:px],
                         [self ocstringConvcsting:py],
                         [self ocstringConvcsting:k_SM2UID],
                         [self ocstringConvcsting:originalStr],
                         result,outlen)){
        
        isSuccess = false;
        
    } else {
        isSuccess = true;
    }
    
    return isSuccess;
}


#pragma mark -
#pragma mark - helper

#pragma mark - oc字符串转为c字符
- (nullable const char *) ocstringConvcsting:(NSString *)ocsting{
    return [ocsting cStringUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - 生成随机数
// 16进制随机数
-(NSString *)randHexString{
    NSString *hexStr = @"";
    
    for(int i=0;i<16;i++){
        int num = arc4random()%0xFFFF;
        NSString *str = [NSString stringWithFormat:@"%02x", num];
        hexStr = [NSString stringWithFormat:@"%@%@",hexStr,str] ;
    }
    return hexStr;
}

@end
