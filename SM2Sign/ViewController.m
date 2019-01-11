//
//  ViewController.m
//  SM2Sign
//
//  Created by R on 2019/1/11.
//  Copyright © 2019 R. All rights reserved.
//

#import "ViewController.h"
#import "SM2Manager.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    /*
     SM3withSM2 签名验签
     1.两端待验签的原文要经过base64编码，中文符号(，！)等编码不一致
     导致SM3消息摘要后的字符串会不同，经验证会验签失败
     2.两端密钥对生成方式可能会导致公钥的长度不统一，一般为服务器端公钥
     前缀有04，iOS端没有，去掉04即可，经验证不会影响
     */
    
    // SM2管理类
    SM2Manager *sm2Manager = [[SM2Manager alloc] init];
    
    // 1.生成sm2密钥对
    NSArray *keyPairs = [sm2Manager genSM2KeyPairs];
    NSString *publicKey = [NSString stringWithFormat:@"%@%@",keyPairs[0],keyPairs[1]];
    NSString *priviteKey = keyPairs[2];
    
    NSLog(@"公钥==========> \n%@",publicKey);
    NSLog(@"私钥==========> %@",priviteKey);
    
    // 2.base64原文
    NSString *str = @"hello sm2！";
    NSData *data =[str dataUsingEncoding:NSUTF8StringEncoding];
    str = [data base64EncodedStringWithOptions:0];
    NSLog(@"base64原文==========> %@",str);
    
    // 3.签名
    NSString *signStr = [sm2Manager signWithPritvatekey:priviteKey publickey:publicKey originalStr:str];
    NSLog(@"签名结果==========> \n%@",signStr);
    
    // 4.验签
    BOOL isVertifySign = [sm2Manager vertifySignWithPublickey:publicKey originalStr:str signStr:signStr];
    
    if (isVertifySign) {
        NSLog(@"验签结果==========>成功");
    }else{
        NSLog(@"验签结果==========>失败");
    }
    
    /*
     // 5.服务器验签(需要将SM2Manager中的UID改为服务器的UID)
     NSString *server_publicKey = @"d5548c7825cbb56150a3506cd57464af8a1ae0519dfaf3c58221dc810caf28dd921073768fe3d59ce54e79a49445cf73fed23086537027264d168946d479533e";
     
     NSString *server_str = @"aSBoYXZlIGEBAQFkcmVhbWRyZWFt";
     
     NSString * server_signStr = @"3046022100ac0186c88b3cdd47c6cde0a3046d15a2bad7520f728b9ba4221ed2c002e7e48a022100968c6fc7ff940e9f21e1c4455298fdf61344b9877581ab662a33f0441003e9a5";
     
     BOOL flag = [sm2Manager vertifySignWithPublickey:server_publicKey originalStr:server_str signStr:server_signStr];
     
     if (flag) {
     NSLog(@"验签服务器签名结果==========>成功");
     }else{
     NSLog(@"验签服务器签名结果==========>失败");
     }
     */
    
}

@end
