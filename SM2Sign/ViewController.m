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

     1.两端中文符号(，！)等编码不一致会导致SM3消息摘要后的字符串不同，经验证会验签失败
     2.两端生成公钥的长度可能不统一，一般为服务器端公钥前缀有04，iOS端截取04即可，经验证不会影响
     */
    
    // SM2管理类
    SM2Manager *sm2Manager = [[SM2Manager alloc] init];
    
    // 1.生成sm2密钥对
    NSArray *keyPairs = [sm2Manager genSM2KeyPairs];
    NSString *publicKey = [NSString stringWithFormat:@"%@%@",keyPairs[0],keyPairs[1]];
    NSString *priviteKey = keyPairs[2];
    
    NSLog(@"公钥==========> \n%@",publicKey);
    NSLog(@"私钥==========> %@",priviteKey);
    
    // 2.原文
    NSString *str = @"hello sm2！";
    NSLog(@"原文==========> %@",str);
    
    // 3.签名
    NSString *signStr = [sm2Manager signWithPritvatekey:priviteKey publickey:publicKey originalStr:str];
    NSLog(@"签名结果==========> \n%@",signStr);
    
    // 4.验签
    BOOL isVertifySign = [sm2Manager vertifySignWithPublickey:publicKey originalStr:str signStr:signStr isPublikeySub:NO isBase64:YES];
    
    if (isVertifySign) {
        NSLog(@"验签结果==========>成功 \n");
    }else{
        NSLog(@"验签结果==========>失败 \n");
    }
    
     // 5.服务器验签
     NSString *server_publicKey = @"0401470CCF24418EA33DFD555C1A52FA00B3E7E56A7FC73A892CF998BEE95610FC73B52446AD53C8BD1C3870649D33E3A8F664ED5ABE6D342B1FBC49DD04BE865D";
     
     NSString *server_str = @"aGVsbG8gc20y77yB";
     
     NSString * server_signStr = @"304402203A09F28AC2BAE0CA555E58D7D2FC940C8A35FDAE751A8C5FC120ED0F0A509B9D0220479351FC725D0E9B98A36DC3339A07A551F395E64DD5B1300B859C8E823DBC9E";
     
     BOOL flag = [sm2Manager vertifySignWithPublickey:server_publicKey originalStr:server_str signStr:server_signStr isPublikeySub:YES isBase64:NO];
     
     if (flag) {
     NSLog(@"验签服务器签名结果==========>成功");
     }else{
     NSLog(@"验签服务器签名结果==========>失败");
     }
}

@end
