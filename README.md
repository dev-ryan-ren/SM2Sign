# SM2Sign
基于国密SM2、SM3的签名验签，加密解密(iOS)

## using
1. `git clone`
2. `将SM2libs拖入自己的项目中，导入SM2Manager.h`

## 使用注意
1. 基于国密SM2签名验签,国密SM3消息摘要 SM3withSM2
2. 基于国密SM2加密解密
3. 两端中文符号(，！)等编码不一致会导致SM3消息摘要后的字符串不同，经验证会验签失败
4. 两端生成公钥的长度可能不统一，一般为服务器端公钥前缀有04，iOS端截取04即可，经验证不会影响
5. 提供SM2的官方文档和推荐曲线方便查阅

## 资源参考
1. stevenpsm/GM_SM2 
2. lbw_sm2_sign
3. GmSSL            
4. PBGMService


