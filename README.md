# proxy2-transmit

为tls-trans-proxy: [github停更](https://github.com/lrioxh/tls-trans-proxy)/[gitee最新](https://gitee.com/lrioxh/tls_proxy) 的开发测试环境

在socket tcp通信基础上，通过代理获取/改变tls握手报文，获得密钥解密C/S tls通信，实现tls透明代理。

环境：linux、openssl 3.0.12


文件结构：

> ├─linux	//linux代理 socket&ssl
>
> │  └─proxy_transmit.c	//main 
>
> ├─server-flask	//flask测试服务器
>
> ├─socketOnlyVer	//老版本win&linux socket代理
>
> ├─ssl
>
> │  ├─ca	//ca files
>
> │  ├─linux	//ssl C&S for linux 
>
> │  └─win	//ssl C&S for win
>
> └─win	//老版本win代理 socket&ssl

协议栈：

- TLS12_RSA_AES128_SHA256

  > 1. 获取C&S random
  > 2. 替换certificate证书
  > 3. 解密client key exchange报文获取pre master secret，再加密发送服务器
  > 4. PRF导出与C&S一致的master secret和key bolck
  > 5. 重构握手finished。PRF导出C&S侧verify data，aes_cbc加密并计算mac
  > 6. 对C&S发送的Application消息进行解密，并消除填充
  > 7. 实现开启扩展主密钥EMS情况下，客户端-代理-服务器的正常通信，以及对finished和application解密再加密和mac的重新计算

- TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  > 1. 获取C&S random
  > 2. 替换certificate证书，获取使用的椭圆曲线名称
  > 3. 生成新的椭圆曲线公钥和私钥，替换掉原始client key exchange和server key exchange报文的临时公钥，重新计算签名
  > 4. 利用新生成的椭圆曲线私钥和C/S两端的临时公钥计算出不同的预主密钥、主密钥、keyblock
  > 5. 重构握手finished。PRF导出C&S侧verify data，aes_gcm重新加密
  > 6. 实现开启扩展主密钥EMS情况下，客户端-代理-服务器的正常通信，以及对finished重新计算
