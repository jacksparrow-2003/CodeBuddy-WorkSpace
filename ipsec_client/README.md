# IPsec VPN Client

基于 strongSwan 参考实现的完整 IPsec VPN 客户端，使用 C 语言编写，支持 IKEv2 协议协商和 ESP 数据加密传输。

## 功能特性

- **IKEv2 协议**（RFC 7296）完整实现
  - IKE_SA_INIT 交换（DH 密钥协商、SA 提案）
  - IKE_AUTH 交换（PSK 认证、Child SA 建立）
  - 密钥派生：SKEYSEED、SK_d、SK_ei、SK_er、SK_ai、SK_ar、SK_pi、SK_pr
  - PRF+ 扩展密钥材料函数

- **ESP（封装安全有效载荷）**（RFC 4303）
  - 支持 AES-256-CBC + HMAC-SHA256-128 模式
  - 支持 AES-256-GCM（AEAD）模式（可配置）
  - 通过 Linux 内核 XFRM 框架自动处理 ESP 封装

- **Linux XFRM 内核集成**
  - 通过 Netlink/XFRM 接口安装 SA（安全关联）
  - 安装 SPD 策略（出站/入站）
  - 隧道模式（Tunnel Mode）

- **HTTP 业务数据传输**
  - 通过已建立的 IPsec 隧道发送 HTTP GET 请求
  - 内核自动对匹配流量进行 ESP 封装（透明 IPsec）

## 项目结构

```
ipsec_client/
├── Makefile
├── config.h          # 配置参数（PSK、算法、服务端 IP 等）
├── main.c            # 主程序
├── ikev2/
│   ├── ike_types.h   # IKEv2 协议常量和数据结构
│   ├── ike_message.c # IKE 消息编解码（载荷序列化/反序列化）
│   ├── ike_sa_init.c # IKE_SA_INIT 交换实现
│   ├── ike_auth.c    # IKE_AUTH 交换实现（PSK 认证）
│   └── ike_crypto.c  # 密钥派生和 SK 载荷加解密
├── crypto/
│   ├── dh.c          # Diffie-Hellman（Group 14 MODP / Group 19 ECP）
│   ├── prf.c         # PRF 和 PRF+ 函数（HMAC-SHA256）
│   └── aes_utils.c   # AES-CBC 和 AES-GCM 封装（OpenSSL EVP）
├── xfrm/
│   └── xfrm_api.c    # Linux Netlink XFRM SA/Policy 管理
└── http/
    └── http_client.c # 简单 HTTP/1.1 GET 客户端
```

## 编译

### 依赖安装（Ubuntu/Debian）

```bash
sudo apt-get install gcc libssl-dev
```

### 编译

```bash
make
```

### 编译并检查依赖

```bash
make check-deps
make
```

## 使用方法

```bash
sudo ./ipsec_client <server_ip> [http_port] [http_path]
```

**参数说明：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `server_ip` | IPsec/HTTP 服务端 IP 地址 | 必填 |
| `http_port` | HTTP 服务端口 | 80 |
| `http_path` | HTTP 请求路径 | `/` |

**示例：**

```bash
# 向 10.0.0.1 的 HTTP 服务发送请求（通过 IPsec 隧道）
sudo ./ipsec_client 10.0.0.1 80 /

# 访问特定路径
sudo ./ipsec_client 192.168.100.1 8080 /api/status
```

## 配置

编辑 `config.h` 修改客户端参数：

```c
/* 预共享密钥 */
#define PSK_VALUE          "supersecretkey123"

/* 客户端标识 */
#define CLIENT_ID          "client@ipsec.local"
#define SERVER_ID          "server@ipsec.local"

/* IKE 算法套件 */
#define IKE_ENCR_ALG       ENCR_AES_CBC        /* 或 ENCR_AES_GCM_16 */
#define IKE_ENCR_KEY_BITS  256
#define IKE_DH_GROUP       DH_GROUP_14         /* 或 DH_GROUP_19 */

/* ESP 算法套件 */
#define ESP_ENCR_ALG       ENCR_AES_CBC        /* 或 ENCR_AES_GCM_16 */
#define ESP_ENCR_KEY_BITS  256
```

## 服务端配置（strongSwan）

### `/etc/swanctl/swanctl.conf`

```hcl
connections {
    ipsec_client {
        version    = 2
        proposals  = aes256-sha256-modp2048

        local {
            auth  = psk
            id    = server@ipsec.local
        }

        remote {
            auth  = psk
            id    = client@ipsec.local
        }

        children {
            net {
                local_ts  = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256
                mode      = tunnel
            }
        }
    }
}

secrets {
    ike_psk {
        id     = client@ipsec.local
        secret = supersecretkey123
    }
}
```

### 启动 strongSwan

```bash
# 安装
sudo apt-get install strongswan strongswan-swanctl

# 启动
sudo systemctl start strongswan
sudo swanctl --load-all

# 启动 HTTP 测试服务器
python3 -m http.server 80 &
```

### 防火墙规则（服务端）

```bash
# 允许 IKE 流量（UDP 500）
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# 允许 ESP 协议
sudo iptables -A INPUT -p esp -j ACCEPT

# 允许 HTTP
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

## 工作流程

```
客户端                                    服务端 (strongSwan)
  |                                              |
  |  ---(IKE_SA_INIT req: SA+KE+Ni)----------->|
  |  <--(IKE_SA_INIT resp: SA+KE+Nr)------------|
  |                                              |
  |  [派生 SKEYSEED, SK_d, SK_ei, SK_er ...]    |
  |                                              |
  |  ---(IKE_AUTH req: SK{IDi,AUTH,SA,TS})----->|
  |  <--(IKE_AUTH resp: SK{IDr,AUTH,SA,TS})-----|
  |                                              |
  |  [安装 XFRM SA/Policy 到 Linux 内核]        |
  |                                              |
  |  ===(TCP: HTTP GET / 经 ESP 隧道加密)======>|
  |  <==(TCP: HTTP 200 OK 经 ESP 解密)===========|
```

## 协议细节

### IKE_SA_INIT 密钥派生

```
SKEYSEED = PRF(Ni | Nr, g^ir)
{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
    = PRF+(SKEYSEED, Ni | Nr | SPIi | SPIr)
```

### IKE_AUTH PSK 认证

```
AUTH_i = PRF(PRF(PSK, "Key Pad for IKEv2"),
             msg1 | Nr | PRF(SK_pi, IDi_data))
AUTH_r = PRF(PRF(PSK, "Key Pad for IKEv2"),
             msg2 | Ni | PRF(SK_pr, IDr_data))
```

### Child SA 密钥派生

```
KEYMAT = PRF+(SK_d, Ni | Nr)
→ SK_ei (ESP 加密, 发起方→响应方)
→ SK_ai (ESP 完整性, 发起方→响应方)
→ SK_er (ESP 加密, 响应方→发起方)
→ SK_ar (ESP 完整性, 响应方→发起方)
```

## 注意事项

1. **必须以 root 运行**：XFRM 操作和绑定 UDP 500 需要 root 权限
2. **端口冲突**：若系统已运行 strongSwan/racoon，需先停止它们（`systemctl stop strongswan`）
3. **防火墙**：确保客户端可以发送/接收 UDP 500（IKE）和 ESP（IP 协议 50）流量
4. **内核要求**：Linux 2.6+ 内核，支持 CONFIG_XFRM、CONFIG_CRYPTO_AES、CONFIG_CRYPTO_SHA256
5. **调试**：设置环境变量 `IPSEC_DEBUG=1` 可输出密钥材料用于调试

## 许可证

MIT License

---

**参考文档：**
- [RFC 7296 - IKEv2](https://tools.ietf.org/html/rfc7296)
- [RFC 4303 - ESP](https://tools.ietf.org/html/rfc4303)
- [RFC 3526 - MODP Groups](https://tools.ietf.org/html/rfc3526)
- [strongSwan 源码](https://github.com/strongswan/strongswan)
- [Linux XFRM 文档](https://www.kernel.org/doc/html/latest/networking/xfrm_proc.html)
