# OpenQGL

OpenQGL 是由 **热土工作室** 开发的开源 Minecraft 启动器，基于 [Wails v2](https://wails.io) + Vue 3 构建。

- 开源协议：Apache License 2.0
- 版本：OpenQGL 1-RC

---

## 目录

- [环境要求](#环境要求)
- [构建命令](#构建命令)
- [上线前必须修改的内容](#上线前必须修改的内容)
  - [1. 加密逻辑（重要）](#1-加密逻辑重要)
  - [2. 正版账号 Client ID](#2-正版账号-client-id)
- [开源协议说明](#开源协议说明)
- [许可证](#许可证)

---

## 环境要求

- Go 1.23+
- Node.js 16+
- Wails CLI v2.11.0+（安装：`go install github.com/wailsapp/wails/v2/cmd/wails@latest`）
- Windows 系统

---

## 构建命令

```bash
# 安装前端依赖（首次构建需要）
cd frontend && npm install && cd ..

# 开发模式（热重载）
wails dev

# 构建生产版本（输出到 build/bin 目录）
wails build
```

---

## 上线前必须修改的内容

> 以下内容在开源版中已做简化或留空，**如果你的产品需要上线，必须自行修改为更安全的实现**。

### 1. 加密逻辑（重要）

开源版中，微软账号认证数据（`ms_auth.json`）和外置账号认证数据使用 AES-GCM 加密存储。当前加密密钥的生成逻辑已简化：

- 文件位置：`auth.go`
- 函数：`getEncryptionKey(username string) []byte`（约第 64 行）
- 当前逻辑：根据 `用户名 + "OQL"` 生成 32 字节 AES 密钥

源码中已添加警告注释：

```go
//为了防止加密逻辑被获取，加密逻辑已更改简化，如果你的产品需要上线必须修改逻辑为更安全的!!!!!!!
// getEncryptionKey 根据用户名+OQL生成 32 字节 AES 密钥
func getEncryptionKey(username string) []byte {
    raw := username + "OQL"
    ...
}
```

**上线前必须将此逻辑替换为更安全的密钥派生方案**，例如：
- 使用 PBKDF2 / Argon2 / scrypt 等标准 KDF 函数
- 引入设备指纹、随机盐值等不可预测因素
- 不要使用简单的字符串拼接 + 异或混合

> 注意：修改加密逻辑后，已存储的旧认证数据将无法解密，用户需重新登录。

### 2. 正版账号 Client ID

开源版中已移除微软 OAuth 的 Client ID，正版登录功能不可用，需手动添加。

- 文件位置：`auth.go`（第 24 行）
- 需要修改的常量：

```go
const (
    oauthClientID = "" //修改为你的client id
    ...
)
```

**获取 Client ID 的步骤：**

1. 前往 [Azure 门户](https://portal.azure.com/) → Azure Active Directory → 应用注册
2. 注册一个新应用，账户类型选择「个人 Microsoft 账户」
3. 添加重定向 URI（可选，设备代码流程不需要）
4. 在「证书和密码」中获取 Application (client) ID
6. 提交申请至 [Minecraft AppID Review](https://forms.office.com/Pages/ResponsePage.aspx?id=v4j5cvGGr0GRqy180BHbR-ajEQ1td1ROpz00KtS8Gd5UNVpPTkVLNFVROVQxNkdRMEtXVjNQQjdXVC4u)
5. 将获取的 ID 填入 `auth.go` 的 `oauthClientID` 常量

> Client ID 属于公开标识符，不构成机密信息，但请遵守 [Microsoft 服务协议](https://www.microsoft.com/servicesagreement)。

---

## 开源协议说明

启动器「关于」页面的「开源协议」按钮（LicensePage）中展示了项目引用的第三方组件协议：

- **PCL CE Mod 翻译对照表**
  - 版权归属：(c) 龙腾猫跃
  - 来源链接：https://github.com/PCL-Community/PCL-CE
  - 许可证：Apache License 2.0
  - 用途说明：用于为「Mod 中文搜索」功能提供支持

LicensePage 组件位置：`frontend/src/components/LicensePage.vue`

---

## 许可证

本项目基于 **Apache License 2.0** 开源。

```
Copyright 2026 热土工作室 (RTStudio)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

完整许可证文本请见：http://www.apache.org/licenses/LICENSE-2.0
