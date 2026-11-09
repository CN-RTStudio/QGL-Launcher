package main

import "time"

const (
	oauthClientID = "" //修改为你的client id
	oauthScope    = "XboxLive.signin offline_access"

	// Microsoft OAuth endpoints
	deviceCodeURL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
	tokenURL      = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

	// Xbox Live endpoints
	xblAuthURL  = "https://user.auth.xboxlive.com/user/authenticate"
	xstsAuthURL = "https://xsts.auth.xboxlive.com/xsts/authorize"

	// Minecraft services endpoints
	mcLoginURL       = "https://api.minecraftservices.com/authentication/login_with_xbox"
	mcEntitlementURL = "https://api.minecraftservices.com/entitlements/mcstore"
	mcProfileURL     = "https://api.minecraftservices.com/minecraft/profile"

	// 安全加固: PBKDF2 参数
	pbkdf2Iterations = 100000
	pbkdf2KeyLength  = 32
	pbkdf2Salt       = "OpenQGL_Salt_2024!@#"

	// authJSONMaxBytes 限制每个认证 JSON 响应最多 1 MiB。
	// 认证接口本应返回小体量的 token 结构，超过这个尺寸基本就是恶意响应或错误页面。
	authJSONMaxBytes = 1 << 20

	// 设备码轮询参数。interval / expires_in 都来自微软的响应，不能无条件信任：
	// 被劫持或畸形的响应可以给个超大值，让轮询 goroutine 睡几个小时、或把登录
	// 有效期拉到几天。这里按官方正常范围（间隔 5s、设备码约 15min 失效）钳制。
	deviceCodeMinInterval = 5 * time.Second
	deviceCodeMaxInterval = 5 * time.Minute
	deviceCodeDefaultTTL  = 5 * time.Minute
	deviceCodeMaxTTL      = 15 * time.Minute
	// slow_down 要求每次间隔 +5s，但加多少次必须有上限，否则服务器一直回
	// slow_down 就能把这个 goroutine 无限期挂住。
	deviceCodeMaxSlowDowns = 60
	// 网络错误 / 429 / 5xx 属于瞬时故障，连续这么多次仍不恢复就放弃登录，
	// 而不是在后台无限重试。
	deviceCodeMaxTransientErrors = 8
	// token expires_in 的合理上限（一年）。正常 MSA/MC 令牌都是 24h，
	// 给极大值只会把过期时间写到未来很久，掩盖"该刷新了"的判断。
	tokenMaxLifetimeSeconds = 365 * 24 * 3600
	tokenDefaultLifetimeSec = 24 * 3600
)
