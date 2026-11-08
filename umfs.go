package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// UMFS (Ultra Mersenne Fractal Sponge) — 与 bool-hybrid-array core.py 对齐。
// M = 2^2281 - 1（梅森素数），十阶模幂 + 海绵结构。
var (
	umfsM   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2281), big.NewInt(1))
	umfsE1  = big.NewInt(11)
	umfsE2  = big.NewInt(13)
	umfsE3  = big.NewInt(17)
	umfsE4  = big.NewInt(19)
	umfsE5  = big.NewInt(23)
	umfsE6  = big.NewInt(29)
	umfsE7  = big.NewInt(31)
	umfsE8  = big.NewInt(37)
	umfsE9  = big.NewInt(41)
	umfsE10 = big.NewInt(43)
	umfsIVR = big.NewInt(0x2957A2F168CC3509)
	umfsIVC = big.NewInt(0x71D39E40BB72A61F)
	umfsC1  = big.NewInt(0x19260817)
	umfsC2  = big.NewInt(0x114514)
	umfsC3  = big.NewInt(0xABCDEF)
	umfsC4  = big.NewInt(0x233333)
	umfsC5  = big.NewInt(0x666666)
	umfsC6  = big.NewInt(0x123456789)
	umfs210 = big.NewInt(210)
	umfs7   = big.NewInt(7)
	umfs3   = big.NewInt(3)
)

const umfsBlockSize = 8

// maxRedirects 单次请求最多跟 5 次跳转，超过就报错。
// 防止 CDN 被劫持后用无限跳转拖死启动。
const maxRedirects = 5

// isPrivateDest 报告 URL 指向的主机是不是内网/回环/链路本地地址。
// 启动器只该访问公网镜像和 Mojang，不应该被诱导去读 169.254.169.254
// （云元数据）或 127.0.0.1:本地端口。
func isPrivateDest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	// 用更宽的 IP 字面量解析器，连十六进制/八进制/扁平整数/IPv4-mapped
	// IPv6 等非规范写法一并在字符串态识别，防止绕过内网拦截。
	if ip, ok := parseDestIP(host); ok {
		return isBlockedIP(ip)
	}
	// 没解析成 IP 字面量的（域名），交给 DNS，不在这里拦；
	// 真正解析到内网的边缘情况由 net.Dialer 侧再兜一次。
	return false
}

// isBlockedIP 报告 IP 是否属于不该被启动器主动连出的地址段。判定表统一收敛到
// ipparse.go 的 isNonPublicIP，与浏览器打开 / 短链 / 重定向共用同一份最严策略，
// 覆盖回环、RFC1918 私网、CGNAT、链路本地（含云元数据 169.254.169.254）、未指定、
// 0.0.0.0/8 “本网络”段，以及此前漏掉的整段 224/4 多播（如 SSDP 239.255.255.250）
// 与 240/4 保留段（含 255.255.255.255 有限广播）。
func isBlockedIP(ip net.IP) bool {
	return isNonPublicIP(ip)
}

// safeDialContext 在 TCP 建连前再做一次 IP 级拦截。
// isPrivateDest 只能拦字符串形态的内网地址；公网域名通过自托管 DNS 解析到
// 127.0.0.1 / 169.254.169.254（DNS rebinding）时字符串看不出来，必须在这里兜：
// 先自行解析、逐个候选 IP 校验，全部非法则拒绝建连。
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// 主机本身就是 IP 字面量时（含非规范进制 / IPv4-mapped 写法），直接按
	// 规范化地址判定并建连，不再交给 resolver：不同平台 resolver 对
	// "2130706433"、"0x7f.1" 这类写法行为不一致，先归一化可彻底消除歧义。
	if ip, ok := parseDestIP(host); ok {
		if isBlockedIP(ip) {
			return nil, errDenyPrivateRedirect
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			lastErr = errDenyPrivateRedirect
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errDenyPrivateRedirect
	}
	return nil, lastErr
}

// safeCheckRedirect 是 http.Client.CheckRedirect 的实现：
//   - 只允许跳 https://（除非原地 http→http，且我们本来就只发 https）；
//   - 拒绝跳内网/回环/链路本地；
//   - 最多 maxRedirects 次。
func safeCheckRedirect(requ *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	next := requ.URL
	if !isHTTPSURL(next.String()) {
		return errDenyInsecureRedirect
	}
	if isPrivateDest(next.String()) {
		return errDenyPrivateRedirect
	}
	return nil
}

var (
	errDenyInsecureRedirect = &url.Error{Op: "Get", URL: "", Err: errText("redirect to non-HTTPS blocked")}
	errDenyPrivateRedirect  = &url.Error{Op: "Get", URL: "", Err: errText("redirect to private/loopback address blocked")}
)

type errText string

func (e errText) Error() string { return string(e) }

// safeHTTPClient 创建安全的 HTTP 客户端：
//   - TLS 1.2+；
//   - 30 秒总超时（API JSON 够用，大文件走带 MaxBytesReader 的专用路径）；
//   - 跳转策略：只跟 https→https，且不跳内网。
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			DialContext: safeDialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			// 单连接复用池上限别太大，避免在用户机器上占一堆 TIME_WAIT
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// localHTTPClient 与 safeHTTPClient 相同，但不在 Dial 层拦截私网地址。
// 仅限用户主动配置的 Yggdrasil 外置登录服务器使用——本地调试皮肤站就是
// 跑在 127.0.0.1 / 局域网的 http 服务，这是用户显式指定的可信目标。
// 绝不能用于任何由远程元数据给出来的 URL。
func localHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

func umfsMod(x *big.Int) *big.Int {
	return new(big.Int).And(x, umfsM)
}

func umfsPow(x, e *big.Int) *big.Int {
	return new(big.Int).Exp(x, e, umfsM)
}

// tenthOrderMapping 十阶模幂置换
func tenthOrderMapping(x *big.Int) *big.Int {
	p1 := umfsPow(x, umfs210)
	p2 := umfsPow(umfs210, x)
	p3 := umfsPow(x, x)
	x = umfsMod(new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(p1, p2), p3), big.NewInt(1)))

	x = new(big.Int).Xor(umfsPow(x, umfsE1), umfsC1)
	x = umfsMod(new(big.Int).Add(umfsPow(x, umfsE2), umfsC2))

	xShr := umfsMod(new(big.Int).Rsh(x, 18))
	xShl := umfsMod(new(big.Int).Lsh(x, 9))
	x = new(big.Int).Xor(new(big.Int).Xor(umfsPow(x, umfsE3), xShr), xShl)

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE4), umfsC3))
	x = new(big.Int).Xor(umfsPow(x, umfsE5), umfsMod(new(big.Int).Lsh(x, 21)))
	x = new(big.Int).Xor(umfsPow(x, umfsE6), umfsC4)
	x = umfsMod(new(big.Int).Sub(umfsPow(x, umfsE7), umfsC6))

	xS12 := umfsMod(new(big.Int).Rsh(x, 12))
	xS15 := umfsMod(new(big.Int).Lsh(x, 15))
	x = new(big.Int).Xor(umfsPow(x, umfsE8), new(big.Int).And(xS12, xS15))

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE9), umfsC6))
	x = new(big.Int).Xor(umfsPow(x, umfsE10), umfsMod(new(big.Int).Lsh(x, 33)))

	return new(big.Int).Mod(x, umfsM)
}

type UMFS struct {
	r        *big.Int
	c        *big.Int
	totalLen int
	dataPool []*big.Int
	pending  bytes.Buffer
}

func NewUMFS(data []byte) *UMFS {
	u := &UMFS{
		r:        new(big.Int).Set(umfsIVR),
		c:        new(big.Int).Set(umfsIVC),
		totalLen: 0,
		dataPool: make([]*big.Int, 0),
	}
	if len(data) > 0 {
		u.pending.Write(data)
	}
	return u
}

// Absorb 与 bool-hybrid-array core.py UltraMersenneFractalSponge.absorb 对齐：
// 数据不是整段转成一个大整数，而是按 step = n // bitlen(n) 切块，逐块转大整数
// 入池并更新海绵状态。旧实现把整段当一个大整数吸收，切块粒度与上游不一致，
// 会让任何长度超过单块的数据得到与 Python 生态不同的摘要。
func (u *UMFS) Absorb(data []byte) *UMFS {
	n := len(data)
	if n == 0 {
		return u
	}
	u.totalLen += n
	step := n / bits.Len(uint(n))
	for i := 0; i < n; i += step {
		j := i + step
		if j > n {
			j = n
		}
		num := new(big.Int).SetBytes(data[i:j])
		u.dataPool = append(u.dataPool, num)
		u.r = tenthOrderMapping(new(big.Int).Xor(u.r, num))
		// term = (num^7 mod M * r) mod M，这里必须是模 M，不能用按位与近似。
		term := new(big.Int).Mod(new(big.Int).Mul(umfsPow(num, umfs7), u.r), umfsM)
		// Python 表达式 self.c = (self.c ^ self.r + term) % M 中，'+' 优先级
		// 高于 '^'，真实含义是 c ^ (r + term)，而非 (c ^ r) + term。
		u.c = new(big.Int).Mod(new(big.Int).Xor(u.c, new(big.Int).Add(u.r, term)), umfsM)
	}
	return u
}

func (u *UMFS) flushPending() {
	if u.pending.Len() > 0 {
		u.Absorb(u.pending.Bytes())
		u.pending.Reset()
	}
}

func (u *UMFS) foldRecursive(arr []*big.Int) *big.Int {
	if len(arr) <= 2 {
		res := big.NewInt(0)
		for _, v := range arr {
			res = new(big.Int).Mod(new(big.Int).Add(res, tenthOrderMapping(new(big.Int).Xor(v, res))), umfsM)
		}
		return res
	}
	mid := len(arr) >> 1
	left := u.foldRecursive(arr[:mid])
	right := u.foldRecursive(arr[mid:])
	l3 := umfsPow(left, umfs3)
	r3 := umfsPow(right, umfs3)
	// Python：cross = (left*right ^ l3 + r3) % M。'+' 优先级高于 '^'，
	// 真实含义是 (l*r) ^ (l3+r3)，旧实现误写成 ((l*r)^l3)+r3。
	cross := new(big.Int).Mod(
		new(big.Int).Xor(new(big.Int).Mul(left, right), new(big.Int).Add(l3, r3)),
		umfsM)
	return tenthOrderMapping(cross)
}

func (u *UMFS) HexDigest(bitn int) string {
	u.flushPending()
	if bitn <= 0 || bitn > 4562 {
		bitn = 256
	}

	len3 := umfsPow(big.NewInt(int64(u.totalLen)), umfs3)
	u.r = new(big.Int).Xor(u.r, len3)
	u.c = new(big.Int).Mod(new(big.Int).Add(u.c, new(big.Int).Mul(len3, u.r)), umfsM)

	foldVal := u.foldRecursive(u.dataPool)
	u.r = new(big.Int).Mod(new(big.Int).Xor(u.r, foldVal), umfsM)

	for i := 0; i < 10; i++ {
		u.r = tenthOrderMapping(u.r)
		u.c = tenthOrderMapping(u.c)
		r3 := umfsPow(u.r, umfs3)
		c3 := umfsPow(u.c, umfs3)
		// Python：cross = (r3 ^ c3 + r*c) % M，'+' 优先级高于 '^'，
		// 真实含义是 r3 ^ (c3 + r*c)，旧实现误写成 (r3^c3)+(r*c)。
		cross := new(big.Int).Mod(
			new(big.Int).Xor(r3, new(big.Int).Add(c3, new(big.Int).Mul(u.r, u.c))),
			umfsM)
		oldR := new(big.Int).Set(u.r)
		u.r = new(big.Int).Mod(cross, umfsM)
		u.c = new(big.Int).Mod(new(big.Int).Xor(cross, oldR), umfsM)
	}

	shift := bitn - 2281
	if shift < 0 {
		shift = 0
	}
	res := new(big.Int).Xor(new(big.Int).Lsh(u.r, uint(shift)), u.c)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bitn)), big.NewInt(1))
	res.And(res, mask)

	hexLen := (bitn + 3) / 4
	hexStr := res.Text(16)
	for len(hexStr) < hexLen {
		hexStr = "0" + hexStr
	}
	return hexStr
}

func (u *UMFS) Digest() []byte {
	hx := u.HexDigest(256)
	b, _ := hex.DecodeString(hx)
	return b
}

func umfsHash(data []byte) string {
	return NewUMFS(data).HexDigest(256)
}

type UMFSHash struct {
	umfs *UMFS
}

func NewUMFSHash() *UMFSHash {
	return &UMFSHash{umfs: NewUMFS(nil)}
}

func (h *UMFSHash) Write(p []byte) (n int, err error) {
	h.umfs.pending.Write(p)
	return len(p), nil
}

func (h *UMFSHash) Sum(in []byte) []byte {
	savedR := new(big.Int).Set(h.umfs.r)
	savedC := new(big.Int).Set(h.umfs.c)
	savedLen := h.umfs.totalLen
	savedPool := append([]*big.Int{}, h.umfs.dataPool...)
	savedPending := make([]byte, h.umfs.pending.Len())
	copy(savedPending, h.umfs.pending.Bytes())

	result := h.umfs.Digest()

	h.umfs.r = savedR
	h.umfs.c = savedC
	h.umfs.totalLen = savedLen
	h.umfs.dataPool = savedPool
	h.umfs.pending.Reset()
	h.umfs.pending.Write(savedPending)

	return append(in, result...)
}

func (h *UMFSHash) Reset() {
	h.umfs = NewUMFS(nil)
}

func (h *UMFSHash) Size() int      { return 32 }
func (h *UMFSHash) BlockSize() int { return umfsBlockSize }

func generateUMFSToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return umfsHash(b)
	}
	return umfsHash(b)
}

var _ hash.Hash = (*UMFSHash)(nil)

// ===== 文件完整性校验辅助 =====

// sha512File 计算文件 SHA-512
func sha512File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// umfsFile 流式计算文件 UMFS-256 十六进制摘要（bool-hybrid-array 生态）。
// 注意：UMFS 是整块吸收的海绵，这里把文件分块喂给 hash.Hash 接口的 Write，
// 在 Sum 时一次性 squeeze，与 Python 版对整文件 hexdigest 等价。
func umfsFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewUMFSHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
