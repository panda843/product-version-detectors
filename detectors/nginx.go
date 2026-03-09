package detectors

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/protocols"
)

// NginxDetector 是Nginx服务器的版本检测器
type NginxDetector struct {
	httpClient protocols.HTTPClient
}

// NewNginxDetector 创建一个新的Nginx版本检测器
func NewNginxDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) Detector {
	return &NginxDetector{httpClient: httpClient}
}

// Detect 检测Nginx服务器的版本
func (d *NginxDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 确保URL有协议前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req := protocols.HttpRequest{
		Method:          "",
		URL:             target,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         5 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送HEAD请求获取服务器头
	req.Headers.Add("User-Agent", "VersionDetector/1.0")
	req.Method = "HEAD"
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		// 如果HEAD失败，尝试GET
		req.Method = "GET"
		resp, err = d.httpClient.Do(ctx, req)

		if err != nil {
			return "", err
		}
	}

	// 检查Server头
	serverHeaders, ok := resp.Headers["Server"]
	if !ok || len(serverHeaders) == 0 {
		return "", nil // 没有Server头，返回空版本
	}

	serverHeader := serverHeaders[0]

	// 提取Nginx版本
	if strings.Contains(serverHeader, "nginx") {
		parts := strings.Split(serverHeader, "/")
		if len(parts) > 1 {
			versionParts := strings.Split(parts[1], " ")
			return versionParts[0], nil
		}
	}

	return "", nil // 不是Nginx服务器
}
