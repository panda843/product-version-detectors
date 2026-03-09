package barracuda_cloudgen_firewall

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// NGFWDetector 是版本检测器
type NGFWDetector struct {
	httpClient protocols.HTTPClient
}

// NewNGFWDetector 创建一个新的版本检测器
func NewNGFWDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &NGFWDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *NGFWDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 构造请求的完整URL，固定访问/cgi-mod/index.cgi路径
	targetURL := target + "/cgi-mod/index.cgi"

	// 创建 HTTP 请求，跳过 TLS 验证并设置超时
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 提取版本信息并输出结果
	version := exInstalledVersion(string(resp.Body))
	if version != "" {
		return version, nil
	}

	return "", nil
}

// exInstalledVersion 从HTML内容中提取版本信息
// 使用正则表达式匹配<meta http-equiv="Content-Version">标签
// 返回匹配到的版本号，如果未找到则返回"version not found"
func exInstalledVersion(html string) string {
	re := regexp.MustCompile(`<meta http-equiv="Content-Version" content="([^"]+)"\s*/>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		version := strings.TrimSpace(matches[1])
		// 提取主版本、次版本、修订号
		if len(version) >= 4 { // 确保字符串长度足够
			major := version[0:1] // 主版本（第1位）
			minor := version[1:2] // 次版本（第2位）
			patch := version[2:4] // 修订号（第3-4位）
			return fmt.Sprintf("%s.%s.%s", major, minor, patch)
		}
	}
	return ""
}
