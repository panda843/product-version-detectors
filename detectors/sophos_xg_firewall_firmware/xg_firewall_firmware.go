package sophos_xg_firewall_firmware

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

type SophosXGFirewallDetector struct {
	httpClient protocols.HTTPClient
}

func NewSophosXGFirewallDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &SophosXGFirewallDetector{httpClient: httpClient}
}

func (d *SophosXGFirewallDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有前缀协议，自动添加 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	// 构造初始URL
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// 构造完整URL
	targetURL := strings.TrimRight(baseURL, "/") + "/userportal/webpages/myaccount/login.jsp"

	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         5 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送请求
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", nil
	}

	// 使用正则表达式匹配版本信息
	re := regexp.MustCompile(`/javascript/validation/OEM\.js\?ver=([\d\.]+)`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return getMainVersion(matches[1]), nil
	}

	return "", nil
}

// 从完整版本号中提取主要版本部分
func getMainVersion(fullVersion string) string {
	parts := strings.Split(fullVersion, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[:2], ".")
	}
	return fullVersion // 如果不足2部分，返回原字符串
}
