package sophos_unified_threat_management_software

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

type SophosUTMDetector struct {
	httpClient protocols.HTTPClient
}

func NewSophosUTMDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &SophosUTMDetector{httpClient: httpClient}
}

func (d *SophosUTMDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有指定协议 默认为https
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
	targetURL := baseURL + "/Webadmin"

	// 创建 HTTP 请求配置
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

	// 发送请求
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", nil
	}

	// 提取版本信息
	re := regexp.MustCompile(`"version"\s*:\s*"([\d.]+)"`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}

	return "", nil // 没有找到版本信息
}
