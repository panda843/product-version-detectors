package mikrotik_routeros

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

type RouterOSDetector struct {
	httpClient protocols.HTTPClient
}

func NewRouterOSDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &RouterOSDetector{httpClient: httpClient}
}

func (d *RouterOSDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 检查是否带有协议前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// 构造完整URL
	targetURL := strings.TrimRight(baseURL, "/") + "/webfig/roteros.info"

	// 创建 HTTP 请求配置
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
	re := regexp.MustCompile(`(?i)"?version"?\s*:\s*"?([\w\d._-]+)`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", nil
}
