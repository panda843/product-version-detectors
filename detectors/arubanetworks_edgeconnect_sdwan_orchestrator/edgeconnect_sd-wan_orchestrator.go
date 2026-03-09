package arubanetworks_edgeconnect_sdwan_orchestrator

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

type ArubaEdgeConnectSDWANDetector struct {
	httpClient protocols.HTTPClient
}

func NewArubaEdgeConnectSDWANDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &ArubaEdgeConnectSDWANDetector{httpClient: httpClient}
}

func (d *ArubaEdgeConnectSDWANDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 检查是否带有协议前缀
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
	targetURL := strings.TrimRight(baseURL, "/") + "/gms/rest/gmsserver/ping"

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
	re := regexp.MustCompile(`"version":"([\d\.]+)"`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return getMainVersion(matches[1]), nil
	}

	return "", nil // 没有找到版本信息
}

// 从完整版本号中提取主要版本部分
func getMainVersion(fullVersion string) string {
	parts := strings.Split(fullVersion, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}
	return fullVersion // 如果不足3部分，返回原字符串
}
