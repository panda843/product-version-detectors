package sophosvpnportal

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

type SophosVPNPortalDetector struct {
	httpClient protocols.HTTPClient
}

func NewSophosVPNPortalDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &SophosVPNPortalDetector{httpClient: httpClient}
}

func (d *SophosVPNPortalDetector) Detect(ctx context.Context, cnvendor, vendor, target string) (string, error) {
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
	baseURL = strings.TrimRight(baseURL, "/")

	// 构造完整URL
	targetURL := baseURL + "/themes/lite1/css/myaccount.css"

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "",
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
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	// 正则表达式匹配版本号
	re := regexp.MustCompile(`background\s*:\s*url\(\s*[^\)]*?\?a=([\w\.]+)`)
	matches := re.FindSubmatch(resp.Body)
	if matches == nil {
		return "", nil
	}

	// 返回版本号
	return string(matches[1]), nil
}
