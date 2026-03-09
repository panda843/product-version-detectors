package cyberoamfirewall

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

type CyberoamFirewallDetector struct {
	httpClient protocols.HTTPClient
}

func NewCyberoamFirewallDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &CyberoamFirewallDetector{httpClient: httpClient}
}

func (d *CyberoamFirewallDetector) Detect(ctx context.Context, cnvendor, vendor, target string) (string, error) {
	// 如果没有前缀协议，自动添加 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	// 构造 base URL（仅保留 scheme 和 host），移除末尾斜杠
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	baseURL = strings.TrimRight(baseURL, "/")

	// 构造完整请求 URL
	targetURL := baseURL + "/css/wizard.css"

	// 设置请求头
	headers := make(http.Header)
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	headers.Set("Accept", "text/css,*/*;q=0.1")

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL,
		Data:            nil,
		Headers:         headers,
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
