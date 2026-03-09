package cisco_secure_email_and_web_manager_firmware

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

type CiscoSmaZeusDetector struct {
	httpClient protocols.HTTPClient
}

func NewCiscoSmaZeusDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &CiscoSmaZeusDetector{httpClient: httpClient}
}

func (d *CiscoSmaZeusDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
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

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             baseURL,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         30 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    10,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送请求
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", nil
	}
	// 使用正则表达式匹配版本信息
	re := regexp.MustCompile(`<p\s+class=["']text_login_version["']>\s*Version:\s*([\d\.]+-[\d]+)\s*</p>`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", nil
}
