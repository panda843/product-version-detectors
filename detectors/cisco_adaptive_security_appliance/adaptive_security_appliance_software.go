package cisco_adaptive_security_appliance

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

type CiscoASADetector struct {
	httpClient protocols.HTTPClient
}

func NewCiscoASADetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &CiscoASADetector{httpClient: httpClient}
}

func (d *CiscoASADetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
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

	// 从管理端口检查版本
	version, err := d.CheckManagerVersion(ctx, baseURL)
	if err != nil || version == "" {
		// 从vpn口检查
		version, err = d.CheckVPNVersion(ctx, baseURL)
		if version == "" {
			return "", nil
		}
	}

	return version, nil
}

// 管理端口获取版本
func (d *CiscoASADetector) CheckManagerVersion(ctx context.Context, baseURL string) (string, error) {

	// 构造完整URL
	targetURL := strings.TrimRight(baseURL, "/") + "/admin/public/index.html"

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
		return "", err
	}

	// 使用正则表达式匹配版本信息
	re := regexp.MustCompile(`Cisco ASDM\s+(\d+\.\d+)`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", nil
}

// vpn获取版本
func (d *CiscoASADetector) CheckVPNVersion(ctx context.Context, baseURL string) (string, error) {
	// 构造请求体
	reqBody := []byte(`TESTME`)

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "POST",
		URL:             baseURL,
		Data:            reqBody,
		Headers:         make(http.Header),
		Timeout:         30 * time.Second,
		ContentType:     "application/x-www-form-urlencoded",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 设置请求头
	req.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Headers.Set("X-Aggregate-Auth", "1")
	req.Headers.Set("Connection", "close")
	req.Headers.Set("Accept", "*/*")

	// 发送请求
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}

	// 使用正则表达式匹配版本信息
	re := regexp.MustCompile(`<version who="sg">([^<]+)</version>`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", nil
}
