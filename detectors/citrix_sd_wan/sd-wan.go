package citrix_sd_wan

import (
	"context"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SDWanDetector 是版本检测器
type SDWanDetector struct {
	httpClient protocols.HTTPClient
}

// NewSDWanDetector 创建一个新的版本检测器
func NewSDWanDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &SDWanDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *SDWanDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	url := strings.TrimRight(target, "/") + "/cgi-bin/login.cgi"

	// 创建 GET 请求，
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             url,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 执行请求并接收响应
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	var configRegex = regexp.MustCompile(`R\d+_\d+_\d+_\d+_\d+`)
	version := configRegex.FindString(string(resp.Body))
	if version != "" {
		return getMainVersion(version), nil
	}

	return "", nil
}

// 提取主要版本号
func getMainVersion(versionDesc string) string {
	if !strings.HasPrefix(versionDesc, "R") {
		return versionDesc
	}

	parts := strings.Split(versionDesc[1:], "_")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}

	return versionDesc // 如果不足3部分，返回原字符串
}
