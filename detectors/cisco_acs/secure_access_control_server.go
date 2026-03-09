package cisco_acs

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// ACSDetector 是版本检测器
type ACSDetector struct {
	httpClient protocols.HTTPClient
}

// NewACSDetector 创建一个新的版本检测器
func NewACSDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &ACSDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *ACSDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 修改访问路径
	targeturl := strings.TrimRight(target, "/")

	//创建 GET 请求
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targeturl,
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
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 使用正则表达式提取版本信息
	var versionRegex = regexp.MustCompile(`ACS([\d.]+)<`)
	matches := versionRegex.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		version := matches[1]
		return version, nil
	}

	return "", nil
}
