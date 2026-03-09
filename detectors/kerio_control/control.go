package kerio_control

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

type KerioDetector struct {
	httpClient protocols.HTTPClient
}

func NewKerioDetecto(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &KerioDetector{httpClient: httpClient}
}

func (d *KerioDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有指定协议，默认添加 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// 构造完整请求 URL
	targetURL := baseURL + "/admin/weblib/int/webAssist/webAssist.js"

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

	// 提取版本信息
	re := regexp.MustCompile(`this\.k_version\s*=\s*['"]([^'"]+)['"]`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return getMainVersion(strings.TrimSpace(matches[1])), nil
	}

	return "", nil
}

func getMainVersion(fullVersion string) string {
	// 先按连字符分割
	parts := strings.SplitN(fullVersion, "-", 2)
	versionPart := parts[0]

	// 再按点号分割提取主要版本
	dotParts := strings.Split(versionPart, ".")
	if len(dotParts) >= 3 {
		return strings.Join(dotParts[:3], ".")
	}
	return versionPart
}
