package juniper_junos

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

type JuniperDetector struct {
	httpClient protocols.HTTPClient
}

func NewJuniperDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &JuniperDetector{httpClient: httpClient}
}

func (d *JuniperDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 检查是否带有协议前缀
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// 构造完整请求 URL
	targetURL := strings.TrimRight(baseURL, "/") + "/assets/js/conf/global_config.js"

	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         5 * time.Second,
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

	// 使用正则表达式匹配版本信息
	re := regexp.MustCompile(`jweb-(srx[\d\.]+)|jweb([\d\.]+)`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 0 {
		// 提取匹配到的内容，优先取第一个非空匹配组
		version := ""
		if matches[1] != "" {
			// 去掉前缀
			version = strings.TrimPrefix(matches[1], "srx")
		} else if matches[2] != "" {
			version = matches[2]
		}
		return version, nil
	}

	return "", nil
}
