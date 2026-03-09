package barracudanextgenfirewallsslvpn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// JSON 响应格式
type AuthSettingResponse struct {
	APIVersion string `json:"apiVersion"`
}

type NEXTGENSSLVPNDetector struct {
	httpClient protocols.HTTPClient
}

func NewNextgensslvpnDetectorDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &NEXTGENSSLVPNDetector{httpClient: httpClient}
}

func (d *NEXTGENSSLVPNDetector) Detect(ctx context.Context, cnvendor, vendor, target string) (string, error) {
	// 如果没有前缀协议，自动添加 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	// 构造初始URL 移除末尾/
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	baseURL = strings.TrimRight(baseURL, "/")

	// 构造完整请求 URL
	targetURL := baseURL + "/sslvpn_api/authentication/setting"

	// 设置请求头
	headers := make(http.Header)
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0")
	headers.Set("Accept", "*/*")
	headers.Set("Connection", "close")

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

	// 解析 JSON 响应
	var authSetting AuthSettingResponse
	err = json.Unmarshal(resp.Body, &authSetting)
	if err != nil {
		return "", nil
	}

	// 返回版本号
	if authSetting.APIVersion != "" {
		return authSetting.APIVersion, nil
	}

	return "", nil
}
