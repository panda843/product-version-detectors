package cisco_identity_services_engine_software

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// CiscoISEDetector 是版本检测器
type CiscoISEDetector struct {
	httpClient protocols.HTTPClient
}

// NewCiscoISEDetector 创建一个新的版本检测器
func NewCiscoISEDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &CiscoISEDetector{httpClient: httpClient}
}

// Detect 检测版本并处理ETag值
// Detect 检测版本并处理ETag值
func (d *CiscoISEDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 拼接访问路径
	urls := []string{
		strings.TrimRight(target, "/") + "/errimgs/cisco-logo.svg",
		strings.TrimRight(target, "/") + "/errimgs/error-image.svg",
		strings.TrimRight(target, "/") + "/errimgs/favicon.ico",
	}

	var timestamp int64
	found := false

	// 遍历URL列表发送请求
	for _, url := range urls {
		// 创建HEAD请求获取响应头
		req := protocols.HttpRequest{
			Method:          "GET",
			URL:             url,
			Data:            "",
			Headers:         make(http.Header),
			Timeout:         10 * time.Second,
			FollowRedirects: true,
		}

		// 发送请求
		resp, err := d.httpClient.Do(ctx, req)
		if err != nil {
			continue // 忽略错误，继续尝试其他URL
		}
		if resp.Err != nil {
			continue
		}

		// 从响应头中提取ETag
		etag := resp.Headers.Get("ETag")
		if etag == "" {
			continue
		}

		// 处理ETag值
		processed, err := processETag(etag)
		if err != nil {
			continue
		}

		// 提取时间戳
		ts, err := extractTimestamp(processed)
		if err != nil {
			continue
		}

		// 记录第一个有效的时间戳
		if !found {
			timestamp = ts
			found = true
		}
	}

	if !found {
		return "", errors.New("未能从任何URL获取有效的ETag时间戳")
	}

	// 返回格式化的时间
	return time.Unix(timestamp, 0).UTC().Format("2006-01-02"), nil
}

// 处理ETag值: 去除引号 -> 分割 -> 十六进制转十进制
func processETag(etag string) (string, error) {
	// 去除可能存在的引号
	etag = strings.Trim(etag, "\"")

	// 按'-'分割
	parts := strings.Split(etag, "-")
	if len(parts) < 1 {
		return "", errors.New("ETag格式错误")
	}

	// 转换第一部分(时间戳部分)
	timestampHex := parts[0]
	return timestampHex, nil
}

// 提取并转换时间戳
func extractTimestamp(hexTime string) (int64, error) {
	return strconv.ParseInt(hexTime, 16, 64)
}
