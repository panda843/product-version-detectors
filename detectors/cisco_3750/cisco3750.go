package cisco3750

import (
	"bufio"
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

type Cisco3750Detector struct {
	tcpClient protocols.TCPClient
}

func NewCisco3750Detector(_ protocols.HTTPClient, tcpClient protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &Cisco3750Detector{tcpClient: tcpClient}
}

func (d *Cisco3750Detector) Detect(ctx context.Context, cnvendor, vendor, target string) (string, error) {
	// 去除协议前缀
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// 如果没有指定端口，添加默认端口 23
	if !strings.Contains(target, ":") {
		target = target + ":23"
	}

	// 构造 TCP 请求
	req := protocols.TURequest{
		Address:        target,
		Data:           nil,
		Timeout:        5 * time.Second,
		ReadBufferSize: 4096,
		MaxRetries:     2,
		RetryDelay:     1 * time.Second,
	}

	// 发送 TCP 请求
	resp, err := d.tcpClient.Do(ctx, req)
	if err != nil {
		return "", nil
	}

	// 解析响应
	scanner := bufio.NewScanner(strings.NewReader(string(resp.Body)))
	re := regexp.MustCompile(`Mobile Wifi Cisco 3750\((.*?)\)`)
	for scanner.Scan() {
		line := scanner.Text()
		// 检查是否包含目标字符串
		if matches := re.FindStringSubmatch(line); matches != nil {
			return matches[1], nil
		}
		// 如果遇到交互提示，停止读取
		if strings.Contains(line, "User Access Verification") {
			break
		}
	}

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return "", nil
	}

	return "", nil
}
