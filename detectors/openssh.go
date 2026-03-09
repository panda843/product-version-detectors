package detectors

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"strings"
	"time"
)

// SSHDetector 是SSH服务器的版本检测器
type SSHDetector struct {
	tcpClient protocols.TCPClient
}

// NewSSHDetector 创建一个新的SSH版本检测器
func NewSSHDetector(_ protocols.HTTPClient, tcpClient protocols.TCPClient, _ protocols.UDPClient) Detector {
	return &SSHDetector{
		tcpClient: tcpClient,
	}
}

// Detect 检测SSH服务器的版本
func (d *SSHDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 构建 TCP 连接请求
	req := protocols.TURequest{
		Method: "TCP", Address: target, Timeout: 5 * time.Second,
	}
	// 执行 TCP 请求并获取响应
	resp, err := d.tcpClient.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("连接 SSH 服务器失败: %w", err)
	}
	// 检查响应错误
	if resp.Err != nil {
		return "", fmt.Errorf("SSH 服务器响应错误: %w", resp.Err)
	}

	// 转换响应体为字符串
	bodyStr := string(resp.Body)

	// 按行分割响应内容
	lines := strings.Split(bodyStr, "\n")

	// 遍历每一行，查找 SSH 版本标识
	for _, line := range lines {
		// 检查是否为 SSH 版本行（格式应为 "SSH-协议版本-软件版本"）
		if strings.HasPrefix(line, "SSH-") {
			// 按 "-" 分割字符串，期望得到 3 部分
			parts := strings.SplitN(line, "-", 3)
			if len(parts) >= 3 {
				// 进一步处理软件版本部分，例如 "OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
				softwareParts := strings.SplitN(parts[2], "_", 2)
				if len(softwareParts) >= 2 {
					// 处理包含版本号和额外信息的情况，如 "8.2p1 Ubuntu-4ubuntu0.3"
					versionParts := strings.FieldsFunc(softwareParts[1], func(r rune) bool {
						return r == ' ' || r == '\t' || r == '-'
					})
					if len(versionParts) > 0 {
						return versionParts[0], nil // 返回第一个部分，即主要版本号
					}
				}
				// 如果没有下划线或无法进一步分割，直接返回原始软件版本部分
				return parts[2], nil
			}
		}
	}

	return "", nil // 无法解析版本
}
