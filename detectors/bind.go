package detectors

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"strings"
	"time"
)

// BindDetector 是BIND版本探测器的结构体
type BindDetector struct {
	udpClient protocols.UDPClient
}

func NewBindDetector(_ protocols.HTTPClient, _ protocols.TCPClient, udpClient protocols.UDPClient) Detector {
	return &BindDetector{udpClient: udpClient}
}

func (d BindDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 构建DNS请求包
	reqData, err := buildDNSRequest("version.bind", "TXT", "CHAOS")
	if err != nil {
		return "", fmt.Errorf("构建DNS请求失败: %w", err)
	}

	// 构建UDP请求
	req := protocols.TURequest{
		Method: "UDP", Address: target, Data: reqData, Timeout: 5 * time.Second,
	}

	// 执行UDP请求
	resp, err := d.udpClient.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("查询BIND版本失败: %w", err)
	}

	if resp.Err != nil {
		return "", fmt.Errorf("BIND服务器响应错误: %w", resp.Err)
	}

	// 解析DNS响应中的版本信息
	version, err := parseBINDVersion(resp.Body)
	if err != nil {
		return "", fmt.Errorf("解析BIND版本失败: %w", err)
	}

	return version, nil
}

// buildDNSRequest 构建DNS请求包
func buildDNSRequest(name, qtype, qclass string) ([]byte, error) {
	// 创建DNS头部 (12字节)
	header := make([]byte, 12)

	// 设置随机ID
	// 实际应用中应使用更安全的随机数生成器
	header[0] = 0x12
	header[1] = 0x34

	// 设置标志位: 标准查询
	header[2] = 0x01 // QR=0, OPCODE=0, AA=0, TC=0, RD=1
	header[3] = 0x00 // RA=0, Z=0, RCODE=0

	// 设置问题数量
	header[4] = 0x00
	header[5] = 0x01

	// 答案、权威、附加记录数量设为0
	header[6] = 0x00
	header[7] = 0x00
	header[8] = 0x00
	header[9] = 0x00
	header[10] = 0x00
	header[11] = 0x00

	// 构建问题部分
	question, err := buildDNSQuestion(name, qtype, qclass)
	if err != nil {
		return nil, err
	}

	// 合并头部和问题部分
	return append(header, question...), nil
}

// buildDNSQuestion 构建DNS问题部分
func buildDNSQuestion(name, qtype, qclass string) ([]byte, error) {
	// 将域名转换为DNS格式 (例如: "version.bind" -> [7]version[4]bind[0])
	parts := strings.Split(name, ".")
	var question []byte

	for _, part := range parts {
		length := len(part)
		if length > 63 {
			return nil, fmt.Errorf("域名部分过长: %s", part)
		}
		question = append(question, byte(length))
		question = append(question, []byte(part)...)
	}

	// 添加终止字节
	question = append(question, 0)

	// 添加QTYPE和QCLASS
	var qtypeValue uint16
	switch qtype {
	case "A":
		qtypeValue = 1
	case "NS":
		qtypeValue = 2
	case "CNAME":
		qtypeValue = 5
	case "SOA":
		qtypeValue = 6
	case "PTR":
		qtypeValue = 12
	case "MX":
		qtypeValue = 15
	case "TXT":
		qtypeValue = 16
	default:
		return nil, fmt.Errorf("不支持的QTYPE: %s", qtype)
	}

	var qclassValue uint16
	switch qclass {
	case "IN":
		qclassValue = 1
	case "CS":
		qclassValue = 2
	case "CH":
		qclassValue = 3
	case "HS":
		qclassValue = 4
	default:
		return nil, fmt.Errorf("不支持的QCLASS: %s", qclass)
	}

	// 添加QTYPE和QCLASS到问题部分
	qtypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBytes, qtypeValue)
	question = append(question, qtypeBytes...)

	qclassBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qclassBytes, qclassValue)
	question = append(question, qclassBytes...)

	return question, nil
}

// parseBINDVersion 解析BIND版本响应数据
func parseBINDVersion(data []byte) (string, error) {
	// 检查响应长度是否足够
	if len(data) < 12 {
		return "", fmt.Errorf("响应数据过短")
	}

	// 跳过DNS头部 (前12字节)
	offset := 12

	// 解析问题部分
	// 域名部分是压缩格式，简化处理，直接跳到问题类型和类
	for offset < len(data) && data[offset] != 0 {
		offset += int(data[offset]) + 1
	}
	offset++ // 跳过终止字节0

	if offset+4 > len(data) {
		return "", fmt.Errorf("问题部分解析失败")
	}

	offset += 4 // 跳过QTYPE和QCLASS

	// 解析应答部分
	if offset+10 > len(data) {
		return "", fmt.Errorf("应答部分缺失")
	}

	// 跳过NAME (压缩指针)
	offset += 2
	// 跳过TYPE (TXT=16)
	offset += 2
	// 跳过CLASS (CHAOS=3)
	offset += 2
	// 跳过TTL
	offset += 4
	// 获取RDLENGTH
	if offset+2 > len(data) {
		return "", fmt.Errorf("RDLENGTH缺失")
	}
	rdLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+rdLength > len(data) {
		return "", fmt.Errorf("RDATA不完整")
	}

	// 解析TXT记录
	rdData := data[offset : offset+rdLength]
	if len(rdData) == 0 {
		return "", fmt.Errorf("TXT记录为空")
	}

	// TXT记录格式: 长度字节 + 字符串
	var versionStr string
	for i := 0; i < len(rdData); {
		if i >= len(rdData) {
			break
		}
		strLen := int(rdData[i])
		i++
		if i+strLen > len(rdData) {
			break
		}
		versionStr += string(rdData[i : i+strLen])
		i += strLen
	}

	// 提取主要版本信息，直到第一个连字符或空格
	// 例如: "9.3.6-P1-RedHat-9.3.6-25.P1.el5_11.12" -> "9.3.6-P1"
	// 或者 "BIND 9.16.36" -> "9.16.36"
	parts := strings.FieldsFunc(versionStr, func(r rune) bool {
		return r == ' ' || r == '-'
	})

	if len(parts) > 0 {
		// 检查第一部分是否包含版本号格式
		if strings.ContainsAny(parts[0], "0123456789.") {
			return parts[0], nil
		} else if len(parts) > 1 {
			return parts[1], nil
		}
	}

	// 备用方案：使用连字符分割
	versionParts := strings.SplitN(versionStr, "-", 2)
	if len(versionParts) > 0 {
		return versionParts[0], nil
	}

	return "", fmt.Errorf("无法解析BIND版本信息")
}
