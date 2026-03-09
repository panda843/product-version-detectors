package detectors

import (
	"context"

	"github.com/panda843/product-version-detectors/protocols"
)

// Detector 是版本检测器的接口
type Detector interface {
	Detect(ctx context.Context, cnProduct, vendor, target string) (string, error)
}

// DetectorCreator 是创建检测器的函数类型
type DetectorCreator func(httpClient protocols.HTTPClient, tcpClient protocols.TCPClient, udpClient protocols.UDPClient) Detector
