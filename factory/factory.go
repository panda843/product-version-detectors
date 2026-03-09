package factory

import (
	"errors"
	"sync"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// DetectorFactory 是创建版本检测器的工厂
type DetectorFactory struct {
	httpClient protocols.HTTPClient
	tcpClient  protocols.TCPClient
	udpClient  protocols.UDPClient
	detectors  map[string]detectors.DetectorCreator
	mu         sync.RWMutex
}

// NewDetectorFactory 创建一个新的检测器工厂
func NewDetectorFactory() *DetectorFactory {
	return &DetectorFactory{
		httpClient: protocols.NewDefaultHTTPClient(),
		tcpClient:  protocols.NewDefaultTCPClient(),
		udpClient:  protocols.NewDefaultUDPClient(),
		detectors:  make(map[string]detectors.DetectorCreator),
	}
}

// WithHTTPClient 设置HTTP客户端
func (f *DetectorFactory) WithHTTPClient(client protocols.HTTPClient) *DetectorFactory {
	f.httpClient = client
	return f
}

// WithTCPClient 设置TCP客户端
func (f *DetectorFactory) WithTCPClient(client protocols.TCPClient) *DetectorFactory {
	f.tcpClient = client
	return f
}

// WithUDPClient 设置UDP客户端
func (f *DetectorFactory) WithUDPClient(client protocols.UDPClient) *DetectorFactory {
	f.udpClient = client
	return f
}

// RegisterDetector 注册一个检测器
func (f *DetectorFactory) RegisterDetector(product string, creator detectors.DetectorCreator) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detectors[product] = creator
}

// Products 产品列表
func (f *DetectorFactory) Products() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	products := make([]string, 0, len(f.detectors))
	for product := range f.detectors {
		products = append(products, product)
	}
	return products
}

// CreateDetector 创建一个检测器
func (f *DetectorFactory) CreateDetector(product string) (detectors.Detector, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	creator, exists := f.detectors[product]
	if !exists {
		return nil, errors.New("unsupported product: " + product)
	}

	return creator(f.httpClient, f.tcpClient, f.udpClient), nil
}
