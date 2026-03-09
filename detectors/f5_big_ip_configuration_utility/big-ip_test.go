package f5_big_ip_configuration_utility

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"testing"
)

func TestNewCiscoEsaDetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewBigIpDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewBigIpDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "big-ip_configuration_utility", "f5", "https://20.57.187.56")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewBigIpDetector detector:", v)
}
