package cisco_adaptive_security_appliance

import (
	"context"
	"fmt"
	"testing"

	"github.com/panda843/product-version-detectors/protocols"
)

func TestNewCiscoASADetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewCiscoASADetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewASADetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "ASA_configuration_utility", "f5", "https://172.16.21.239")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewASADetector detector:", v)
}
