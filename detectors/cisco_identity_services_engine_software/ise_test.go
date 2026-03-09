package cisco_identity_services_engine_software

import (
	"context"
	"fmt"
	"testing"

	"github.com/panda843/product-version-detectors/protocols"
)

func TestNewCiscoEsaDetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewCiscoISEDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewCiscoISEDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "big-ip_configuration_utility", "f5", "https://27.254.253.248")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewCiscoISEDetector detector:", v)
}
