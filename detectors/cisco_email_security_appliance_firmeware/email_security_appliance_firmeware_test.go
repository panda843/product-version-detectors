package cisco_email_security_appliance_firmeware

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
	detector := NewCiscoEsaDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewCiscoEsaDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "email_security_appliance_firmeware", "cisco", "https://110.49.111.74")
	if e != nil {
		panic(e)
	}
	fmt.Println("CiscoEsaDetector detector:", v)
}
