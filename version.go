package version

import (
	"context"
	"sync"

	array_ArrayosAG "github.com/panda843/product-version-detectors/detectors/array_ag"
	"github.com/panda843/product-version-detectors/detectors/cisco_identity_services_engine_software"

	"github.com/panda843/product-version-detectors/detectors/Fortinet/fortigate"
	"github.com/panda843/product-version-detectors/detectors/arubanetworks_edgeconnect_sdwan_orchestrator"
	"github.com/panda843/product-version-detectors/detectors/cisco_adaptive_security_appliance"
	"github.com/panda843/product-version-detectors/detectors/cisco_email_security_appliance_firmeware"
	"github.com/panda843/product-version-detectors/detectors/cisco_prime_infrastructure"
	"github.com/panda843/product-version-detectors/detectors/cisco_secure_email_and_web_manager_firmware"
	"github.com/panda843/product-version-detectors/detectors/cisco_stealthwatch_management_console"
	"github.com/panda843/product-version-detectors/detectors/citrix_netscaler_application_delivery_controller"
	"github.com/panda843/product-version-detectors/detectors/silver_peak_unity_edgeconnect_sd_wan_firmware"
	"github.com/panda843/product-version-detectors/detectors/sophos_xg_firewall_firmware"
	"github.com/panda843/product-version-detectors/detectors/vmware_vcenter"
	"github.com/panda843/product-version-detectors/factory"
	"github.com/panda843/product-version-detectors/protocols"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/detectors/barracuda_cloudgen_firewall"
	barracudanextgenfirewallsslvpn "github.com/panda843/product-version-detectors/detectors/barracuda_nextgen_firewall_sslvpn"
	"github.com/panda843/product-version-detectors/detectors/checkpoint_cpsg"
	cisco3750 "github.com/panda843/product-version-detectors/detectors/cisco_3750"
	"github.com/panda843/product-version-detectors/detectors/cisco_acs"
	"github.com/panda843/product-version-detectors/detectors/citrix_sd_wan"
	"github.com/panda843/product-version-detectors/detectors/cyberoam_firewall"
	"github.com/panda843/product-version-detectors/detectors/f5_big_ip_configuration_utility"
	"github.com/panda843/product-version-detectors/detectors/forescout_counteract"
	"github.com/panda843/product-version-detectors/detectors/juniper_junos"
	"github.com/panda843/product-version-detectors/detectors/kerio_control"
	"github.com/panda843/product-version-detectors/detectors/mikrotik_routeros"
	"github.com/panda843/product-version-detectors/detectors/paloalto_panos"
	"github.com/panda843/product-version-detectors/detectors/plixer_scrutinizer"
	sophosfirewall "github.com/panda843/product-version-detectors/detectors/sophos_firewall"
	"github.com/panda843/product-version-detectors/detectors/sophos_unified_threat_management_software"
	sophosuserportal "github.com/panda843/product-version-detectors/detectors/sophos_user_portal"
	sophosvpnportal "github.com/panda843/product-version-detectors/detectors/sophos_vpn_portal"
	"github.com/panda843/product-version-detectors/detectors/vmware_esxi"
	zabbixzabbix "github.com/panda843/product-version-detectors/detectors/zabbix_zabbix"
)

var once sync.Once
var ins *Version

type Version struct {
	detectorFactory *factory.DetectorFactory
}

func New() *Version {
	if ins == nil {
		once.Do(func() {
			ins = &Version{}
			ins.initVersion()
		})
	}
	return ins
}

// initVersion 初始化版本检测工厂
func (v *Version) initVersion() {
	v.detectorFactory = factory.NewDetectorFactory()
	// 注册产品
	v.detectorFactory.RegisterDetector("nginx", detectors.NewNginxDetector)
	v.detectorFactory.RegisterDetector("openssh", detectors.NewSSHDetector)
	v.detectorFactory.RegisterDetector("bind", detectors.NewBindDetector)
	v.detectorFactory.RegisterDetector("counteract", forescout_counteract.NewCounteractDetector)
	v.detectorFactory.RegisterDetector("arrayos_ag", array_ArrayosAG.NewArrayosAGDetector)
	v.detectorFactory.RegisterDetector("cloudgen_firewall", barracuda_cloudgen_firewall.NewNGFWDetector)
	v.detectorFactory.RegisterDetector("gaia_portal", checkpoint_cpsg.NewGaiaPortalDetector)
	v.detectorFactory.RegisterDetector("secure_access_control_server", cisco_acs.NewACSDetector)
	v.detectorFactory.RegisterDetector("sd-wan", citrix_sd_wan.NewSDWanDetector)
	v.detectorFactory.RegisterDetector("vcenter_server", vmware_vcenter.NewVCenterDetector)
	v.detectorFactory.RegisterDetector("esxi", vmware_esxi.NewEsxiDetector)
	v.detectorFactory.RegisterDetector("big-ip_configuration_utility", f5_big_ip_configuration_utility.NewBigIpDetector)
	v.detectorFactory.RegisterDetector("junos", juniper_junos.NewJuniperDetector)
	v.detectorFactory.RegisterDetector("control", kerio_control.NewKerioDetecto)
	v.detectorFactory.RegisterDetector("routeros", mikrotik_routeros.NewRouterOSDetector)
	v.detectorFactory.RegisterDetector("scrutinizer", plixer_scrutinizer.NewPlixerScrutinizerDetector)
	v.detectorFactory.RegisterDetector("unified_threat_management_software", sophos_unified_threat_management_software.NewSophosUTMDetector)
	v.detectorFactory.RegisterDetector("pan-os", paloalto_panos.NewPanOSDetector)
	v.detectorFactory.RegisterDetector("fortios", fortigate.NewFortiGateDetector)
	v.detectorFactory.RegisterDetector("adaptive_security_appliance_software", cisco_adaptive_security_appliance.NewCiscoASADetector)
	// v.detectorFactory.RegisterDetector("adaptive_security_virtual_appliance", cisco_adaptive_security_virtual_appliance.NewCiscoASAvDetector)
	v.detectorFactory.RegisterDetector("prime_infrastructure", cisco_prime_infrastructure.NewCicsoPrimeInfraDetector)
	v.detectorFactory.RegisterDetector("email_security_appliance_firmeware", cisco_email_security_appliance_firmeware.NewCiscoEsaDetector)
	v.detectorFactory.RegisterDetector("secure_email_and_web_manager_firmware", cisco_secure_email_and_web_manager_firmware.NewCiscoSmaZeusDetector)
	v.detectorFactory.RegisterDetector("stealthwatch_management_console", cisco_stealthwatch_management_console.NewCiscoStealthwatchDetector)
	v.detectorFactory.RegisterDetector("xg_firewall_firmware", sophos_xg_firewall_firmware.NewSophosXGFirewallDetector)
	v.detectorFactory.RegisterDetector("edgeconnect_sd-wan_orchestrator", arubanetworks_edgeconnect_sdwan_orchestrator.NewArubaEdgeConnectSDWANDetector)
	v.detectorFactory.RegisterDetector("unity_edgeconnect_sd-wan_firmware", silver_peak_unity_edgeconnect_sd_wan_firmware.NewSilverPeakEdgeconnectSDWANDetector)
	v.detectorFactory.RegisterDetector("netscaler_application_delivery_controller", citrix_netscaler_application_delivery_controller.NewCitrixNetScalerDetector)
	v.detectorFactory.RegisterDetector("identity_services_engine_software", cisco_identity_services_engine_software.NewCiscoISEDetector)
	v.detectorFactory.RegisterDetector("zabbix", zabbixzabbix.NewZabbixDetector)
	v.detectorFactory.RegisterDetector("nextgen_firewall_sslvpn", barracudanextgenfirewallsslvpn.NewNextgensslvpnDetectorDetector)
	v.detectorFactory.RegisterDetector("cisco3750", cisco3750.NewCisco3750Detector)
	v.detectorFactory.RegisterDetector("sophos_vpn_portal", sophosvpnportal.NewSophosVPNPortalDetector)
	v.detectorFactory.RegisterDetector("sophos_firewall", sophosfirewall.NewSophosFirewalletector)
	v.detectorFactory.RegisterDetector("sophos_user_portal", sophosuserportal.NewSophosUserPortalDetector)
	v.detectorFactory.RegisterDetector("cyberoam_firewall", cyberoamfirewall.NewCyberoamFirewallDetector)

}

// WithHTTPClient 设置HTTP客户端
func (v *Version) WithHTTPClient(client protocols.HTTPClient) *Version {
	v.detectorFactory = v.detectorFactory.WithHTTPClient(client)
	return v
}

// WithTCPClient 设置TCP客户端
func (v *Version) WithTCPClient(client protocols.TCPClient) *Version {
	v.detectorFactory = v.detectorFactory.WithTCPClient(client)
	return v
}

// WithUDPClient 设置UDP客户端
func (v *Version) WithUDPClient(client protocols.UDPClient) *Version {
	v.detectorFactory = v.detectorFactory.WithUDPClient(client)
	return v
}

// Check 检查目标的版本信息
func (v *Version) Check(ctx context.Context, product, cnProduct, vendor, target string) (string, error) {
	version := ""
	detector, err := v.detectorFactory.CreateDetector(product)
	if err != nil {
		return version, err
	}
	return detector.Detect(ctx, cnProduct, vendor, target)
}

// Products 返回所有支持的产品列表
func (v *Version) Products() []string {
	return v.detectorFactory.Products()
}
