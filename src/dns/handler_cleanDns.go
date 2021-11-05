package dns

import (
	"net"
	"os"
	"os/exec"

	"github.com/zerops-io/zcli/src/dnsServer"

	"github.com/zerops-io/zcli/src/constants"

	"github.com/zerops-io/zcli/src/utils"
	"github.com/zerops-io/zcli/src/utils/cmdRunner"
)

func CleanDns(dnsServer *dnsServer.Handler, dnsIp net.IP, interfaceName string, dnsManagement LocalDnsManagement) error {

	switch dnsManagement {
	case LocalDnsManagementUnknown:
		return nil
	case LocalDnsManagementSystemdResolve:
		return nil
	case LocalDnsManagementResolveConf:
		cmd := exec.Command("resolvconf", "-d", interfaceName)
		_, err := cmdRunner.Run(cmd)
		if err != nil {
			return err
		}
	case LocalDnsManagementFile:
		err := utils.RemoveFirstLine(constants.ResolvFilePath, "nameserver "+dnsIp.String())
		if err != nil {
			return err
		}
	case LocalDnsManagementDarwin:
		err := os.Remove(constants.ResolverZeropsPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		dnsServer.StopForward()
	default:
		return UnknownDnsManagementErr
	}
	return nil
}
