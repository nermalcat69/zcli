//go:build darwin
// +build darwin

package vpn

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/zerops-io/zcli/src/i18n"
	"github.com/zerops-io/zcli/src/utils/cmdRunner"
	"github.com/zerops-io/zcli/src/zeropsVpnProtocol"
)

func (h *Handler) setVpn(selectedVpnAddress, privateKey string, mtu uint32, response *zeropsVpnProtocol.StartVpnResponse) error {
	var err error

	h.logger.Debug("run wireguard-go utun")

	interfaceName, err := h.createInterface()
	if err != nil {
		return err
	}

	{
		privateKeyName := uuid.New().String()
		tempPrivateKeyFile := path.Join(os.TempDir(), privateKeyName)
		err = ioutil.WriteFile(tempPrivateKeyFile, []byte(privateKey), 0755)
		if err != nil {
			return err
		}
		_, err = cmdRunner.Run(exec.Command("wg", "set", interfaceName, "private-key", tempPrivateKeyFile))
		if err != nil {
			return err
		}
		err = os.Remove(tempPrivateKeyFile)
		if err != nil {
			return err
		}
	}

	_, err = cmdRunner.Run(exec.Command("wg", "set", interfaceName, "listen-port", wireguardPort))
	if err != nil {
		return err
	}

	clientIp := zeropsVpnProtocol.FromProtoIP(response.GetVpn().GetAssignedClientIp())
	vpnRange := zeropsVpnProtocol.FromProtoIPRange(response.GetVpn().GetVpnIpRange())

	args := []string{
		"set", interfaceName,
		"peer", response.GetVpn().GetServerPublicKey(),
		"allowed-ips", vpnRange.String(),
		"endpoint", selectedVpnAddress + ":" + strconv.Itoa(int(response.GetVpn().GetPort())),
		"persistent-keepalive", "25",
	}
	_, err = cmdRunner.Run(exec.Command("wg", args...))
	if err != nil {
		if !errors.Is(err, cmdRunner.IpAlreadySetErr) {
			panic(err)
		}
	}

	_, err = cmdRunner.Run(exec.Command("ifconfig", interfaceName, "inet6", clientIp.String(), "mtu", strconv.Itoa(int(mtu))))
	if err != nil {
		return err
	}

	serverIp := zeropsVpnProtocol.FromProtoIP(response.GetVpn().GetServerIp())
	_, err = cmdRunner.Run(exec.Command("route", "add", "-inet6", vpnRange.String(), serverIp.String()))
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) createInterface() (string, error) {
	wireGuardCmd := exec.Command("wireguard-go", "utun")
	wireGuardCmd.Env = append(os.Environ(), "WG_TUN_NAME_FILE=/tmp/zerops_tun")
	_, execErr := cmdRunner.Run(wireGuardCmd)
	if execErr != nil {
		h.logger.Error(execErr)
		return "", errors.New(i18n.VpnStartWireguardUtunError)
	}
	buf, err := ioutil.ReadFile("/tmp/zerops_tun")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buf)), nil
}
