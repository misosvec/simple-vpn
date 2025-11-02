package common

import (
	"errors"
	"os/exec"
	"strings"
)

func GetDefaultRoute() ([]string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		panic(err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") {
			return strings.Split(line, " "), nil
		}
	}
	return nil, errors.New("Failed to determine default gateway")
}

func setDefaultRoute(iface string) error {
	cmd := exec.Command("ip", "route", "add", "default", "dev", iface)
	return cmd.Run()
}

func RouteAllPacketsToTun(tunIface string) {
	if !strings.Contains(strings.ToLower(tunIface), "tun") {
		panic(errors.New("Provided Interace is not TUN"))
	}
	err := setDefaultRoute(tunIface)
	if err != nil {
		panic(err)
	}
}
