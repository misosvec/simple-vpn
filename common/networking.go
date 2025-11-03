package common

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func GetDefaultRoute() ([]string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve routing table: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") {
			return strings.Split(line, " "), nil
		}
	}
	return nil, errors.New("Failed to determine default gateway")
}

func SetDefaultRoute(route []string) error {
	err := exec.Command("ip", "route", "del", "default").Run()
	if err != nil {
		return fmt.Errorf("Failed to delete default interface: %w", err)
	}
	args := append([]string{"route", "add"}, route...)
	err = exec.Command("ip", args...).Run()
	if err != nil {
		return fmt.Errorf("Failed to set default route %v: %w", route, err)
	}
	return nil
}

func CreateTunInterface(tunName string) error {
	err := exec.Command("ip", "tuntap", "add", "dev", tunName, "mode", "tun").Run()
	if err != nil {
		return fmt.Errorf("Failed to create %q interface: %w", tunName, err)
	}

	err = exec.Command("ip", "link", "set", "dev", tunName, "up").Run()
	if err != nil {
		return fmt.Errorf("Failed to enable %q interface: %w", tunName, err)
	}

	return nil
}

func DeleteInterface(iface string) error {
	err := exec.Command("ip", "link", "delete", iface).Run()
	if err != nil {
		return fmt.Errorf("Failed to delete %q interface: %w", iface, err)
	}
	return nil
}
