package common

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.zx2c4.com/wireguard/tun"
)

func PrintParsedPacket(raw []byte) {
	var layerType gopacket.LayerType
	switch raw[0] >> 4 {
	case 4:
		layerType = layers.LayerTypeIPv4
	case 6:
		layerType = layers.LayerTypeIPv6
	default:
		fmt.Println("Unknown IP version")
		return
	}

	packet := gopacket.NewPacket(raw, layerType, gopacket.Default)

	var srcIP, dstIP string

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
	}

	// Check for ICMP
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("%s -> %s | ICMP %s (Type: %d, Code: %d)\n",
			srcIP, dstIP, icmp.TypeCode.String(), icmp.TypeCode.Type(), icmp.TypeCode.Code())
		return
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv6)
		fmt.Printf("%s -> %s | ICMPv6 (Type: %d, Code: %d)\n",
			srcIP, dstIP, icmp.TypeCode.Type(), icmp.TypeCode.Code())
		return
	}

	// Check for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flags := ""
		if tcp.SYN {
			flags += "SYN "
		}
		if tcp.ACK {
			flags += "ACK "
		}
		if tcp.FIN {
			flags += "FIN "
		}
		if tcp.RST {
			flags += "RST "
		}

		fmt.Printf("%s:%d -> %s:%d | TCP [%s]\n",
			srcIP, tcp.SrcPort, dstIP, tcp.DstPort, flags)

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				fmt.Printf("  Data: %s\n", string(payload))
			}
		}
		return
	}

	// Check for UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		fmt.Printf("%s:%d -> %s:%d | UDP\n",
			srcIP, udp.SrcPort, dstIP, udp.DstPort)

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				fmt.Printf("  Data: %s\n", string(payload))
			}
		}
		return
	}

	fmt.Printf("%s -> %s\n", srcIP, dstIP)
}

func GetDefaultRoute() ([]string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") {
			return strings.Split(line, " "), nil
		}
	}
	return nil, nil
}

func SetDefaultRoute(route []string) error {
	err := exec.Command("ip", "route", "del", "default").Run()
	if err != nil {
		if e := err.(*exec.ExitError); e.ExitCode() != 2 {
			return fmt.Errorf("Failed to delete default interface: %w", err)
		}
	}
	args := append([]string{"route", "add"}, route...)
	err = exec.Command("ip", args...).Run()
	if err != nil {
		return fmt.Errorf("Failed to set default route %v: %w", route, err)
	}
	return nil
}

func SetupTunInterface(tunName string, mtu int) (tun.Device, error) {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		return nil, err
	}

	err = exec.Command("ip", "link", "set", tunName, "up").Run()
	if err != nil {
		return nil, err
	}
	return dev, nil
}

func DeleteInterface(iface string) error {
	err := exec.Command("ip", "link", "delete", iface).Run()
	if err != nil {
		return fmt.Errorf("Failed to delete %q interface: %w", iface, err)
	}
	return nil
}

func EnableIpForwarding() error {
	// TODO this changes last only until reboot
	_, err := exec.Command("sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1").CombinedOutput()
	if err != nil {
		return err
	}

	_, err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func SetIpAddress(addr string, iface string) error {
	_, err := exec.Command("ip", "addr", "add", addr, "dev", iface).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func EnablePostrouting(subnet string) error {
	_, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", "eth0", "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}
