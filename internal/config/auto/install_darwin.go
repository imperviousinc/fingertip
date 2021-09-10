//+build darwin

package auto

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

var re = regexp.MustCompile(`(?m)^\([0-9]+\)(.+)`)

// Supported whether auto configuration
// is supported for this build
func Supported() bool {
	return true
}

// GetProxyStatus checks if the OS is already using a proxy
// and whether its the same as autoURL.
func GetProxyStatus(autoURL string) (ProxyStatus, error) {
	var (
		conflict  bool
		installed = true
	)

	ok, err := forEachService(func(service string) error {
		cmd := exec.Command("networksetup", "-getautoproxyurl", service)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}

		url, enabled := parseGetAutoURL(string(out))
		if !enabled {
			installed = false
			return nil
		}

		if url == "" {
			installed = false
			return nil
		}

		if !strings.EqualFold(url, autoURL) {
			conflict = true
		}

		return nil
	})

	if err != nil && !ok {
		return ProxyStatusNone, err
	}

	if conflict {
		return ProxyStatusConflict, nil
	}

	if installed {
		return ProxyStatusInstalled, nil
	}

	return ProxyStatusNone, nil
}

func UninstallAutoProxy() error {
	ok, err := forEachService(func(service string) error {
		_, err := runCommand("networksetup", "-setautoproxystate", service, "off")
		return err
	})

	if ok {
		return nil
	}

	return err
}

func InstallAutoProxy(autoURL string) error {
	ok, err := forEachService(func(service string) error {
		_, err := runCommand("networksetup", "-setautoproxyurl", service, autoURL)
		if err != nil {
			return err
		}

		_, err = runCommand("networksetup", "-setautoproxystate", service, "on")
		return err
	})

	if ok {
		return nil
	}

	return err
}

func runCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func forEachService(run func(service string) error) (bool, error) {
	services, err := getNetworkServices()
	if err != nil {
		return false, err
	}

	var lastErr error
	var good bool
	for _, service := range services {
		if err := run(service); err != nil {
			lastErr = err
			continue
		}
		good = true
	}
	return good, lastErr
}

func getNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed reading network services: %v", err)
	}

	var services []string
	for _, match := range re.FindAllStringSubmatch(string(out), -1) {
		if len(match) != 2 {
			continue
		}
		services = append(services, strings.TrimSpace(match[1]))
	}

	return services, nil
}

func InstallCert(certPath string) error {
	dir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	kp := path.Join(dir, "Library/Keychains/login.keychain")
	out, err := runCommand("security", "add-trusted-cert",
		"-p", "basic", "-p", "ssl", "-k", kp, certPath)

	if err == nil {
		return nil
	}

	if _, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("failed installing cert: %s", string(out))
	}

	return fmt.Errorf("failed installing cert: %v", err)
}

func UninstallCert(certPath string) error {
	_, err := runCommand("security", "remove-trusted-cert", certPath)
	return err
}

// parses networksetup -getautoproxyurl <service>
func parseGetAutoURL(txt string) (url string, enabled bool) {
	lines := strings.Split(strings.TrimSpace(txt), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "URL:") {
			url = strings.TrimSpace(line[4:])
			continue
		}

		if strings.HasPrefix(line, "Enabled:") {
			line = strings.TrimSpace(line[8:])
			enabled = line != "No"
			continue
		}
	}

	return
}
