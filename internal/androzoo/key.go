package androzoo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// KeychainService is where the key is looked for on macOS.
const KeychainService = "androzoo.uni.lu"

// Key finds the AndroZoo API key: the environment first, then the macOS
// keychain so it need not sit in cleartext in a client's config file.
func Key() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ANDROZOO_API_KEY")); k != "" {
		return k, nil
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", "find-generic-password",
			"-s", KeychainService, "-w").Output()
		if err == nil {
			if k := strings.TrimSpace(string(out)); k != "" {
				return k, nil
			}
		}
	}
	return "", fmt.Errorf("no AndroZoo API key: set ANDROZOO_API_KEY.\n" +
		"Keys are issued to academic users on request at https://androzoo.uni.lu/access\n" +
		"On macOS the key can instead be stored in the keychain under the service name " + KeychainService)
}
