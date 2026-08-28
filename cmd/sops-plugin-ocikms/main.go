// Command sops-plugin-ocikms is a sops-plugin/1 plugin that wraps the sops
// data key with Oracle Cloud Infrastructure Key Management.
package main

import (
	"fmt"
	"os"

	"github.com/deblasis/sops-plugin-ocikms"
)

// overridden at build time with
// -ldflags "-X main.pluginVersion=1.2.3"
var pluginVersion = "0.1.0"

func main() {
	// testing hook: in-process fake KMS instead of the network, see README
	fake := os.Getenv("SOPS_OCIKMS_FAKE_KMS") == "1"
	h := &ocikms.KMSHandler{Fake: fake}
	if err := ocikms.Serve(os.Stdin, os.Stdout, h, pluginVersion); err != nil {
		fmt.Fprintln(os.Stderr, "sops-plugin-ocikms: "+err.Error())
		os.Exit(1)
	}
}
