// Package all imports every compiled-in plugin for its side effects.
//
// Each import triggers the plugin package's init(), which calls
// plugin.RegisterTool / plugin.RegisterAgent / plugin.RegisterPipeline.
//
// To add a new plugin:
//  1. Create plugins/<your-plugin>/plugin.go  (implement Tool/Agent, call Register* in init)
//  2. Create plugins/<your-plugin>/plugin.yaml (metadata)
//  3. Add a blank import below.
package all

import (
	_ "xpfarm/plugins/example-echo"
	_ "xpfarm/plugins/example-repo-scanner"
	_ "xpfarm/plugins/repo-secrets"
	_ "xpfarm/plugins/repo-semgrep"
)
