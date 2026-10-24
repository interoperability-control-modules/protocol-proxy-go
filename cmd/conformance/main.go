// Command conformance launches a proxy through the Go manager and checks it against PROTOCOL.md, the counterpart of
// the Python protocol-proxy-conformance command:
//
//	conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials] [--option NAME=VALUE ...]
//	            [--timeout S] [--python PATH] [--log FILE] [--json] [-v]
//
// Exit 0 when every check passes or is skipped.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/conformance"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
	"github.com/eclipse-volttron/protocol-proxy-go/manifest"
)

type optionList []string

func (o *optionList) String() string     { return strings.Join(*o, ",") }
func (o *optionList) Set(v string) error { *o = append(*o, v); return nil }

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials]"+
			" [--option NAME=VALUE ...] [--timeout S] [--python PATH] [--log FILE] [--json] [-v]")
		fs.PrintDefaults()
	}
	echo := fs.String("echo", "", "a method of the proxy that replies with its payload")
	tls := fs.Bool("tls", false, "also launch with TLS material (--ipc-tls)")
	managerDials := fs.Bool("manager-dials", false, "also launch with manager-initiated registration")
	var options optionList
	fs.Var(&options, "option", "a launch option for the proxy, NAME=VALUE (repeatable)")
	timeout := fs.Float64("timeout", 20, "seconds to wait for registration and replies")
	python := fs.String("python", "", "what {python} in a manifest resolves to (default $PROTOCOL_PROXY_PYTHON or python3)")
	asJSON := fs.Bool("json", false, "machine-readable report")
	verbose := fs.Bool("v", false, "show the manager and proxy logs")
	logFile := fs.String("log", "", "write the manager and proxy logs (DEBUG) to this file")
	// Accept the proxy argument before or after the flags.
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if needsValue(a) && !strings.Contains(a, "=") && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		fs.Usage()
		return 2
	}
	target := positional[0]
	var mf *manifest.Manifest
	var err error
	if filepath.Ext(target) == ".toml" || strings.Contains(target, string(os.PathSeparator)) {
		mf, err = manifest.Load(target)
	} else {
		mf, err = manifest.Find(target)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance:", err)
		return 2
	}
	launch := map[string]any{}
	for _, item := range options {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "conformance: --option needs NAME=VALUE, got %q\n", item)
			return 2
		}
		launch[name] = value
	}
	var logger *logs.Logger
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "conformance:", err)
			return 2
		}
		defer f.Close()
		logger = logs.New(logs.DEBUG, &logs.StreamSink{W: f})
	} else if *verbose {
		logger = logs.New(logs.DEBUG, &logs.StreamSink{W: os.Stderr})
	}
	report := conformance.Run(mf, conformance.Options{LaunchOptions: launch, EchoMethod: *echo, TLS: *tls,
		ManagerDials: *managerDials, Timeout: time.Duration(*timeout * float64(time.Second)), Python: *python, Logger: logger})
	if *asJSON {
		out, _ := report.JSON()
		fmt.Println(string(out))
	} else {
		fmt.Println(report.Text())
	}
	if report.OK() {
		return 0
	}
	return 1
}

// needsValue: flags that take a separate value argument.
func needsValue(flag string) bool {
	switch strings.TrimLeft(flag, "-") {
	case "echo", "option", "timeout", "python", "log":
		return true
	}
	return false
}
