package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/eclipse-volttron/protocol-proxy-go/manifest"
)

func TestGoEchoProxyPassesEveryCheck(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("go", "build", "-o", filepath.Join(dir, "echo-proxy"), "../cmd/echo-proxy").CombinedOutput(); err != nil {
		t.Skipf("cannot build echo-proxy: %v\n%s", err, out)
	}
	path := filepath.Join(dir, "proxy.toml")
	os.WriteFile(path, []byte("[proxy]\nname = \"echo-go\"\ncommand = [\"{manifest_dir}/echo-proxy\"]\n"), 0o644)
	mf, err := manifest.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	report := Run(mf, Options{EchoMethod: "ECHO", TLS: true, ManagerDials: true})
	if !report.OK() {
		t.Fatal(report.Text())
	}
	if len(report.Checks) != 26 {
		t.Fatalf("%d checks:\n%s", len(report.Checks), report.Text())
	}
	for _, c := range report.Checks {
		if c.Skipped {
			t.Fatalf("skipped: %s (%s)", c.Name, c.Detail)
		}
	}
	if _, err := report.JSON(); err != nil {
		t.Fatal(err)
	}
}
