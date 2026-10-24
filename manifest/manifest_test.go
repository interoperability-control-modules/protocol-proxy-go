package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const example = `
[proxy]
name = "mqtt"
command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]
header_version = 2

[identity]
keys = ["host", "port"]
must_match = ["username", "password"]

[identity.normalize]
host = ["strip", "lowercase"]
port = [{ default = 1883 }]

[environment]
MQTT_LOG = "info"

[self_test]
command = ["{manifest_dir}/bin/mqtt-proxy", "--self-test"]
`

func TestParseExample(t *testing.T) {
	m, err := Parse(example, "/opt/mqtt/proxy.toml")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "mqtt" || m.HeaderVersion != 2 || m.Environment["MQTT_LOG"] != "info" {
		t.Fatalf("unexpected manifest %+v", m)
	}
	if strings.Join(m.Identity.Keys, ",") != "host,port" || strings.Join(m.Identity.MustMatch, ",") != "username,password" {
		t.Fatalf("identity %+v", m.Identity)
	}
	argv := m.LaunchCommand("/venv/bin/python", []string{"--proxy-id", "x"})
	want := "/venv/bin/python -m protocol_proxy.proxy --gevent protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy --proxy-id x"
	if strings.Join(argv, " ") != want {
		t.Fatalf("launch command %q", strings.Join(argv, " "))
	}
	if got := strings.Join(m.SelfTestCommand("python3"), " "); got != "/opt/mqtt/bin/mqtt-proxy --self-test" {
		t.Fatalf("self test %q", got)
	}
}

func TestNormalisationAndKeys(t *testing.T) {
	m, err := Parse(example, "")
	if err != nil {
		t.Fatal(err)
	}
	key := m.ProcessKey([]any{"ignored"}, map[string]any{"host": "  Broker.Example ", "username": "u"})
	if len(key) != 3 || key[0] != "mqtt" || key[1] != "broker.example" || key[2] != int64(1883) {
		t.Fatalf("process key %#v", key)
	}
	first := map[string]any{"username": "u", "password": "p"}
	if c := m.Identity.Conflicts(first, map[string]any{"username": "u", "password": "p"}); len(c) != 0 {
		t.Fatalf("unexpected conflicts %v", c)
	}
	if c := m.Identity.Conflicts(first, map[string]any{"username": "u", "password": "other"}); strings.Join(c, ",") != "password" {
		t.Fatalf("conflicts %v", c)
	}
	plain, _ := Parse("[proxy]\nname = \"echo\"\ncommand = [\"echo-proxy\"]\n", "")
	if key := plain.ProcessKey([]any{"dev", 7}, map[string]any{"host": "h"}); len(key) != 2 || key[0] != "dev" || key[1] != 7 {
		t.Fatalf("caller's key not kept: %#v", key)
	}
	if plain.HeaderVersion != 2 || plain.SelfTest != nil {
		t.Fatalf("defaults: %+v", plain)
	}
}

func TestEnvironmentPlaceholders(t *testing.T) {
	text := "[proxy]\nname = \"dummy\"\ncommand = [\"{python}\", \"-m\", \"protocol_proxy.proxy\", \"d:D\"]\n" +
		"[environment]\nPYTHONPATH = \"{manifest_dir}/..\"\nINTERP = \"{python}\"\nPLAIN = \"as is\"\n"
	m, err := Parse(text, "/repo/tests/manifests/dummy.toml")
	if err != nil {
		t.Fatal(err)
	}
	if m.Environment["PYTHONPATH"] != "{manifest_dir}/.." {
		t.Fatalf("the parsed table keeps the placeholders: %q", m.Environment["PYTHONPATH"])
	}
	env := m.ResolvedEnvironment("/venv/bin/python")
	if env["PYTHONPATH"] != "/repo/tests/manifests/.." || env["INTERP"] != "/venv/bin/python" || env["PLAIN"] != "as is" {
		t.Fatalf("resolved environment %v", env)
	}
}

func TestRejectsBadManifests(t *testing.T) {
	cases := map[string]string{
		"no proxy table":     "[identity]\nkeys = [\"a\"]\n",
		"unknown table":      "[proxy]\nname = \"x\"\ncommand = [\"x\"]\n[extra]\na = 1\n",
		"bad name":           "[proxy]\nname = \"a b\"\ncommand = [\"x\"]\n",
		"empty command":      "[proxy]\nname = \"x\"\ncommand = []\n",
		"bad placeholder":    "[proxy]\nname = \"x\"\ncommand = [\"{home}/x\"]\n",
		"bad header version": "[proxy]\nname = \"x\"\ncommand = [\"x\"]\nheader_version = 3\n",
		"normalize unknown":  "[proxy]\nname = \"x\"\ncommand = [\"x\"]\n[identity]\nkeys = [\"a\"]\n[identity.normalize]\nb = [\"strip\"]\n",
		"bad normaliser":     "[proxy]\nname = \"x\"\ncommand = [\"x\"]\n[identity]\nkeys = [\"a\"]\n[identity.normalize]\na = [\"upper\"]\n",
		"env not strings":    "[proxy]\nname = \"x\"\ncommand = [\"x\"]\n[environment]\nA = 1\n",
		"env placeholder":    "[proxy]\nname = \"x\"\ncommand = [\"x\"]\n[environment]\nA = \"{home}/x\"\n",
		"not toml":           "[proxy\n",
	}
	for name, text := range cases {
		if _, err := Parse(text, name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSearchPathAndLocate(t *testing.T) {
	root := t.TempDir()
	first, config, prefix, etc, share := filepath.Join(root, "first"), filepath.Join(root, "config"), filepath.Join(root, "prefix"),
		filepath.Join(root, "etc"), filepath.Join(root, "share")
	t.Setenv(EnvManifestPath, first+string(os.PathListSeparator)+first)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv(EnvPrefix, prefix)
	t.Setenv("XDG_CONFIG_DIRS", etc)
	t.Setenv("XDG_DATA_DIRS", share)
	got := SearchPath()
	want := []string{first, filepath.Join(config, Subdir), filepath.Join(prefix, "share", Subdir), filepath.Join(etc, Subdir),
		filepath.Join(share, Subdir)}
	if strings.Join(got, ":") != strings.Join(want, ":") {
		t.Fatalf("search path\n got %v\nwant %v", got, want)
	}
	if _, err := Locate("nothing"); err == nil || !strings.Contains(err.Error(), filepath.Join(first, "nothing.toml")) {
		t.Fatalf("missing manifest error should name the places looked: %v", err)
	}
	later := filepath.Join(config, Subdir, "echo")
	if err := os.MkdirAll(later, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(later, Filename), []byte("[proxy]\nname = \"echo\"\ncommand = [\"{manifest_dir}/bin/echo\"]\n"), 0o644)
	path, err := Locate("echo")
	if err != nil || path != filepath.Join(later, Filename) {
		t.Fatalf("locate: %v %q", err, path)
	}
	os.MkdirAll(first, 0o755)
	os.WriteFile(filepath.Join(first, "echo.toml"), []byte("[proxy]\nname = \"echo\"\ncommand = [\"first\"]\n"), 0o644)
	m, err := Find("echo")
	if err != nil || m.Command[0] != "first" {
		t.Fatalf("the first directory should win: %v %+v", err, m)
	}
	all, err := Discover()
	if err != nil || len(all) != 1 || all["echo"].Command[0] != "first" {
		t.Fatalf("discover: %v %+v", err, all)
	}
	if m.Dir() != first {
		t.Fatalf("manifest dir %q", m.Dir())
	}
}
