// Package manifest reads proxy manifests (PROTOCOL.md §1a): everything a manager needs to launch and key a proxy, as
// data. A proxy ships a proxy.toml beside its binary; a manager in any language reads it to learn the command that
// starts the proxy, which launch options identify one process, and which options remotes sharing a process must
// agree on. Nothing in a manifest is executable: identity values may only be normalised by the fixed set of
// normalisers plus a default.
//
//	[proxy]
//	name = "mqtt"
//	command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]
//	header_version = 2
//
//	[identity]
//	keys = ["host", "port"]
//	must_match = ["username", "password"]
//
//	[identity.normalize]
//	host = ["strip", "lowercase"]
//	port = [{ default = 1883 }]
//
//	[environment]                      # values take the same {python} and {manifest_dir} placeholders as command
//	MQTT_LOG = "info"
//
//	[self_test]
//	command = ["{manifest_dir}/bin/mqtt-proxy", "--self-test"]
//
// Discovery (SearchPath) is the §1a list: PROTOCOL_PROXY_MANIFESTS, the user's configuration directory, this
// installation's share directory (see PrefixDirectory), then the system's configuration and data directories.
package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Filename is the manifest's name inside a proxy's own directory.
const Filename = "proxy.toml"

// EnvManifestPath names directories searched first, os.PathListSeparator-separated.
const EnvManifestPath = "PROTOCOL_PROXY_MANIFESTS"

// EnvPrefix overrides the installation prefix whose share/protocol-proxy/manifests is searched (see PrefixDirectory).
const EnvPrefix = "PROTOCOL_PROXY_PREFIX"

// Subdir is the relative directory under a configuration or data root.
var Subdir = filepath.Join("protocol-proxy", "manifests")

// Placeholders a command may use; the manager resolves them at launch.
var Placeholders = map[string]bool{"python": true, "manifest_dir": true}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Error is a manifest that cannot be used: malformed, missing a required field, or asking for something not allowed.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// Step is one normalisation step: a normaliser name ("lowercase", "strip") or a default value.
type Step struct {
	Name       string
	Default    any
	HasDefault bool
}

// Identity is how launch options select a proxy process and what remotes sharing one must agree on.
type Identity struct {
	Keys      []string
	MustMatch []string
	Normalize map[string][]Step
}

// Normalized is value of option key after the manifest's normalisers for it (a nil value takes the default).
func (id Identity) Normalized(key string, value any) any {
	for _, step := range id.Normalize[key] {
		if step.HasDefault {
			if value == nil {
				value = step.Default
			}
			continue
		}
		if s, ok := value.(string); ok {
			switch step.Name {
			case "lowercase":
				value = strings.ToLower(s)
			case "strip":
				value = strings.TrimSpace(s)
			}
		}
	}
	return value
}

// Key is the process key: the proxy name and the normalised identity options when the manifest names keys, else the
// caller's uniqueRemoteID as given (every device shares a process unless the caller groups).
func (id Identity) Key(name string, uniqueRemoteID []any, options map[string]any) []any {
	if len(id.Keys) == 0 {
		return append([]any(nil), uniqueRemoteID...)
	}
	key := make([]any, 0, len(id.Keys)+1)
	key = append(key, name)
	for _, k := range id.Keys {
		key = append(key, id.Normalized(k, options[k]))
	}
	return key
}

// Conflicts lists the must_match options on which options differs from the first remote of a shared process.
func (id Identity) Conflicts(first, options map[string]any) []string {
	var conflicts []string
	for _, k := range id.MustMatch {
		if fmt.Sprint(id.Normalized(k, first[k])) != fmt.Sprint(id.Normalized(k, options[k])) {
			conflicts = append(conflicts, k)
		}
	}
	return conflicts
}

// Manifest is one proxy's manifest.
type Manifest struct {
	Name          string
	Command       []string
	Identity      Identity
	Environment   map[string]string
	SelfTest      []string // nil when the manifest has no [self_test]
	HeaderVersion int
	Source        string // the file it was read from, "" for one built in memory
}

// Parse reads a manifest from TOML text; source names it in errors and resolves {manifest_dir}.
func Parse(text string, source string) (*Manifest, error) {
	var data map[string]any
	if _, err := toml.Decode(text, &data); err != nil {
		return nil, errorf("%s: not valid TOML: %v", where(source), err)
	}
	return FromMap(data, source)
}

// Load reads a manifest file.
func Load(path string) (*Manifest, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return Parse(string(text), abs)
}

func where(source string) string {
	if source == "" {
		return "manifest"
	}
	return source
}

// FromMap validates decoded TOML data exactly as the Python reference does.
func FromMap(data map[string]any, source string) (*Manifest, error) {
	w := where(source)
	if err := only(data, []string{"proxy", "identity", "environment", "self_test"}, w); err != nil {
		return nil, err
	}
	proxy, err := table(data, "proxy", w, true)
	if err != nil {
		return nil, err
	}
	if err := only(proxy, []string{"name", "command", "header_version"}, w+" [proxy]"); err != nil {
		return nil, err
	}
	name, _ := proxy["name"].(string)
	if name == "" || !namePattern.MatchString(name) {
		return nil, errorf("%s [proxy]: name must be a short identifier, got %#v", w, proxy["name"])
	}
	command, err := commandList(proxy["command"], w+" [proxy] command")
	if err != nil {
		return nil, err
	}
	headerVersion := 2
	if v, present := proxy["header_version"]; present {
		n, ok := v.(int64)
		if !ok || (n != 1 && n != 2) {
			return nil, errorf("%s [proxy]: header_version must be 1 or 2, got %#v", w, v)
		}
		headerVersion = int(n)
	}
	identityTable, err := table(data, "identity", w, false)
	if err != nil {
		return nil, err
	}
	identity, err := parseIdentity(identityTable, w+" [identity]")
	if err != nil {
		return nil, err
	}
	envTable, err := table(data, "environment", w, false)
	if err != nil {
		return nil, err
	}
	environment := map[string]string{}
	for k, v := range envTable {
		s, ok := v.(string)
		if !ok {
			return nil, errorf("%s [environment]: values must be strings", w)
		}
		if err := checkPlaceholders(s, w+" [environment] "+k); err != nil {
			return nil, err
		}
		environment[k] = s
	}
	selfTestTable, err := table(data, "self_test", w, false)
	if err != nil {
		return nil, err
	}
	var selfTest []string
	if len(selfTestTable) > 0 {
		if err := only(selfTestTable, []string{"command"}, w+" [self_test]"); err != nil {
			return nil, err
		}
		if selfTest, err = commandList(selfTestTable["command"], w+" [self_test] command"); err != nil {
			return nil, err
		}
	}
	return &Manifest{Name: name, Command: command, Identity: identity, Environment: environment, SelfTest: selfTest,
		HeaderVersion: headerVersion, Source: source}, nil
}

// Dir is the manifest's directory ({manifest_dir}), "" for one built in memory.
func (m *Manifest) Dir() string {
	if m.Source == "" {
		return ""
	}
	return filepath.Dir(m.Source)
}

// Resolve substitutes the placeholders of one command part.
func (m *Manifest) Resolve(part string, python string) string {
	return placeholder.ReplaceAllStringFunc(part, func(match string) string {
		switch match {
		case "{python}":
			return python
		case "{manifest_dir}":
			return m.Dir()
		}
		return match
	})
}

// LaunchCommand is the argv to start the proxy: the manifest's command with placeholders resolved, then the
// manager's standard options (--proxy-id and the rest).
func (m *Manifest) LaunchCommand(python string, standardOptions []string) []string {
	argv := make([]string, 0, len(m.Command)+len(standardOptions))
	for _, part := range m.Command {
		argv = append(argv, m.Resolve(part, python))
	}
	return append(argv, standardOptions...)
}

// ResolvedEnvironment is the [environment] table with its placeholders resolved, as the launch command's are.
func (m *Manifest) ResolvedEnvironment(python string) map[string]string {
	env := make(map[string]string, len(m.Environment))
	for k, v := range m.Environment {
		env[k] = m.Resolve(v, python)
	}
	return env
}

// SelfTestCommand is the argv of the self test with placeholders resolved, nil when there is none.
func (m *Manifest) SelfTestCommand(python string) []string {
	if m.SelfTest == nil {
		return nil
	}
	argv := make([]string, 0, len(m.SelfTest))
	for _, part := range m.SelfTest {
		argv = append(argv, m.Resolve(part, python))
	}
	return argv
}

// ProcessKey is Identity.Key for this manifest.
func (m *Manifest) ProcessKey(uniqueRemoteID []any, options map[string]any) []any {
	return m.Identity.Key(m.Name, uniqueRemoteID, options)
}

// ---- discovery -----------------------------------------------------------------------------------------------------

// PrefixDirectory is where this installation keeps manifests: <prefix>/share/protocol-proxy/manifests, the prefix
// being PROTOCOL_PROXY_PREFIX when set, else the directory above the running executable's directory (a binary at
// <prefix>/bin/<name> looks in <prefix>/share), the Go counterpart of a Python environment's sys.prefix.
func PrefixDirectory() string {
	prefix := os.Getenv(EnvPrefix)
	if prefix == "" {
		exe, err := os.Executable()
		if err != nil {
			return ""
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		prefix = filepath.Dir(filepath.Dir(exe))
	}
	return filepath.Join(prefix, "share", Subdir)
}

// SearchPath is the directories searched for manifests, most specific first: PROTOCOL_PROXY_MANIFESTS (prepended
// rather than replacing the rest), the user's configuration directory (XDG_CONFIG_HOME or ~/.config), this
// installation's share directory, then the system's configuration and data directories (XDG_CONFIG_DIRS or /etc;
// XDG_DATA_DIRS or /usr/local/share:/usr/share). Duplicates are dropped.
func SearchPath() []string {
	var dirs []string
	for _, p := range filepath.SplitList(os.Getenv(EnvManifestPath)) {
		if p != "" {
			dirs = append(dirs, expandUser(p))
		}
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configHome = filepath.Join(home, ".config")
		}
	}
	if configHome != "" {
		dirs = append(dirs, filepath.Join(configHome, Subdir))
	}
	if prefixDir := PrefixDirectory(); prefixDir != "" {
		dirs = append(dirs, prefixDir)
	}
	configDirs := os.Getenv("XDG_CONFIG_DIRS")
	if configDirs == "" {
		configDirs = "/etc"
	}
	for _, p := range filepath.SplitList(configDirs) {
		if p != "" {
			dirs = append(dirs, filepath.Join(p, Subdir))
		}
	}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	for _, p := range filepath.SplitList(dataDirs) {
		if p != "" {
			dirs = append(dirs, filepath.Join(p, Subdir))
		}
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	return unique
}

func expandUser(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// Locate is where the manifest for name is: <dir>/<name>.toml or <dir>/<name>/proxy.toml in the search path, first
// match wins. The error names every place looked.
func Locate(name string) (string, error) {
	var looked []string
	for _, dir := range SearchPath() {
		for _, candidate := range []string{filepath.Join(dir, name+".toml"), filepath.Join(dir, name, Filename)} {
			looked = append(looked, candidate)
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("no manifest for proxy %q; looked at: %s", name, strings.Join(looked, ", "))
}

// Find loads the manifest for name.
func Find(name string) (*Manifest, error) {
	path, err := Locate(name)
	if err != nil {
		return nil, err
	}
	return Load(path)
}

// Discover is every manifest reachable through the search path, by proxy name (the first found wins).
func Discover() (map[string]*Manifest, error) {
	found := map[string]*Manifest{}
	var errs []error
	for _, dir := range SearchPath() {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		var paths []string
		if matches, err := filepath.Glob(filepath.Join(dir, "*.toml")); err == nil {
			paths = append(paths, matches...)
		}
		if matches, err := filepath.Glob(filepath.Join(dir, "*", Filename)); err == nil {
			paths = append(paths, matches...)
		}
		sort.Strings(paths)
		for _, path := range paths {
			m, err := Load(path)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if _, present := found[m.Name]; !present {
				found[m.Name] = m
			}
		}
	}
	return found, errors.Join(errs...)
}

// ---- validation helpers ---------------------------------------------------------------------------------------------

func only(t map[string]any, allowed []string, w string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var unknown []string
	for k := range t {
		if !ok[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return errorf("%s: unknown keys %v; allowed: %v", w, unknown, allowed)
	}
	return nil
}

func table(data map[string]any, key, w string, required bool) (map[string]any, error) {
	v, present := data[key]
	if !present || v == nil {
		if required {
			return nil, errorf("%s: the [%s] table is required", w, key)
		}
		return map[string]any{}, nil
	}
	t, ok := v.(map[string]any)
	if !ok {
		return nil, errorf("%s: [%s] must be a table", w, key)
	}
	return t, nil
}

func commandList(value any, w string) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, errorf("%s: must be a non-empty list of strings", w)
	}
	command := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, errorf("%s: must be a non-empty list of strings", w)
		}
		if err := checkPlaceholders(s, w); err != nil {
			return nil, err
		}
		command = append(command, s)
	}
	return command, nil
}

// checkPlaceholders rejects a placeholder that is not in Placeholders (commands and environment values alike).
func checkPlaceholders(s, w string) error {
	for _, match := range placeholder.FindAllStringSubmatch(s, -1) {
		if !Placeholders[match[1]] {
			return errorf("%s: unknown placeholder {%s}; allowed: [manifest_dir python]", w, match[1])
		}
	}
	return nil
}

func names(value any, w string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, errorf("%s: must be a list of option names", w)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, errorf("%s: must be a list of option names", w)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseIdentity(t map[string]any, w string) (Identity, error) {
	var id Identity
	if err := only(t, []string{"keys", "must_match", "normalize"}, w); err != nil {
		return id, err
	}
	var err error
	if id.Keys, err = names(t["keys"], w+" keys"); err != nil {
		return id, err
	}
	if id.MustMatch, err = names(t["must_match"], w+" must_match"); err != nil {
		return id, err
	}
	known := map[string]bool{}
	for _, k := range id.Keys {
		known[k] = true
	}
	for _, k := range id.MustMatch {
		known[k] = true
	}
	id.Normalize = map[string][]Step{}
	normalize, _ := t["normalize"].(map[string]any)
	for key, raw := range normalize {
		if !known[key] {
			return id, errorf("%s.normalize: %q is not in keys or must_match", w, key)
		}
		steps, ok := raw.([]any)
		if !ok {
			return id, errorf("%s.normalize: %s must be a list of steps", w, key)
		}
		var checked []Step
		for _, step := range steps {
			switch s := step.(type) {
			case string:
				if s != "lowercase" && s != "strip" {
					return id, errorf("%s.normalize: unknown normaliser %q for %s; allowed: [lowercase strip] or { default = <value> }", w, s, key)
				}
				checked = append(checked, Step{Name: s})
			case map[string]any:
				value, present := s["default"]
				if !present || len(s) != 1 {
					return id, errorf("%s.normalize: a step is a normaliser name or { default = <value> }, got %#v", w, step)
				}
				checked = append(checked, Step{Default: value, HasDefault: true})
			default:
				return id, errorf("%s.normalize: a step is a normaliser name or { default = <value> }, got %#v", w, step)
			}
		}
		id.Normalize[key] = checked
	}
	return id, nil
}
