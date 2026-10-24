package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

func TestParseArgsStandardLine(t *testing.T) {
	opts, err := ParseArgs(strings.Fields("--proxy-id 11111111222233334444555555555555 --proxy-name x --manager-id " +
		"aaaaaaaabbbbccccddddeeeeeeeeeeee --manager-address 127.0.0.1 --manager-port 22815 --inbound-address 127.0.0.1 " +
		"--inbound-port 42764 --encrypt true --cipher aes-256-gcm --ipc-tls false --manager-dials true --persistent false " +
		"--socket-logging true --compress-threshold 0 --log-level DEBUG --host example.org --password s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if opts.ProxyID.Hex() != "11111111222233334444555555555555" || opts.ManagerPort != 22815 || opts.InboundPort != 42764 ||
		!opts.Encrypt || opts.Cipher != ipc.CipherAES256GCM || opts.IPCTLS || !opts.ManagerDials || opts.Persistent ||
		opts.CompressThreshold != 0 || opts.LogLevel != "DEBUG" {
		t.Fatalf("%+v", opts)
	}
	if opts.Extra["host"] != "example.org" || opts.Extra["password"] != "s3cret" {
		t.Fatalf("protocol options %v", opts.Extra)
	}
	if red := opts.Redacted(); strings.Contains(red, "s3cret") || !strings.Contains(red, `password="***"`) {
		t.Fatal(red)
	}
	if _, err := ParseArgs([]string{"--proxy-name", "x"}); err == nil || !strings.Contains(err.Error(), "--proxy-id") {
		t.Fatalf("missing options not reported: %v", err)
	}
	if _, err := ParseArgs(strings.Fields("--proxy-id 1 --proxy-name x --manager-id 2")); err == nil {
		t.Fatal("bad uuid accepted")
	}
	if _, err := ParseArgs(strings.Fields("--proxy-id 11111111222233334444555555555555 --proxy-name x --manager-id " +
		"aaaaaaaabbbbccccddddeeeeeeeeeeee --encrypt maybe")); err == nil {
		t.Fatal("bad boolean accepted")
	}
	opts, err = ParseArgs([]string{"--self-test"})
	if err != nil || !opts.SelfTest {
		t.Fatal(err)
	}
	opts, err = ParseArgs([]string{"--self-test", "/tmp/v.json"})
	if err != nil || !opts.SelfTest || opts.Vectors != "/tmp/v.json" {
		t.Fatal(err, opts)
	}
}

func TestReadHandshake(t *testing.T) {
	proxyToken, managerToken := ipc.NewUUID(), ipc.NewUUID()
	key, _ := ipc.NewKey()
	material := &ipc.TLSMaterial{CA: "ca", Cert: "cert", Key: "key"}
	line, _ := material.Line()
	var stdin bytes.Buffer
	stdin.WriteString(proxyToken.Hex())
	stdin.WriteString(managerToken.Hex())
	stdin.WriteString(strings.ToLower(bytesHex(key)))
	stdin.Write(line)
	hs, err := ReadHandshake(&stdin, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if hs.ProxyToken != proxyToken || hs.ManagerToken != managerToken || !bytes.Equal(hs.Key, key) || hs.TLS.Cert != "cert" {
		t.Fatalf("%+v", hs)
	}
	if _, err := ReadHandshake(strings.NewReader(proxyToken.Hex()), false, false); err == nil {
		t.Fatal("half a handshake accepted")
	}
	if _, err := ReadHandshake(strings.NewReader(proxyToken.Hex()+managerToken.Hex()), true, false); err == nil {
		t.Fatal("--encrypt without a key accepted")
	}
	if _, err := ReadHandshake(strings.NewReader(proxyToken.Hex()+managerToken.Hex()), false, true); err == nil {
		t.Fatal("--ipc-tls without material accepted")
	}
	if hs, err := ReadHandshake(strings.NewReader(proxyToken.Hex()+managerToken.Hex()), false, false); err != nil || hs.Key != nil {
		t.Fatal(err)
	}
}

func bytesHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestRegistrationReplies(t *testing.T) {
	ok, features := RegistrationAccepted([]byte(`{"registered": true, "features": ["compress", "aead-chacha20poly1305"]}`))
	if !ok || len(features) != 2 {
		t.Fatal(ok, features)
	}
	if ok, _ := RegistrationAccepted([]byte(`{"registered": false}`)); ok {
		t.Fatal("refused registration read as accepted")
	}
	if ok, _ := RegistrationAccepted([]byte(`{"status": "error", "error": "x", "method": "REGISTER_PEER"}`)); ok {
		t.Fatal("error reply read as accepted")
	}
	if ok, _ := RegistrationAccepted([]byte(`true`)); !ok {
		t.Fatal("old-style true refused")
	}
	if ok, _ := RegistrationAccepted([]byte(`not json`)); ok {
		t.Fatal("garbage accepted")
	}
}

func TestSetLogLevelAndHealth(t *testing.T) {
	logger := logs.New(logs.INFO, nil)
	var reply map[string]string
	_ = json.Unmarshal(SetLogLevelReply(logger, []byte(`{"level": "debug"}`)), &reply)
	if reply["level"] != "DEBUG" || logger.Level() != logs.DEBUG {
		t.Fatal(reply)
	}
	_ = json.Unmarshal(SetLogLevelReply(logger, []byte(`{"level": 30}`)), &reply)
	if reply["level"] != "WARNING" {
		t.Fatal(reply)
	}
	_ = json.Unmarshal(SetLogLevelReply(logger, []byte(`{"level": "LOUD"}`)), &reply)
	if reply["status"] != "error" || reply["method"] != MethodSetLogLevel || logger.Level() != logs.WARNING {
		t.Fatal(reply)
	}
	conn, _ := ipc.New(ipc.Options{ID: ipc.NewUUID(), Token: ipc.NewUUID()})
	out, _ := json.Marshal(Health(conn))
	var health map[string]any
	_ = json.Unmarshal(out, &health)
	if _, ok := health["uptime"].(float64); !ok || health["remotes"] != float64(0) || health["busy"] != false || health["last_activity"] != nil {
		t.Fatalf("%s", out)
	}
}

func TestSelfTestPasses(t *testing.T) {
	var report bytes.Buffer
	if failures := SelfTest(nil, &report); failures != 0 {
		t.Fatal(report.String())
	}
	if !strings.Contains(report.String(), "ok   frame v2_encrypted_aes_gcm") {
		t.Fatal(report.String())
	}
}
