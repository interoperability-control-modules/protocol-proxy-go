package manager

import (
	"testing"

	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

func TestRecordFromLine(t *testing.T) {
	json := `{"name": "protocol_proxy.proxy.base", "msg": "Registered with manager", "levelno": 20, "levelname": "INFO", "process": 4242}`
	r, ok := RecordFromLine([]byte(json+"\n"), "protocol_proxy.proxies.echo.x", "stderr", 1, "x")
	if !ok || r.Level != logs.INFO || r.Message != "Registered with manager" || r.RemoteName != "protocol_proxy.proxy.base" ||
		r.Channel != "stderr" || r.PID != 4242 || r.Logger != "protocol_proxy.proxies.echo.x" {
		t.Fatalf("json record %+v", r)
	}
	r, ok = RecordFromLine([]byte("something went wrong\r\n"), "l", "stderr", 7, "x")
	if !ok || r.Level != logs.WARNING || r.Message != "something went wrong" || r.RemoteName != "stderr" || r.PID != 7 {
		t.Fatalf("plain stderr %+v", r)
	}
	r, ok = RecordFromLine([]byte("hello"), "l", "stdout", 0, "x")
	if !ok || r.Level != logs.INFO {
		t.Fatalf("plain stdout %+v", r)
	}
	r, ok = RecordFromLine([]byte("<7>detail"), "l", "stderr", 0, "x")
	if !ok || r.Level != logs.DEBUG || r.Message != "detail" {
		t.Fatalf("syslog prefix %+v", r)
	}
	r, ok = RecordFromLine([]byte("<3>bad"), "l", "stdout", 0, "x")
	if !ok || r.Level != logs.ERROR || r.Message != "bad" {
		t.Fatalf("syslog prefix %+v", r)
	}
	if _, ok := RecordFromLine([]byte("   \n"), "l", "stderr", 0, "x"); ok {
		t.Fatal("an empty line is not a record")
	}
	r, ok = RecordFromLine([]byte(`{"not": "a record"}`), "l", "stderr", 0, "x")
	if !ok || r.Level != logs.WARNING || r.Message != `{"not": "a record"}` {
		t.Fatalf("json without msg is a plain line: %+v", r)
	}
}

func TestRecordsFromBatch(t *testing.T) {
	payload := `{"records": [{"name": "a", "msg": "one", "levelno": 20}, {"name": "b", "msg": "two", "levelname": "ERROR"}], "dropped": 3}`
	records, err := RecordsFromBatch([]byte(payload), "logger", 9, "('x',)")
	if err != nil || len(records) != 3 {
		t.Fatalf("%v %d", err, len(records))
	}
	if records[0].Channel != "socket" || records[0].Message != "one" || records[0].Level != logs.INFO || records[0].PID != 9 {
		t.Fatalf("%+v", records[0])
	}
	if records[1].Level != logs.ERROR || records[1].RemoteName != "b" {
		t.Fatalf("%+v", records[1])
	}
	if records[2].Level != logs.WARNING || records[2].Message != "('x',) dropped 3 log records (rate or queue limit)." {
		t.Fatalf("%+v", records[2])
	}
	if _, err := RecordsFromBatch([]byte("nope"), "l", 0, "x"); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

func TestProxyLoggerName(t *testing.T) {
	if got := ProxyLoggerName("mqtt", "('mqtt', 'broker.example', 1883)"); got != "protocol_proxy.proxies.mqtt.mqtt_broker_example_1883" {
		t.Fatalf("%q", got)
	}
	if got := ProxyLoggerName("x", "..."); got != "protocol_proxy.proxies.x.proxy" {
		t.Fatalf("%q", got)
	}
}

func TestPyTupleAndOptions(t *testing.T) {
	if got := PyTuple([]any{"conformance"}); got != "('conformance',)" {
		t.Fatalf("%q", got)
	}
	if got := PyTuple([]any{"mqtt", "host", int64(1883), true, nil}); got != "('mqtt', 'host', 1883, True, None)" {
		t.Fatalf("%q", got)
	}
	if OptionString(true) != "true" || OptionString(false) != "false" || OptionString(7) != "7" || OptionString("s") != "s" {
		t.Fatal("option strings")
	}
	if !optBool("True", false) || optBool("off", true) || !optBool(nil, true) || !optBool(true, false) {
		t.Fatal("optBool")
	}
}
