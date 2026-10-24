package logs

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONLineRecords(t *testing.T) {
	var out bytes.Buffer
	logger := New(INFO, &StreamSink{W: &out, JSON: true})
	logger.Debugf("x", "hidden")
	logger.Warningf("protocol_proxy_go.test", "device %s offline", "d1")
	line := strings.TrimSpace(out.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("expected one line, got %q", line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"name", "levelno", "levelname", "pathname", "lineno", "funcName", "created", "msecs", "process", "msg"} {
		if _, ok := record[key]; !ok {
			t.Errorf("record lacks %s", key)
		}
	}
	if record["msg"] != "device d1 offline" || record["levelno"] != float64(30) || record["levelname"] != "WARNING" {
		t.Fatal(record)
	}
}

func TestLevels(t *testing.T) {
	for input, want := range map[any]Level{"debug": DEBUG, "INFO": INFO, "Warn": WARNING, "warning": WARNING, "ERROR": ERROR,
		"critical": CRITICAL, "fatal": CRITICAL, float64(20): INFO, "40": ERROR} {
		if got, err := ParseLevel(input); err != nil || got != want {
			t.Errorf("%v -> %v, %v", input, got, err)
		}
	}
	if _, err := ParseLevel("LOUD"); err == nil {
		t.Error("LOUD accepted")
	}
	if LevelName(25) != "Level 25" || LevelName(WARNING) != "WARNING" {
		t.Error(LevelName(25))
	}
}

func TestQueueBoundsAndCounts(t *testing.T) {
	q := &Queue{MaxLen: 3, Rate: 1000, Burst: 1000, tokens: 1000}
	for i := 0; i < 5; i++ {
		q.Emit(Record{"i": i})
	}
	records, dropped := q.Drain(2)
	if len(records) != 2 || dropped != 2 || q.Len() != 1 {
		t.Fatal(len(records), dropped, q.Len())
	}
	if records, dropped = q.Drain(0); len(records) != 1 || dropped != 0 {
		t.Fatal(len(records), dropped)
	}
	payload, _ := MarshalBatch(nil, 0)
	if string(payload) != `{"records":[],"dropped":0}` {
		t.Fatal(string(payload))
	}
}
