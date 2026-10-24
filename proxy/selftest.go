package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

// SelfTest checks this implementation against a test_vectors.json (the embedded copy when data is nil): the
// constants, every frame vector packed and unpacked, and the log channel examples. It writes a report to w and
// returns the number of failures.
func SelfTest(data []byte, w io.Writer) int {
	if data == nil {
		data = ipc.EmbeddedVectors
	}
	vectors, err := ipc.ParseVectors(data)
	if err != nil {
		fmt.Fprintln(w, "FAIL", err)
		return 1
	}
	var failures []string
	report := func(name string, problems []string) {
		if len(problems) == 0 {
			fmt.Fprintf(w, "ok   %s\n", name)
			return
		}
		for _, problem := range problems {
			fmt.Fprintf(w, "FAIL %s: %s\n", name, problem)
		}
		failures = append(failures, problems...)
	}
	report("constants", vectors.CheckConstants())
	names := make([]string, 0, len(vectors.Frames))
	for name := range vectors.Frames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		report("frame "+name, vectors.CheckFrame(name, vectors.Frames[name]))
	}
	report("log channel", checkLogChannel(vectors))
	fmt.Fprintf(w, "%d checks, %d failures\n", 2+len(names), len(failures))
	return len(failures)
}

func checkLogChannel(v *ipc.Vectors) []string {
	var problems []string
	var record map[string]any
	if err := json.Unmarshal([]byte(v.LogChannel.JSONLine), &record); err != nil {
		problems = append(problems, "json_line does not parse: "+err.Error())
	} else {
		logger := logs.New(logs.DEBUG, nil)
		captured := &captureSink{}
		logger.SetSink(captured)
		logger.Warningf("protocol_proxy_go.selftest", "device %s offline", "d1")
		for _, key := range []string{"name", "levelno", "levelname", "pathname", "lineno", "funcName", "created", "msecs",
			"process", "msg"} {
			if _, ok := record[key]; !ok {
				problems = append(problems, "json_line lacks "+key)
			}
			if _, ok := captured.last[key]; !ok {
				problems = append(problems, "our record lacks "+key)
			}
		}
		if captured.last["msg"] != record["msg"] || captured.last["levelno"] != 30 {
			problems = append(problems, fmt.Sprintf("our record %v does not interpolate like the vector's", captured.last["msg"]))
		}
	}
	var batch logs.Batch
	if err := json.Unmarshal([]byte(v.LogChannel.LogBatchPayload), &batch); err != nil || len(batch.Records) != 1 || batch.Dropped != 2 {
		problems = append(problems, "log_batch_payload does not read as records + dropped")
	}
	if out, err := logs.MarshalBatch(batch.Records, batch.Dropped); err != nil || !jsonEqual(out, []byte(v.LogChannel.LogBatchPayload)) {
		problems = append(problems, "our LOG batch differs from the vector's")
	}
	logger := logs.New(logs.INFO, nil)
	reply := SetLogLevelReply(logger, []byte(v.LogChannel.SetLogLevelRequest))
	if !jsonEqual(reply, []byte(v.LogChannel.SetLogLevelReply)) || logger.Level() != logs.DEBUG {
		problems = append(problems, fmt.Sprintf("SET_LOG_LEVEL reply %s, expected %s", reply, v.LogChannel.SetLogLevelReply))
	}
	var example map[string]any
	if err := json.Unmarshal([]byte(v.LogChannel.PingReplyExample), &example); err != nil {
		problems = append(problems, "ping_reply_example does not parse")
	} else {
		conn, _ := ipc.New(ipc.Options{ID: ipc.NewUUID(), Token: ipc.NewUUID()})
		ours, _ := json.Marshal(Health(conn))
		var health map[string]any
		_ = json.Unmarshal(ours, &health)
		for key := range example {
			if _, ok := health[key]; !ok {
				problems = append(problems, "our PING reply lacks "+key)
			}
		}
	}
	accepted, features := RegistrationAccepted([]byte(v.LogChannel.RegisterPeerReply))
	if !accepted || !reflect.DeepEqual(features, ipc.ConnectorFeatures) {
		problems = append(problems, fmt.Sprintf("register_peer_reply read as accepted=%v features=%v", accepted, features))
	}
	if accepted, _ := RegistrationAccepted([]byte("true")); !accepted {
		problems = append(problems, "plain true registration reply not accepted")
	}
	if accepted, _ := RegistrationAccepted([]byte("false")); accepted {
		problems = append(problems, "plain false registration reply accepted")
	}
	return problems
}

type captureSink struct{ last logs.Record }

func (s *captureSink) Emit(r logs.Record) { s.last = r }

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// RunSelfTest is the --self-test entry point: vectors from path (the embedded copy when ""), report on stdout,
// exit status 0 when every check passes.
func RunSelfTest(path string) int {
	var data []byte
	if path != "" {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if SelfTest(data, os.Stdout) > 0 {
		return 1
	}
	return 0
}
