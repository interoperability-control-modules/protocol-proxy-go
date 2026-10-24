package manager

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

// ProxiesLogger is the logger name under which every launched proxy's records are handled in the manager's process:
// one child per manifest and proxy, protocol_proxy.proxies.<manifest name>.<proxy name>.
const ProxiesLogger = "protocol_proxy.proxies"

// Default level of a plain (non-JSON) line, by the stream it arrived on (PROTOCOL.md §9).
var streamDefaultLevels = map[string]logs.Level{"stdout": logs.INFO, "stderr": logs.WARNING}

// A plain line may start with a syslog-style severity, <7> (debug) to <0> (emergency), which sets its level.
var syslogLevels = map[byte]logs.Level{'7': logs.DEBUG, '6': logs.INFO, '5': logs.INFO, '4': logs.WARNING, '3': logs.ERROR,
	'2': logs.CRITICAL, '1': logs.CRITICAL, '0': logs.CRITICAL}

var unsafeLoggerChars = regexp.MustCompile(`[^A-Za-z0-9\-]+`)

// ProxyLoggerName is the manager-side logger for one launched proxy, the proxy name reduced to logger-safe
// characters (dots would create further hierarchy): protocol_proxy.proxies.<manifest>.<safe name>.
func ProxyLoggerName(manifestName, proxyName string) string {
	var parts []string
	for _, part := range unsafeLoggerChars.Split(proxyName, -1) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	safe := strings.Join(parts, "_")
	if safe == "" {
		safe = "proxy"
	}
	return ProxiesLogger + "." + manifestName + "." + safe
}

// Record is one log record from a launched proxy, as the manager handles it: rebuilt from a JSON line on a pipe,
// an entry of a LOG batch, or a plain line.
type Record struct {
	// Logger is the manager-side logger name (ProxyLoggerName); RemoteName the proxy's own logger name, or the
	// stream a plain line came from.
	Logger     string
	RemoteName string
	// Channel is where the record arrived: "stdout", "stderr" or "socket".
	Channel string
	Level   logs.Level
	Message string
	ExcText string
	// Fields are the wire fields of a JSON record (nil for a plain line).
	Fields logs.Record
	// Proxy and PID identify the sender.
	Proxy string
	PID   int
}

// RecordHandler receives a launched proxy's records. The manager calls it from the goroutines reading the proxy's
// pipes and from the connector's LOG handler, so it must be safe for concurrent use.
type RecordHandler interface {
	HandleRecord(record Record)
}

// RecordHandlerFunc adapts a function to RecordHandler.
type RecordHandlerFunc func(record Record)

// HandleRecord calls f.
func (f RecordHandlerFunc) HandleRecord(record Record) { f(record) }

// LoggerRecordHandler forwards records to a logs.Logger under the manager-side logger name, with the proxy's own
// logger name and the channel appended to the message for a reader (the default when no handler is given).
type LoggerRecordHandler struct{ Logger *logs.Logger }

// HandleRecord logs the record.
func (h LoggerRecordHandler) HandleRecord(record Record) {
	msg := record.Message
	if record.RemoteName != "" && record.RemoteName != record.Channel {
		msg = fmt.Sprintf("[%s] %s", record.RemoteName, msg)
	}
	h.Logger.Log(record.Level, record.Logger, msg, record.ExcText)
}

// RecordFromFields rebuilds a record from its wire fields (a JSON line or one entry of a LOG batch), attributed to
// loggerName with the sender's own logger name in RemoteName and the channel it arrived by in Channel.
func RecordFromFields(fields logs.Record, loggerName, channel string, pid int, proxyName string) Record {
	record := Record{Logger: loggerName, Channel: channel, Fields: fields, Proxy: proxyName, PID: pid}
	record.RemoteName, _ = fields["name"].(string)
	record.Message = fmt.Sprint(fields["msg"])
	if fields["msg"] == nil {
		record.Message = ""
	}
	if text, ok := fields["exc_text"].(string); ok {
		record.ExcText = text
	}
	if level, err := logs.ParseLevel(fields["levelno"]); err == nil {
		record.Level = level
	} else if level, err := logs.ParseLevel(fields["levelname"]); err == nil {
		record.Level = level
	} else {
		record.Level = logs.INFO
	}
	if p, ok := fields["process"].(float64); ok && p != 0 {
		record.PID = int(p)
	}
	return record
}

// RecordFromLine turns one line read from a proxy's stdout or stderr into a Record for loggerName. A JSON object
// with a msg field is rebuilt from its fields; a plain line becomes a record at the stream's default level (stderr
// WARNING, stdout INFO) or at the level a leading <N> syslog prefix names, with RemoteName set to the stream.
// ok is false for an empty line.
func RecordFromLine(raw []byte, loggerName, stream string, pid int, proxyName string) (record Record, ok bool) {
	line := strings.TrimRight(string(raw), "\r\n")
	if strings.TrimSpace(line) == "" {
		return Record{}, false
	}
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		var fields logs.Record
		if err := json.Unmarshal([]byte(line), &fields); err == nil {
			if _, hasMsg := fields["msg"]; hasMsg {
				return RecordFromFields(fields, loggerName, stream, pid, proxyName), true
			}
		}
	}
	level, known := streamDefaultLevels[stream]
	if !known {
		level = logs.WARNING
	}
	if len(line) > 2 && line[0] == '<' && line[2] == '>' {
		if l, ok := syslogLevels[line[1]]; ok {
			level, line = l, line[3:]
		}
	}
	return Record{Logger: loggerName, RemoteName: stream, Channel: stream, Level: level, Message: line, Proxy: proxyName,
		PID: pid}, true
}

// Batch is the payload of a LOG message: {"records": [fields...], "dropped": n}.
type Batch struct {
	Records []logs.Record `json:"records"`
	Dropped int           `json:"dropped"`
}

// RecordsFromBatch rebuilds the records of one LOG batch (channel "socket"); a dropped count becomes one WARNING
// at the end, as the Python manager logs it.
func RecordsFromBatch(payload []byte, loggerName string, pid int, proxyName string) ([]Record, error) {
	var batch Batch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(batch.Records)+1)
	for _, fields := range batch.Records {
		records = append(records, RecordFromFields(fields, loggerName, "socket", pid, proxyName))
	}
	if batch.Dropped > 0 {
		records = append(records, Record{Logger: loggerName, RemoteName: "protocol_proxy.logs", Channel: "socket",
			Level: logs.WARNING, Proxy: proxyName, PID: pid,
			Message: fmt.Sprintf("%s dropped %d log records (rate or queue limit).", proxyName, batch.Dropped)})
	}
	return records, nil
}

// readRecords reads a proxy's pipe line by line until EOF and handles each record at or above level.
func readRecords(r io.Reader, stream, loggerName string, pid int, proxyName string, level func() logs.Level,
	handler RecordHandler) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		record, ok := RecordFromLine(scanner.Bytes(), loggerName, stream, pid, proxyName)
		if ok && record.Level >= level() {
			handler.HandleRecord(record)
		}
	}
}
