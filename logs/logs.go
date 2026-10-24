// Package logs is the logging pipeline of a proxy process: records in the shape of a Python LogRecord, written as
// one JSON object per line on stderr before registration (and again for whatever is queued at exit), or queued for
// the proxy to ship to its manager in LOG batches over the socket (PROTOCOL.md §9).
package logs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is a Python logging level number.
type Level int

const (
	DEBUG    Level = 10
	INFO     Level = 20
	WARNING  Level = 30
	ERROR    Level = 40
	CRITICAL Level = 50
)

// LaunchedByManagerEnv is set in a proxy's environment by the manager that launched it; with stderr a pipe, it
// selects the JSON record channel.
const LaunchedByManagerEnv = "_LAUNCHED_BY_PROXY_MANAGER"

var levelNames = map[Level]string{DEBUG: "DEBUG", INFO: "INFO", WARNING: "WARNING", ERROR: "ERROR", CRITICAL: "CRITICAL"}

// LevelName is Python's logging.getLevelName for a level number.
func LevelName(level Level) string {
	if name, ok := levelNames[level]; ok {
		return name
	}
	return fmt.Sprintf("Level %d", int(level))
}

// ParseLevel reads a level as Python's logging accepts it: a name (any case, WARN and FATAL included) or a number.
func ParseLevel(value any) (Level, error) {
	switch v := value.(type) {
	case float64:
		return Level(int(v)), nil
	case int:
		return Level(v), nil
	case string:
		upper := strings.ToUpper(strings.TrimSpace(v))
		switch upper {
		case "WARN":
			return WARNING, nil
		case "FATAL":
			return CRITICAL, nil
		}
		for level, name := range levelNames {
			if name == upper {
				return level, nil
			}
		}
		var n int
		if _, err := fmt.Sscanf(upper, "%d", &n); err == nil && fmt.Sprint(n) == upper {
			return Level(n), nil
		}
		return 0, fmt.Errorf("Unknown level: %q", v)
	}
	return 0, fmt.Errorf("Level not an integer or a valid string: %v", value)
}

// Record is one log record in wire form: the Python LogRecord attribute names, msg already interpolated.
type Record map[string]any

// Sink receives records from a Logger.
type Sink interface {
	Emit(Record)
}

// Logger produces records at or above its level and hands them to its sink. It is safe for concurrent use.
type Logger struct {
	mu          sync.RWMutex
	level       Level
	sink        Sink
	process     int
	processName string
	// Name prefixes every record's logger name (the Python package the manager expects, e.g. protocol_proxy).
	Name string
}

// New makes a logger at level writing to sink.
func New(level Level, sink Sink) *Logger {
	return &Logger{level: level, sink: sink, process: os.Getpid(), processName: filepath.Base(os.Args[0])}
}

// Level is the level in force.
func (l *Logger) Level() Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

// SetLevel changes the level in force.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Sink is the current sink.
func (l *Logger) Sink() Sink {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sink
}

// SetSink replaces the sink (stderr before registration, a Queue after).
func (l *Logger) SetSink(sink Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = sink
}

// Enabled reports whether a record at level would be emitted.
func (l *Logger) Enabled(level Level) bool {
	return level >= l.Level()
}

// Log emits one record under logger name with the given message and optional traceback text.
func (l *Logger) Log(level Level, name, msg string, excText string) {
	if !l.Enabled(level) {
		return
	}
	now := time.Now()
	pathname, line, funcName := caller(3)
	record := Record{
		"name": name, "msg": msg, "levelname": LevelName(level), "levelno": int(level),
		"pathname": pathname, "filename": filepath.Base(pathname), "module": strings.TrimSuffix(filepath.Base(pathname), ".go"),
		"lineno": line, "funcName": funcName,
		"created": float64(now.UnixNano()) / 1e9, "msecs": float64(now.Nanosecond() / 1e6),
		"process": l.process, "processName": l.processName, "thread": 1, "threadName": "MainThread",
		"exc_text": nil, "stack_info": nil, "taskName": nil,
	}
	if excText != "" {
		record["exc_text"] = excText
	}
	if sink := l.Sink(); sink != nil {
		sink.Emit(record)
	}
}

func caller(skip int) (string, int, string) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "?", 0, "?"
	}
	name := "?"
	if fn := runtime.FuncForPC(pc); fn != nil {
		name = fn.Name()
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
	}
	return file, line, name
}

// Debugf, Infof, Warningf and Errorf format a message and log it under name.
func (l *Logger) Debugf(name, format string, args ...any)   { l.logf(DEBUG, name, format, args...) }
func (l *Logger) Infof(name, format string, args ...any)    { l.logf(INFO, name, format, args...) }
func (l *Logger) Warningf(name, format string, args ...any) { l.logf(WARNING, name, format, args...) }
func (l *Logger) Errorf(name, format string, args ...any)   { l.logf(ERROR, name, format, args...) }

func (l *Logger) logf(level Level, name, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.Log(level, name, fmt.Sprintf(format, args...), "")
}

// ---- sinks ---------------------------------------------------------------------------------------------------------

// StreamSink writes records to a stream: as JSON lines (what a manager reads from the proxy's stderr pipe) or in a
// readable text format for a proxy run by hand.
type StreamSink struct {
	mu   sync.Mutex
	W    io.Writer
	JSON bool
}

// Emit writes one record.
func (s *StreamSink) Emit(record Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.JSON {
		line, err := json.Marshal(record)
		if err != nil {
			return
		}
		_, _ = s.W.Write(append(line, '\n'))
		return
	}
	created, _ := record["created"].(float64)
	stamp := time.Unix(0, int64(created*1e9)).Format("2006-01-02 15:04:05,000")
	_, _ = fmt.Fprintf(s.W, "%s %v %v: %v\n", stamp, record["name"], record["levelname"], record["msg"])
	if exc, ok := record["exc_text"].(string); ok && exc != "" {
		_, _ = fmt.Fprintln(s.W, exc)
	}
}

// WriteJSONLine writes one record straight to stderr as a JSON line (used for what is still queued at exit).
func WriteJSONLine(w io.Writer, record Record) {
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	_, _ = w.Write(append(line, '\n'))
}

// UseJSONChannel reports whether this process should write JSON records: launched by a manager (the environment
// marker) with stderr a pipe.
func UseJSONChannel() bool {
	if _, launched := os.LookupEnv(LaunchedByManagerEnv); !launched {
		return false
	}
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeNamedPipe != 0
}

// Queue holds records for a proxy to ship in LOG batches. Emit never blocks and never does I/O; the queue is bounded
// and token-bucket rate-limited (rate records per second sustained, burst at once). Records beyond either are
// dropped and counted; the count travels in the next batch.
type Queue struct {
	mu       sync.Mutex
	records  []Record
	MaxLen   int
	Rate     float64
	Burst    int
	tokens   float64
	refilled time.Time
	dropped  int
	// TotalDropped counts every record dropped over the queue's life.
	TotalDropped int
}

// NewQueue makes a queue with the Python defaults: 2000 records, 50/s sustained, 200 burst.
func NewQueue() *Queue {
	return &Queue{MaxLen: 2000, Rate: 50, Burst: 200, tokens: 200, refilled: time.Now()}
}

func (q *Queue) takeToken() bool {
	now := time.Now()
	q.tokens = min(float64(q.Burst), q.tokens+now.Sub(q.refilled).Seconds()*q.Rate)
	q.refilled = now
	if q.tokens >= 1 {
		q.tokens--
		return true
	}
	return false
}

// Emit queues a record or counts it as dropped.
func (q *Queue) Emit(record Record) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.records) >= q.MaxLen || !q.takeToken() {
		q.dropped++
		q.TotalDropped++
		return
	}
	q.records = append(q.records, record)
}

// Len is the number of queued records.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.records)
}

// Drain takes up to limit queued records (all when limit <= 0) and the count dropped since the last drain.
func (q *Queue) Drain(limit int) ([]Record, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := len(q.records)
	if limit > 0 && limit < n {
		n = limit
	}
	taken := make([]Record, n)
	copy(taken, q.records[:n])
	q.records = append([]Record(nil), q.records[n:]...)
	dropped := q.dropped
	q.dropped = 0
	return taken, dropped
}

// Batch is the payload of a LOG message.
type Batch struct {
	Records []Record `json:"records"`
	Dropped int      `json:"dropped"`
}

// MarshalBatch is the JSON of a LOG payload with deterministic key order inside each record.
func MarshalBatch(records []Record, dropped int) ([]byte, error) {
	if records == nil {
		records = []Record{}
	}
	return json.Marshal(Batch{Records: records, Dropped: dropped})
}

// Keys lists a record's keys in order (for tests).
func (r Record) Keys() []string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
