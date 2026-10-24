package ipc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func loadVectors(t *testing.T) *Vectors {
	t.Helper()
	v, err := ParseVectors(EmbeddedVectors)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConstantsMatchVectors(t *testing.T) {
	if failures := loadVectors(t).CheckConstants(); len(failures) > 0 {
		t.Fatal(failures)
	}
}

func TestEveryVectorPacksAndUnpacks(t *testing.T) {
	v := loadVectors(t)
	if len(v.Frames) < 10 {
		t.Fatalf("only %d frame vectors", len(v.Frames))
	}
	for name, f := range v.Frames {
		t.Run(name, func(t *testing.T) {
			for _, failure := range v.CheckFrame(name, f) {
				t.Error(failure)
			}
		})
	}
}

func TestHeaderLayout(t *testing.T) {
	h := Header{Version: 1, DataLength: 5, MethodName: "PING", RequestID: 7}
	b, err := h.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != VersionWordBytes+HeaderLengthV1 {
		t.Fatalf("v1 header is %d bytes", len(b))
	}
	h.Version = 2
	if b, _ = h.Pack(); len(b) != VersionWordBytes+HeaderLengthV2 {
		t.Fatalf("v2 header is %d bytes", len(b))
	}
	back, err := Unpack(b)
	if err != nil || back != h {
		t.Fatalf("round trip %+v -> %+v (%v)", h, back, err)
	}
}

func TestPackRefusesWhatDoesNotFit(t *testing.T) {
	if _, err := (&Header{Version: 1, RequestID: 70000, MethodName: "X"}).Pack(); err == nil {
		t.Error("a 32-bit request id packed into a version 1 header")
	}
	if _, err := (&Header{Version: 2, MethodName: string(make([]byte, 33))}).Pack(); err == nil {
		t.Error("a 33-byte method name packed")
	}
	if _, err := (&Header{Version: 1, MethodName: "X", RemoteID: MustUUID("99999999-8888-7777-6666-555555555555")}).Pack(); err == nil {
		t.Error("a remote id packed into a version 1 header")
	}
	if _, err := (&Header{Version: 3, MethodName: "X"}).Pack(); err == nil {
		t.Error("version 3 packed")
	}
	raw, _ := hex.DecodeString("0003" + "00")
	if _, err := Unpack(raw); err == nil {
		t.Error("version 3 unpacked")
	}
}

func TestRequestIDsCycleFromOne(t *testing.T) {
	var ids RequestIDs
	if first := ids.Next(2); first != 1 {
		t.Fatalf("first id %d", first)
	}
	if second := ids.Next(1); second != 1 {
		t.Fatalf("version 1 counter did not start at 1: %d", second)
	}
	ids.next[1] = RequestIDMaxV1 - 1
	if id := ids.Next(1); id != RequestIDMaxV1-1 {
		t.Fatalf("got %d", id)
	}
	if id := ids.Next(1); id != 1 {
		t.Fatalf("version 1 ids did not wrap to 1: %d", id)
	}
}

func TestFrameReaderNeedsWholeFrames(t *testing.T) {
	v := loadVectors(t)
	frame, _ := hex.DecodeString(v.Frames["v1_request"].FrameHex)
	if _, _, _, err := readFrame(bytes.NewReader(frame[:len(frame)-1])); err == nil {
		t.Error("a frame cut inside the payload was read")
	}
	if _, _, _, err := readFrame(bytes.NewReader(frame[:10])); err == nil {
		t.Error("a frame cut inside the header was read")
	}
	if _, _, _, err := readFrame(bytes.NewReader(nil)); err == nil {
		t.Error("EOF not reported")
	}
}
