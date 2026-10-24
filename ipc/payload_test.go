package ipc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCompressionRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"a": 1}`), 1000)
	z, err := Compress(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(z) >= len(payload) {
		t.Fatalf("compressed %d bytes to %d", len(payload), len(z))
	}
	if z[0] != 0x78 {
		t.Fatalf("not zlib framing: first byte %#x", z[0])
	}
	back, err := Decompress(z)
	if err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := Decompress([]byte("not zlib")); err == nil {
		t.Error("corrupt data decompressed")
	}
}

func TestPythonCompressedVectorDecompresses(t *testing.T) {
	v := loadVectors(t)
	f := v.Frames["v2_compressed"]
	frame, _ := hex.DecodeString(f.FrameHex)
	header, _ := hex.DecodeString(f.HeaderHex)
	plain, err := Decompress(frame[len(header):])
	if err != nil || string(plain) != f.PayloadUTF8 {
		t.Fatalf("Python's zlib output did not decompress: %v", err)
	}
}

func TestAEADRoundTrips(t *testing.T) {
	key, _ := NewKey()
	header := []byte("associated data: the header as sent")
	payload := []byte(`{"values": {"a": 1}}`)
	for _, aes := range []bool{false, true} {
		body, err := Seal(key, header, payload, aes)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != len(payload)+NonceBytes+TagBytes {
			t.Fatalf("aes=%v: wire payload is %d bytes", aes, len(body))
		}
		plain, err := Open(key, header, body, aes)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("aes=%v: open failed: %v", aes, err)
		}
		if _, err := Open(key, append([]byte("x"), header...), body, aes); err == nil {
			t.Errorf("aes=%v: altered associated data accepted", aes)
		}
		tampered := append([]byte(nil), body...)
		tampered[NonceBytes] ^= 1
		if _, err := Open(key, header, tampered, aes); err == nil {
			t.Errorf("aes=%v: tampered ciphertext accepted", aes)
		}
		if _, err := Open(key, header, body, !aes); err == nil {
			t.Errorf("aes=%v: opened with the other cipher", aes)
		}
		other, _ := NewKey()
		if _, err := Open(other, header, body, aes); err == nil {
			t.Errorf("aes=%v: opened with another key", aes)
		}
		if _, err := Open(key, header, body[:NonceBytes+TagBytes-1], aes); err == nil {
			t.Errorf("aes=%v: a too-short payload was opened", aes)
		}
	}
	if _, err := Seal(key[:16], header, payload, false); err == nil {
		t.Error("a 16-byte key was accepted")
	}
}

func TestEncryptedVectorsOpenUnderTheirHeaders(t *testing.T) {
	v := loadVectors(t)
	key, _ := hex.DecodeString(v.Identities.KeyHex)
	for _, name := range []string{"v2_encrypted", "v2_encrypted_aes_gcm", "v2_compressed_encrypted"} {
		f := v.Frames[name]
		frame, _ := hex.DecodeString(f.FrameHex)
		header, _ := hex.DecodeString(f.HeaderHex)
		plain, err := Open(key, header, frame[len(header):], f.AESGCM)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.Compressed {
			if plain, err = Decompress(plain); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if string(plain) != f.PayloadUTF8 {
			t.Fatalf("%s: payload %q", name, plain)
		}
	}
}

func TestCipherResolution(t *testing.T) {
	if cpuinfoHasAES("flags\t\t: fpu vme aes sse2\n") != true {
		t.Error("aes flag not seen")
	}
	if cpuinfoHasAES("flags\t\t: fpu vme sse2\n") {
		t.Error("aes flag invented")
	}
	if cpuinfoHasAES("Features\t: fp asimd aes\n") != true {
		t.Error("Arm aes feature not seen")
	}
	if _, err := ResolveCipher("rot13"); err == nil {
		t.Error("unknown cipher accepted")
	}
	if name, err := ResolveCipher(CipherAES256GCM); err != nil || name != CipherAES256GCM {
		t.Error(name, err)
	}
	if name, err := ResolveCipher("auto"); err != nil || (name != CipherAES256GCM && name != CipherChaCha20Poly1305) {
		t.Error(name, err)
	}
	if feature, aes, _ := CipherFeature(CipherAES256GCM); feature != FeatureAES256GCM || !aes {
		t.Error(feature, aes)
	}
}
