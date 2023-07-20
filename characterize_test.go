package characterize

import (
	"fmt"
	"io/ioutil"
	"testing"
	"unicode/utf8"
)

type item struct {
	name   string
	expect CharType
}

var suite = []item{
	{"examples/ascii.txt", ASCII},
	{"examples/utf8.txt", UTF8},
	{"examples/utf8_BOM.txt", UTF8BOM},
	{"examples/utf16be.txt", UTF16BE},
	{"examples/utf16le.txt", UTF16LE},
	{"examples/ebcdic.txt", LATIN1},     // unfortunately my example ebdic file is latin1 too
	{"examples/twilight.txt", EXTENDED}, // from twilight.zip
}

var thorsted = []byte{0x43, 0x48, 0x5F, 0x32, 0x2E, 0x70, 0x64, 0x66, 0x0A, 0xD0, 0xA1, 0x48, 0x5F, 0x33, 0x2E, 0x70, 0x64, 0x66, 0x0A}

func ExampleUTF8() {
	fmt.Print(string(thorsted))
	fmt.Print(Detect(thorsted))
	// Output:
	// CH_2.pdf
	// СH_3.pdf
	// UTF-8 Unicode
}

func TestDetect(t *testing.T) {
	for _, v := range suite {
		buf, err := ioutil.ReadFile(v.name)
		if err != nil {
			t.Fatalf("failed to open %s, got: %v", v.name, err)
		}
		det := Detect(buf)
		if det != v.expect {
			t.Errorf("failed to detect %s: expecting %s, got %s", v.name, v.expect, det)
		}
	}
}

func TestZipName(t *testing.T) {
	buf, err := ioutil.ReadFile("examples/twilight.txt")
	if err != nil {
		t.Fatalf("failed to open twilight.txt, got: %v", err)
	}
	nm := ZipName(string(buf))
	if !utf8.Valid([]byte(nm)) {
		t.Fatalf("not valid: %s", nm)
	}
	raw := "±æ∞∏À˘‘⁄≤„(1-4).dwg"
	nm = ZipName(raw)
	if nm != raw {
		t.Fatalf("expect raw to equal ZipName: %s , %s", raw, nm)
	}
}
