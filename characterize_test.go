package characterize

import (
	"os"
	"testing"
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

func TestDetect(t *testing.T) {
	for _, v := range suite {
		file, err := os.Open(v.name)
		if err != nil {
			t.Fatalf("failed to open %s, got: %v", v.name, err)
		}
		det := Detect(file)
		if det != v.expect {
			t.Errorf("failed to detect %s: expecting %s, got %s", v.name, v.expect, det)
		}
	}
}
