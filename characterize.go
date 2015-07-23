package characterize

import (
	"io"
)

const sniffSz = 4096

func ToUTF8(s string) string {
	c := detect([]byte(s))
	switch c {
	case ASCII, UTF8:
		return s
	case UTF7:
		return s[4:]
	case UTF8BOM:
		return s[3:]
	}
	return s
}

func Detect(r io.Reader) CharType {
	var buf []byte
	slc, ok := r.(slicer)
	if !ok {
		buf = make([]byte, sniffSz)
		l, _ := r.Read(buf)
		buf = buf[:l]
	} else {
		buf, _ = slc.Slice(0, sniffSz)
	}
	return detect(buf)
}

// Slicer interface avoids a copy by getting a byte slice directly from the underlying reader
type slicer interface {
	Slice(offset int64, length int) ([]byte, error)
}

func detect(buf []byte) CharType {
	ubom := utf8BOM(buf)
	if ubom {
		buf = buf[3:]
	}
	tt := detectText(buf)
	if tt == _a {
		if ubom {
			return UTF8BOM
		}
		if utf7BOM(buf) {
			return UTF7
		}
		return ASCII
	}
	if detectUTF8(buf) {
		if ubom {
			return UTF8BOM
		}
		return UTF8
	}
	if utf16, big := detectUTF16(buf); utf16 {
		if big {
			return UTF16BE
		}
		return UTF16LE
	}
	if tt == _i {
		return LATIN1
	}
	if tt == _e {
		return EXTENDED
	}
	if ebcdic, international := detectEBCDIC(buf); ebcdic {
		if international {
			return EBCDICINT
		}
		return EBCDIC
	}
	return Binary
}

type CharType byte

const (
	Binary CharType = iota
	ASCII
	UTF7
	UTF8BOM
	UTF8
	UTF16LE
	UTF16BE
	LATIN1
	EXTENDED
	EBCDIC
	EBCDICINT
)

func (c CharType) String() string {
	switch c {
	case ASCII:
		return "ASCII"
	case UTF7:
		return "UTF-7 Unicode"
	case UTF8BOM:
		return "UTF-8 Unicode (with BOM)"
	case UTF8:
		return "UTF-8 Unicode"
	case UTF16LE:
		return "Little-endian UTF-16 Unicode"
	case UTF16BE:
		return "Big-endian UTF-16 Unicode"
	case LATIN1:
		return "ISO-8859"
	case EXTENDED:
		return "Non-ISO extended-ASCII"
	case EBCDIC:
		return "EBCDIC"
	case EBCDICINT:
		return "International EBCDIC"
	}
	return "binary"
}

type textType byte

const (
	_n textType = iota /* character never appears in text */
	_a                 /* character appears in plain ASCII text */
	_i                 /* character appears in ISO-8859 text */
	_e                 /* character appears in non-ISO extended ASCII (Mac, IBM PC) */

)

var textChars = [256]textType{
	_n, _n, _n, _n, _n, _n, _n, _a, _a, _a, _a, _a, _a, _a, _n, _n, /* 0x0X */
	_n, _n, _n, _n, _n, _n, _n, _n, _n, _n, _n, _a, _n, _n, _n, _n, /* 0x1X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, /* 0x2X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, /* 0x3X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, /* 0x4X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, /* 0x5X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, /* 0x6X */
	_a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _a, _n, /* 0x7X */
	_e, _e, _e, _e, _e, _a, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, /* 0x8X */
	_e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, _e, /* 0x9X */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xaX */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xbX */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xcX */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xdX */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xeX */
	_i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, _i, /* 0xfX */
}

func detectText(r []byte) textType {
	var t textType
	for _, b := range r {
		nt := textChars[b]
		if nt == _n {
			return _n
		}
		if nt > t {
			t = nt
		}
	}
	return t
}

func utf7BOM(r []byte) bool {
	if len(r) > 4 && r[0] == '+' && r[1] == '/' && r[2] == 'v' {
		switch r[3] {
		case '8', '9', '+', '/':
			return true
		}
	}
	return false
}

func utf8BOM(r []byte) bool {
	if len(r) > 3 && r[0] == 239 && r[1] == 187 && r[2] == 191 {
		return true
	}
	return false
}

func detectUTF8(r []byte) bool {
	var high bool
	for i := 0; i < len(r); i++ {
		if r[i]&0x80 == 0 {
			if textChars[r[i]] != _a {
				return false
			}
		} else if r[i]&0x40 == 0 {
			return false
		} else {
			var following int
			switch {
			case r[i]&0x20 == 0:
				following = 1
			case r[i]&0x10 == 0:
				following = 2
			case r[i]&0x08 == 0:
				following = 3
			case r[i]&0x04 == 0:
				following = 4
			case r[i]&0x02 == 0:
				following = 5
			default:
				return false
			}
			for n := 0; n < following; n++ {
				i++
				if i >= len(r) {
					return high
				}
				if r[i]&0x80 == 0 || r[i]&0x40 != 0 {
					return false
				}
			}
			high = true
		}
	}
	return high
}

func detectUTF16(r []byte) (bool, bool) {
	var big bool

	if len(r) < 2 {
		return false, false
	}

	if r[0] == 0xff && r[1] == 0xfe {
		big = false
	} else if r[0] == 0xfe && r[1] == 0xff {
		big = true
	} else {
		return false, false
	}
	for i := 2; i+1 < len(r); i += 2 {
		var char int
		if big {
			char = int(r[i+1]) + 256*int(r[i])
		} else {
			char = int(r[i]) + 256*int(r[i+1])
		}
		if char == 0xfffe {
			return false, false
		}
		if char < 128 && textChars[char] != _a {
			return false, false
		}
	}
	return true, big
}

var ebcdicAscii = [256]byte{
	0, 1, 2, 3, 156, 9, 134, 127, 151, 141, 142, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 157, 133, 8, 135, 24, 25, 146, 143, 28, 29, 30, 31,
	128, 129, 130, 131, 132, 10, 23, 27, 136, 137, 138, 139, 140, 5, 6, 7,
	144, 145, 22, 147, 148, 149, 150, 4, 152, 153, 154, 155, 20, 21, 158, 26,
	' ', 160, 161, 162, 163, 164, 165, 166, 167, 168, 213, '.', '<', '(', '+', '|',
	'&', 169, 170, 171, 172, 173, 174, 175, 176, 177, '!', '$', '*', ')', ';', '~',
	'-', '/', 178, 179, 180, 181, 182, 183, 184, 185, 203, ',', '%', '_', '>', '?',
	186, 187, 188, 189, 190, 191, 192, 193, 194, '`', ':', '#', '@', '\'', '=', '"',
	195, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 196, 197, 198, 199, 200, 201,
	202, 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '^', 204, 205, 206, 207, 208,
	209, 229, 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 210, 211, 212, '[', 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, ']', 230, 231,
	'{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 232, 233, 234, 235, 236, 237,
	'}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 238, 239, 240, 241, 242, 243,
	'\\', 159, 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 244, 245, 246, 247, 248, 249,
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 250, 251, 252, 253, 254, 255,
}

func detectEBCDIC(r []byte) (bool, bool) {
	var international bool
	for _, b := range r {
		switch textChars[ebcdicAscii[b]] {
		case _n, _e:
			return false, false
		case _i:
			international = true
		}
	}
	return true, international
}

// Next up: https://github.com/apache/tika/blob/trunk/tika-parsers/src/main/java/org/apache/tika/parser/txt/CharsetRecog_sbcs.java //
