// Portions of this file are adapted from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3 (see
// web/LICENSE.telemt). This is a modified version, not official Telemt.
// Adapted: the bridge HTML document, the Content-Security-Policy, the
// Permissions-Policy and the nonce format (18 random bytes, base64url).
// Changes: rewritten in Go; the document carries a single script instead of
// telemt's eight; connect-src is 'self' only (no wss:// carrier); the
// diagnostic reporter is put into the page only when diagnostics are enabled.

package web

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"strings"
)

//go:embed bridge/runtime.js
var bridgeRuntime string

// bridgeDocument is the page Telegram opens in its webview. It carries
// nothing extra: the title is neutral and all the logic lives in the script.
const bridgeDocument = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
__RUNTIME__
</script>
</body>
</html>
`

// PermissionsPolicy denies every browser feature to the bridge page: it only
// needs network requests to its own server.
const PermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), " +
	"clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
	"gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), " +
	"picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), " +
	"screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()"

// DefaultBridge renders the bridge page with a one-time token.
type DefaultBridge struct {
	// Diag puts the diagnostic reporter into the page. Without it the page
	// never calls the diagnostic endpoint.
	Diag bool
}

// noReport is the reporter of a page without diagnostics.
const noReport = "() => {}"

// diagReport sends a short mark to the diagnostic endpoint. Sending never
// waits and never interferes with the bridge.
const diagReport = `(message) => {
    try {
      fetch(ORIGIN + '/api/v1/diag', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'text/plain' },
        body: message,
        cache: 'no-store',
        credentials: 'omit',
      }).catch(() => {});
    } catch (error) {
      // Diagnostics must never interfere with the bridge.
    }
  }`

// Render returns the document and a policy that allows exactly one script,
// ours.
//
// The policy is this narrow because the page runs inside the Telegram webview:
// if the server ever starts serving a foreign response (tampering,
// misconfiguration), the browser must not execute anything except the script
// carrying our one-time nonce. Network requests are allowed to the page's own
// origin only.
func (b DefaultBridge) Render(host, bootstrapToken string) (string, string) {
	nonce := randomNonce()

	report := noReport
	if b.Diag {
		report = diagReport
	}

	runtime := strings.ReplaceAll(bridgeRuntime, "__REPORT__", report)
	runtime = strings.ReplaceAll(runtime, "__TOKEN__", bootstrapToken)

	body := strings.ReplaceAll(bridgeDocument, "__RUNTIME__", runtime)
	body = strings.ReplaceAll(body, "__NONCE__", nonce)

	// The policy is as strict as possible and must include sandbox.
	//
	// In the embedded Telegram webview (WKWebView) the page received the port,
	// but the client never sent a single frame and closed it, while the same
	// page worked in an external browser. The only difference from telemt was
	// the set of headers and the missing sandbox: the app routes traffic into
	// the page only when the page is fully restricted.
	csp := strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"child-src 'none'",
		"connect-src 'self'",
		"font-src 'none'",
		"form-action 'none'",
		"frame-ancestors http://127.0.0.1:*",
		"frame-src 'none'",
		"img-src 'none'",
		"manifest-src 'none'",
		"media-src 'none'",
		"object-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"style-src 'none'",
		"worker-src 'none'",
		"sandbox allow-same-origin allow-scripts",
	}, "; ")

	return body, csp
}

func randomNonce() string {
	var buf [18]byte

	// A failing system generator means the process has no randomness. An
	// empty nonce is better then: the page simply will not run, whereas a
	// predictable one would let a foreign script be injected.
	if _, err := rand.Read(buf[:]); err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(buf[:])
}
