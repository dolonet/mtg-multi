package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultBridgeRender(t *testing.T) {
	body, csp := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")

	t.Run("token is injected into the script", func(t *testing.T) {
		assert.Contains(t, body, "TOKEN-VALUE")
		assert.NotContains(t, body, "__TOKEN__")
	})

	t.Run("no placeholders are left", func(t *testing.T) {
		assert.NotContains(t, body, "__RUNTIME__")
		assert.NotContains(t, body, "__NONCE__")
	})

	// The policy must allow exactly our script; otherwise a tampered response
	// would run inside the Telegram webview.
	t.Run("policy is bound to the page nonce", func(t *testing.T) {
		_, after, found := strings.Cut(csp, "'nonce-")
		assert.True(t, found)

		nonce, _, found := strings.Cut(after, "'")
		assert.True(t, found)
		assert.NotEmpty(t, nonce)
		assert.Contains(t, body, `nonce="`+nonce+`"`)
		assert.Contains(t, csp, "default-src 'none'")
		assert.Contains(t, csp, "connect-src 'self'")
	})

	t.Run("nonce is single-use", func(t *testing.T) {
		_, second := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")
		assert.NotEqual(t, csp, second)
	})
}

// Without diagnostics the page carries no reporter at all: it never calls the
// diagnostic endpoint, which would be one more request per event and a
// recognizable pattern.
func TestDefaultBridgeDiag(t *testing.T) {
	off, _ := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.NotContains(t, off, "/api/v1/diag")
	assert.NotContains(t, off, "__REPORT__")
	assert.Contains(t, off, "const report = () => {};")

	on, _ := web.DefaultBridge{Diag: true}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.Contains(t, on, "/api/v1/diag")
	assert.NotContains(t, on, "__REPORT__")
}

// The script is adapted from telemt, and the page sent to the client is a
// copy of it: it must carry the same notice as web/bridge/runtime.js, that is
// the copyright, the licence, the note that this is a modified version and
// the list of changes.
func TestDefaultBridgeKeepsLicenceHeader(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bridge", "runtime.js"))
	require.NoError(t, err)

	var header []string

	for line := range strings.Lines(string(source)) {
		if !strings.HasPrefix(line, "//") {
			break
		}

		header = append(header, line)
	}

	notice := strings.Join(header, "")
	require.Contains(t, notice, "Copyright (c) 2026 Telemt")
	require.Contains(t, notice, "TELEMT LICENSE 3.3")
	require.Contains(t, notice, "This is a modified version, not official Telemt.")
	require.Contains(t, notice, "Changes:")

	for _, diag := range []bool{false, true} {
		body, _ := web.DefaultBridge{Diag: diag}.Render("proxy.example.com", "TOKEN-VALUE")

		assert.Contains(t, body, notice, "diag=%v", diag)
	}
}

// One /up body from the page must fit both the server limit and nginx's
// default client_max_body_size (1m), so that a burst of uploads does not
// depend on the proxy settings: a 413 from the proxy ends the bridge. One
// full frame must still fit, or the page could not send it at all.
func TestDefaultBridgeCapsUpBody(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bridge", "runtime.js"))
	require.NoError(t, err)

	match := regexp.MustCompile(`const MAX_UP_BYTES = (\d+) \* 1024;`).FindSubmatch(source)
	require.NotNil(t, match, "the page must cap one /up body")

	kilobytes, err := strconv.Atoi(string(match[1]))
	require.NoError(t, err)

	limit := int64(kilobytes) * 1024

	assert.LessOrEqual(t, limit, web.DefaultServerConfig().MaxBodyBytes)
	assert.LessOrEqual(t, limit, int64(1024*1024), "nginx default client_max_body_size")
	assert.GreaterOrEqual(t, limit, int64(web.HeaderBytes+web.DataChunkBytes))
}
