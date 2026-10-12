package web_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nginx404 = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n" +
	"<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

func decoyServer(t *testing.T, dir string) *web.Server {
	t.Helper()

	srv, _, err := web.Setup(web.Settings{
		BindTo:   "127.0.0.1:18080",
		Host:     setupHost,
		DecoyDir: dir,
	}, map[string][]byte{"alice": []byte("0123456789abcdef")}, func(*web.Stream) {})
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv
}

func decoyDo(srv *web.Server, method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = setupHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	return rec
}

func writeFile(t *testing.T, name, body string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(name), 0o755))
	require.NoError(t, os.WriteFile(name, []byte(body), 0o600))
}

// The decoy behaves like the static site of an ordinary nginx, not like
// http.FileServer: each Go-specific answer would tell a prober what is behind
// the reverse proxy.
func TestDecoyLooksLikeNginx(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	writeFile(t, filepath.Join(root, "index.html"), "<html>home</html>")
	writeFile(t, filepath.Join(root, "about", "index.html"), "<html>about</html>")
	writeFile(t, filepath.Join(root, "empty", "keep.txt"), "x")
	writeFile(t, filepath.Join(root, ".env"), "SECRET=1")
	writeFile(t, filepath.Join(root, ".git", "config"), "[core]")
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside")
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")))
	require.NoError(t, os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "inside.html")))

	srv := decoyServer(t, root)

	cases := []struct {
		name, method, target string
		status               int
		body                 string
	}{
		{"index", http.MethodGet, "/", http.StatusOK, "<html>home</html>"},
		{"head", http.MethodHead, "/", http.StatusOK, ""},
		{"subdirectory index", http.MethodGet, "/about/", http.StatusOK, "<html>about</html>"},
		{"missing page", http.MethodGet, "/wp-login.php", http.StatusNotFound, nginx404},
		{"POST to a file", http.MethodPost, "/", http.StatusMethodNotAllowed, ""},
		{"POST to a missing page", http.MethodPost, "/api/v1/up", http.StatusNotFound, nginx404},
		{"PUT", http.MethodPut, "/", http.StatusMethodNotAllowed, ""},
		{"directory without slash", http.MethodGet, "/about", http.StatusMovedPermanently, ""},
		{"directory without index", http.MethodGet, "/empty/", http.StatusForbidden, ""},
		{"dotfile", http.MethodGet, "/.env", http.StatusNotFound, nginx404},
		{"dot directory", http.MethodGet, "/.git/config", http.StatusNotFound, nginx404},
		{"symlink out of root", http.MethodGet, "/link.txt", http.StatusNotFound, nginx404},
		{"symlink inside root", http.MethodGet, "/inside.html", http.StatusOK, "<html>home</html>"},
		{"dot-dot", http.MethodGet, "/../" + filepath.Base(outside) + "/secret.txt", http.StatusNotFound, nginx404},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := decoyDo(srv, tc.method, tc.target)

			assert.Equal(t, tc.status, rec.Code)

			if tc.body != "" {
				assert.Equal(t, tc.body, rec.Body.String())
			}

			if tc.status >= 300 {
				assert.Contains(t, rec.Body.String(), "<hr><center>nginx</center>")
				assert.NotContains(t, rec.Body.String(), "page not found")
				assert.Equal(t, "text/html", rec.Header().Get("Content-Type"))
			}

			if tc.method == http.MethodHead {
				assert.Empty(t, rec.Body.String())
			}
		})
	}

	t.Run("redirect target", func(t *testing.T) {
		assert.Equal(t, "/about/", decoyDo(srv, http.MethodGet, "/about").Header().Get("Location"))
	})

	t.Run("405 title", func(t *testing.T) {
		assert.Contains(t, decoyDo(srv, http.MethodPut, "/").Body.String(), "<title>405 Not Allowed</title>")
	})

	t.Run("etag", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(decoyDo(srv, http.MethodGet, "/").Header().Get("ETag"), `"`))
	})
}

// Without a decoy directory every page is an nginx 404, and other methods 405.
func TestEmptyDecoy(t *testing.T) {
	srv := decoyServer(t, "")

	rec := decoyDo(srv, http.MethodGet, "/")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, nginx404, rec.Body.String())

	assert.Equal(t, http.StatusMethodNotAllowed, decoyDo(srv, http.MethodDelete, "/").Code)
}
