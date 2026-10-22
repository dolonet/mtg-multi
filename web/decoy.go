package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// The decoy has to look like the static site of an ordinary nginx, not like a
// Go program: http.FileServer answers POST with 200, lists directories,
// serves dotfiles, follows symlinks and has its own error bodies, and each of
// these tells a prober what is behind the reverse proxy. staticDecoy follows
// the nginx static and index modules instead:
//
//   - GET and HEAD serve files; POST to an existing file is 405, to a missing
//     one 404; any other method is 405;
//   - a directory without a trailing slash is a 301 to the slash form; a
//     directory serves its index.html, and without one it is 403 (nginx
//     without autoindex), never a listing;
//   - error bodies are the nginx default pages;
//   - dotfiles and anything that resolves outside the root (symlinks, "..")
//     are 404.
//
// Set "server_tokens off;" in nginx: the error bodies carry no version, and
// they must match the Server header nginx sends.
type staticDecoy struct {
	root string
}

func newDecoy(dir string) (Decoy, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return emptyDecoy{}, nil
	}

	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("web: decoy-dir %q is not a directory", dir)
	}

	return staticDecoy{root: root}, nil
}

func (d staticDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		writeNginxError(w, r, http.StatusMethodNotAllowed)

		return
	}

	urlPath := r.URL.Path
	if !strings.HasPrefix(urlPath, "/") {
		writeNginxError(w, r, http.StatusBadRequest)

		return
	}

	clean := path.Clean(urlPath)
	if hasDotSegment(clean) {
		writeNginxError(w, r, http.StatusNotFound)

		return
	}

	name, info, ok := d.resolve(clean)
	if !ok {
		writeNginxError(w, r, http.StatusNotFound)

		return
	}

	if info.IsDir() {
		if !strings.HasSuffix(urlPath, "/") {
			location := clean + "/"
			if r.URL.RawQuery != "" {
				location += "?" + r.URL.RawQuery
			}

			w.Header().Set("Location", location)
			writeNginxError(w, r, http.StatusMovedPermanently)

			return
		}

		name, info, ok = d.resolve(path.Join(clean, "index.html"))
		if !ok || info.IsDir() {
			writeNginxError(w, r, http.StatusForbidden)

			return
		}
	}

	if r.Method == http.MethodPost {
		writeNginxError(w, r, http.StatusMethodNotAllowed)

		return
	}

	file, err := os.Open(name)
	if err != nil {
		writeNginxError(w, r, http.StatusNotFound)

		return
	}
	defer file.Close() //nolint: errcheck

	// The same ETag format as nginx: hex mtime and hex size.
	w.Header().Set("ETag", "\""+strconv.FormatInt(info.ModTime().Unix(), 16)+"-"+
		strconv.FormatInt(info.Size(), 16)+"\"")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// resolve maps a clean URL path to a file under the root, following symlinks
// only as long as the result stays inside the root.
func (d staticDecoy) resolve(urlPath string) (string, os.FileInfo, bool) {
	name := filepath.Join(d.root, filepath.FromSlash(urlPath))

	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		return "", nil, false
	}

	if resolved != d.root && !strings.HasPrefix(resolved, d.root+string(filepath.Separator)) {
		return "", nil, false
	}

	info, err := os.Stat(resolved)
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		return "", nil, false
	}

	return resolved, info, true
}

func hasDotSegment(cleanPath string) bool {
	for segment := range strings.SplitSeq(cleanPath, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}

	return false
}

// emptyDecoy is used when no directory is set: an nginx with an empty root.
type emptyDecoy struct{}

func (emptyDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
		writeNginxError(w, r, http.StatusNotFound)
	default:
		writeNginxError(w, r, http.StatusMethodNotAllowed)
	}
}

// nginxStatusLines are the titles nginx puts on its default error pages.
var nginxStatusLines = map[int]string{
	http.StatusMovedPermanently: "301 Moved Permanently",
	http.StatusBadRequest:       "400 Bad Request",
	http.StatusForbidden:        "403 Forbidden",
	http.StatusNotFound:         "404 Not Found",
	http.StatusMethodNotAllowed: "405 Not Allowed",
}

// writeNginxError writes the default nginx error page for a status.
func writeNginxError(w http.ResponseWriter, r *http.Request, status int) {
	title, ok := nginxStatusLines[status]
	if !ok {
		title = strconv.Itoa(status) + " " + http.StatusText(status)
	}

	body := "<html>\r\n<head><title>" + title + "</title></head>\r\n<body>\r\n" +
		"<center><h1>" + title + "</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)

	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}
