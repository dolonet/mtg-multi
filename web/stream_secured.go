package web

// SecuredTransport marks WEB streams for the proxy: they carry plain
// obfuscated2 inside a real HTTPS session, so the secured handshake is
// accepted for them without enabling it on the FakeTLS listener.
func (s *Stream) SecuredTransport() bool { return true }
