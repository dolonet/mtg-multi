// Portions of this file are adapted from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3 (see
// web/LICENSE.telemt). This is a modified version, not official Telemt.
// Adapted: accepting the port from the parent (the checks of the
// tproxy-init message and of the 127.0.0.1 origin), the Android
// TelegramWebProxy shim and its polling, fail/status/traffic messages to the
// port, the /api/v1/session|up|down paths and the fetch options.
// Changes: a single script instead of telemt's eight modules; the bootstrap
// token is used as the session token (no separate session token); no
// sequence numbers, acks or cursors on /up and /down, no retries and no
// recovery (any failed request ends the bridge), no WebSocket carrier, no
// lanes, no queue limits on the page; the WELCOME frame is passed to
// Telegram as received, without telemt's shape check; the Android shim passes
// a received buffer as is instead of splitting it into frames; free-text
// diagnostic marks, put into the page only when the server enables them,
// instead of telemt's fixed diagnostic events; comments rewritten.

// Bridge between Telegram Desktop and our HTTP transport.
//
// Telegram itself opens this page in a webview via https://<host>/?bridge=...
// The parent sends us a MessagePort with the message {t:'tproxy-init',v:1}; on
// Android a TelegramWebProxy object appears instead of the port. From then on
// the port carries frames (ArrayBuffer), exactly the ones we send to the
// server, plus control messages about the state.
//
// The script's job is simple: move frames from the port to POST /api/v1/up and
// from POST /api/v1/down responses back to the port. There is no cryptography
// here: the frames already contain obfuscated MTProto, and the outside is real
// TLS.
(() => {
  'use strict';

  const ORIGIN = location.origin;
  const TOKEN = '__TOKEN__';
  // The app's native bridge passes its one-time value in the URL fragment. It
  // never reaches the server (the fragment is not sent at all), and the page
  // uses it to identify itself to the app; without it the app sends no frames.
  const NATIVE_NONCE = (/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash) || [])[1] || '';
  // How long we wait for the first frame from Telegram. Without it the bridge
  // is useless.
  const HELLO_WAIT_MS = 15000;
  // The largest /up body. Frames that do not fit wait for the next request.
  // It stays below the server's MaxBodyBytes and below nginx's default
  // client_max_body_size (1m), so a burst of uploads does not depend on the
  // proxy settings: a body over a proxy limit gets 413, and a failed /up ends
  // the bridge. One frame is at most 64 KB plus its header, so it always fits.
  const MAX_UP_BYTES = 512 * 1024;

  let port = null;
  let closed = false;
  let pending = []; // frames waiting to be sent
  let flushing = false;
  let sessionStarted = false; // Telegram's HELLO has already been sent to the server
  let sessionReady = false; // the server answered WELCOME, the rest may be sent
  let helloTimer = null;

  // Debug marks: the embedded Telegram webview has no console, so the page
  // reports its progress to the server itself. The server puts the reporter
  // in only when diagnostics are enabled; otherwise report is a no-op and the
  // page never calls the diagnostic endpoint. Marks are sent on events, never
  // per data frame.
  const report = __REPORT__;

  addEventListener('error', (event) => report('script error: ' + (event.message || '') + ' @' + (event.lineno || '?')));
  addEventListener('unhandledrejection', (event) => report('unhandled rejection: ' + String(event.reason)));
  // A security policy violation does not show up in onerror as a separate
  // event, yet in the embedded webview it is the most likely silent failure.
  addEventListener('securitypolicyviolation', (event) =>
    report('security policy: violated ' + event.violatedDirective + ' on ' + event.blockedURI));

  const headers = () => ({
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/octet-stream',
  });

  const status = (state) => {
    if (port && !closed) {
      try {
        port.postMessage({ t: 'status', state });
      } catch (error) {
        // The parent may already be gone; that is no reason to fail.
      }
    }
  };

  const fail = () => {
    if (closed) return;
    closed = true;
    status('failed');

    try {
      if (port) port.postMessage({ t: 'close' });
    } catch (error) {
      // see above
    }

    try {
      if (port) port.close();
    } catch (error) {
      // see above
    }
  };

  const post = async (path, body) => {
    const response = await fetch(ORIGIN + path, {
      method: 'POST',
      headers: headers(),
      body: body ?? new Uint8Array(0),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      // We read the whole response body ourselves; no streaming needed.
      keepalive: false,
    });

    if (!response.ok) throw new Error('bad status ' + response.status);

    const type = response.headers.get('Content-Type') || '';
    // The server answers with the decoy (HTML) when it considers us foreign.
    // This ends the session rather than being a transient failure: retrying
    // would only add noise.
    if (!type.startsWith('application/octet-stream')) throw new Error('not a carrier response');

    return new Uint8Array(await response.arrayBuffer());
  };

  // Client frames are accumulated and sent in batches: one POST per small
  // frame would turn ordinary chatting into a flood of requests. A batch
  // takes whole frames, in order, up to MAX_UP_BYTES; the rest go in the next
  // request of the same loop.
  const takeBatch = () => {
    let count = 0;
    let total = 0;

    while (count < pending.length) {
      const size = pending[count].length;
      if (count > 0 && total + size > MAX_UP_BYTES) break;

      total += size;
      count++;
    }

    return { batch: pending.splice(0, count), total };
  };

  const flush = async () => {
    if (flushing || closed || !sessionReady) return;
    flushing = true;

    try {
      while (pending.length > 0 && !closed) {
        const { batch, total } = takeBatch();

        const body = new Uint8Array(total);
        let offset = 0;

        for (const frame of batch) {
          body.set(frame, offset);
          offset += frame.length;
        }

        await post('/api/v1/up', body);

        if (port) port.postMessage({ t: 'traffic', up: total, down: 0 });
      }
    } catch (error) {
      fail();
    } finally {
      flushing = false;
    }
  };

  // Long polling: the server holds the response while there is no data, so
  // the loop does not spin idly.
  const pump = async () => {
    while (!closed) {
      let body;

      try {
        body = await post('/api/v1/down', null);
      } catch (error) {
        fail();

        return;
      }

      if (closed) return;

      if (body.length > 0) {
        const buffer = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);

        try {
          port.postMessage(buffer, [buffer]);
          port.postMessage({ t: 'traffic', up: 0, down: body.length });
        } catch (error) {
          fail();

          return;
        }

        status('connected');
      }
    }
  };

  // The session is opened by the FIRST frame from Telegram, which is its own
  // HELLO.
  //
  // We must not send a HELLO of our own: Telegram expects a reply to its own
  // handshake. With a substituted HELLO the client received a WELCOME that did
  // not answer its frame, considered the bridge broken, dropped the long poll
  // and started over every two seconds (nginx log: session 200, down 499, and
  // not a single up).
  const startSession = async (hello) => {
    let welcome;

    try {
      welcome = await post('/api/v1/session', hello);
    } catch (error) {
      fail();

      return;
    }

    if (closed) return;

    if (welcome.length > 0) {
      const buffer = welcome.buffer.slice(welcome.byteOffset, welcome.byteOffset + welcome.byteLength);

      try {
        port.postMessage(buffer, [buffer]);
      } catch (error) {
        fail();

        return;
      }
    }

    sessionReady = true;
    status('connecting');
    pump();
    flush(); // frames that arrived during the handshake
  };

  const activate = (activePort) => {
    if (port || closed) return;

    port = activePort;

    port.onmessage = (event) => {
      const data = event.data;
      // Only the first frame (Telegram's HELLO) and control messages: one
      // report per data frame would double the request rate.
      if (!sessionStarted || !(data instanceof ArrayBuffer)) {
        report('frame from port: type=' + Object.prototype.toString.call(data) +
          ' size=' + (data && (data.byteLength ?? data.length ?? '?')));
      }

      if (data instanceof ArrayBuffer) {
        if (!sessionStarted) {
          sessionStarted = true;

          if (helloTimer) {
            clearTimeout(helloTimer);
            helloTimer = null;
          }

          startSession(new Uint8Array(data));

          return;
        }

        pending.push(new Uint8Array(data));
        flush();

        return;
      }

      if (data && typeof data === 'object' && data.t === 'close') fail();
    };

    if (typeof port.start === 'function') port.start();

    report('port accepted, waiting for the first frame');
    status('connecting');
    report('connecting state sent');
    helloTimer = setTimeout(() => {
      report('the first frame never arrived');
      fail();
    }, HELLO_WAIT_MS);
  };

  // Desktop: the port arrives in a message from the parent. The sender is
  // checked strictly: the page must accept the port only from Telegram itself,
  // which runs its own server on localhost.
  addEventListener('message', (event) => {
    report('message: origin=' + event.origin + ' from_parent=' + (event.source === parent) +
      ' ports=' + ((event.ports && event.ports.length) || 0) +
      ' data=' + (event.data && typeof event.data === 'object' ? JSON.stringify(event.data) : String(event.data)));

    if (event.source !== parent || port || closed) return;

    const data = event.data;
    if (data === null || typeof data !== 'object') return;

    const keys = Object.keys(data).sort();
    if (keys.length !== 2 || keys[0] !== 't' || keys[1] !== 'v') return;
    if (data.t !== 'tproxy-init' || data.v !== 1) return;
    if (!event.ports || event.ports.length !== 1) return;

    let source;

    try {
      source = new URL(event.origin);
    } catch (error) {
      return;
    }

    if (source.protocol !== 'http:' || source.hostname !== '127.0.0.1' || !source.port) return;
    if (source.origin !== event.origin) return;

    activate(event.ports[0]);
  });

  // The app's native bridge: there is no port, but an object with the same
  // purpose instead.
  //
  // This is how the EMBEDDED webview works, on both Android and macOS (in the
  // embedded webview no message event with a port arrives at all, only this
  // object). It does not appear instantly, so we poll for a short while.
  // Connecting without the value from the URL fragment is not allowed: it is
  // the proof that this is the right page.
  const discoverNative = () => {
    if (!NATIVE_NONCE) {
      report('native bridge: no value in the URL fragment, waiting for a port from the parent');

      return;
    }

    const deadline = Date.now() + 10000;

    const probe = () => {
      if (port || closed) return;

      const androidBridge = globalThis.TelegramWebProxy;

      if (androidBridge && typeof androidBridge.postMessage === 'function') {
        const shim = {
          onmessage: null,
          start() {},
          close() {
            androidBridge.onmessage = null;
          },
          postMessage(value) {
            if (value instanceof ArrayBuffer) androidBridge.postMessage(value);
            else androidBridge.postMessage(JSON.stringify(value));
          },
        };

        androidBridge.onmessage = (event) => {
          let data = event.data;

          if (typeof data === 'string') {
            try {
              data = JSON.parse(data);
            } catch (error) {
              return;
            }
          }

          if (shim.onmessage) shim.onmessage({ data });
        };

        activate(shim);

        // Identify ourselves to the app: until it gets its value back, no
        // frames will flow and the page will be closed.
        androidBridge.postMessage(JSON.stringify({ t: 'tproxy-android-init', v: 1, nonce: NATIVE_NONCE }));
        report('native bridge: identified to the app');

        return;
      }

      if (Date.now() < deadline) setTimeout(probe, 100);
    };

    probe();
  };

  discoverNative();
  report('page started: ' + navigator.userAgent + ' | native value: ' + (NATIVE_NONCE ? 'present' : 'absent'));

  addEventListener('pagehide', () => {
    report('page is closing');
    fail();
  }, { once: true });
})();
