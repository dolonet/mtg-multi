package mtglib

import (
	"net"
	"time"
)

type eventBase struct {
	streamID  string
	timestamp time.Time
}

// StreamID returns a ID of the stream this event belongs to.
func (e eventBase) StreamID() string {
	return e.streamID
}

// Timestamp return a time when this event was generated.
func (e eventBase) Timestamp() time.Time {
	return e.timestamp
}

// EventStart is emitted when mtg proxy starts to process a new
// connection.
type EventStart struct {
	eventBase

	// RemoteIP is an IP address of the client.
	RemoteIP net.IP
}

// EventConnectedToDC is emitted when mtg proxy has connected to a Telegram
// server.
type EventConnectedToDC struct {
	eventBase

	// RemoteIP is an IP address of the Telegram server proxy has been connected
	// to.
	RemoteIP net.IP

	// DC is an index of the datacenter proxy has been connected to.
	DC int
}

// EventTraffic is emitted when we read/write some bytes on a connection.
type EventTraffic struct {
	eventBase

	// Traffic is a count of bytes which were transmitted.
	Traffic uint

	// IsRead defines if we _read_ or _write_ to connection. A rule of thumb is
	// simple: EventTraffic is bound to a remote connection. Not to a client one,
	// but either to Telegram or front domain one.
	//
	// In the case of Telegram, isRead means that we've fetched some bytes from
	// Telegram to send it to a client.
	//
	// In the case of the front domain, it means that we've fetched some bytes
	// from this domain to send it to a client.
	IsRead bool
}

// EventFinish is emitted when we stop to manage a connection.
type EventFinish struct {
	eventBase
}

// EventDomainFronting is emitted when we connect to a front domain instead of
// Telegram server.
type EventDomainFronting struct {
	eventBase
}

// EventConcurrencyLimited is emitted when connection was declined because of
// the concurrency limit of the worker pool.
type EventConcurrencyLimited struct {
	eventBase
}

// EventIPBlocklisted is emitted when connection was declined because IP
// address was found in IP blocklist.
type EventIPBlocklisted struct {
	eventBase

	RemoteIP    net.IP
	IsBlockList bool
}

// EventReplayAttack is emitted when mtg detects a replay attack on a
// connection.
type EventReplayAttack struct {
	eventBase
}

// EventThrottled is emitted when a connection is rejected because the
// per-user connection cap has been reached.
type EventThrottled struct {
	eventBase

	SecretName string
}

// EventIPListSize is emitted when mtg updates a contents of the ip lists:
// allowlist or blocklist.
type EventIPListSize struct {
	eventBase

	Size        int
	IsBlockList bool
}

// NewEventStart creates a new EventStart event.
func NewEventStart(streamID string, remoteIP net.IP) EventStart {
	return EventStart{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
		RemoteIP: remoteIP,
	}
}

// NewEventConnectedToDC creates a new EventConnectedToDC event.
func NewEventConnectedToDC(streamID string, remoteIP net.IP, dc int) EventConnectedToDC {
	return EventConnectedToDC{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
		RemoteIP: remoteIP,
		DC:       dc,
	}
}

// NewEventTraffic creates a new EventTraffic event.
func NewEventTraffic(streamID string, traffic uint, isRead bool) EventTraffic {
	return EventTraffic{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
		Traffic: traffic,
		IsRead:  isRead,
	}
}

// NewEventFinish creates a new EventFinish event.
func NewEventFinish(streamID string) EventFinish {
	return EventFinish{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
	}
}

// NewEventDomainFronting creates a new EventDomainFronting event.
func NewEventDomainFronting(streamID string) EventDomainFronting {
	return EventDomainFronting{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
	}
}

// EventPendingHandshakeLimit is emitted when a connection exceeds the per-IP
// limit on pending (unauthenticated) handshakes: it is either rejected or, in
// dry-run mode, observed and admitted.
type EventPendingHandshakeLimit struct {
	eventBase

	// Action is PendingHandshakeRejected or PendingHandshakeObserved.
	Action string
}

// NewEventPendingHandshakeLimit creates a new EventPendingHandshakeLimit.
func NewEventPendingHandshakeLimit(streamID, action string) EventPendingHandshakeLimit {
	return EventPendingHandshakeLimit{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
		Action: action,
	}
}

// EventDCPool is emitted on warm DC pool activity: a client got a warm
// connection (hit), had to dial cold (miss), a pooled connection turned out
// stale or dead, a background filler refreshed or failed to refresh the pool.
type EventDCPool struct {
	eventBase

	// DC is a Telegram DC the pool works with.
	DC int

	// Result is one of DCPoolResult* values.
	Result string
}

// NewEventDCPool creates a new EventDCPool event.
func NewEventDCPool(dc int, result string) EventDCPool {
	return EventDCPool{
		eventBase: eventBase{
			timestamp: time.Now(),
		},
		DC:     dc,
		Result: result,
	}
}

// NewEventConcurrencyLimited creates a new EventConcurrencyLimited
// event.
func NewEventConcurrencyLimited() EventConcurrencyLimited {
	return EventConcurrencyLimited{
		eventBase: eventBase{
			timestamp: time.Now(),
		},
	}
}

// NewEventIPBlocklisted creates a new EventIPBlocklisted event.
func NewEventIPBlocklisted(remoteIP net.IP) EventIPBlocklisted {
	return EventIPBlocklisted{
		eventBase: eventBase{
			timestamp: time.Now(),
		},
		RemoteIP:    remoteIP,
		IsBlockList: true,
	}
}

// NewEventIPAllowlisted creates a NewEventIPBlocklisted event with a mark that
// it is supposed to be for allow list.
func NewEventIPAllowlisted(remoteIP net.IP) EventIPBlocklisted {
	return EventIPBlocklisted{
		eventBase: eventBase{
			timestamp: time.Now(),
		},
		RemoteIP:    remoteIP,
		IsBlockList: false,
	}
}

// NewEventReplayAttack creates a new EventReplayAttack event.
func NewEventReplayAttack(streamID string) EventReplayAttack {
	return EventReplayAttack{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
	}
}

// NewEventThrottled creates a new EventThrottled event.
func NewEventThrottled(streamID, secretName string) EventThrottled {
	return EventThrottled{
		eventBase: eventBase{
			timestamp: time.Now(),
			streamID:  streamID,
		},
		SecretName: secretName,
	}
}

// NewEventIPListSize creates a new EventIPListSize event.
func NewEventIPListSize(size int, isBlockList bool) EventIPListSize {
	return EventIPListSize{
		eventBase: eventBase{
			timestamp: time.Now(),
		},
		Size:        size,
		IsBlockList: isBlockList,
	}
}
