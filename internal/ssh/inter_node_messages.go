package ssh

// InterNodeForwardRequestPayload is the payload for a tcpip-forward request
// sent between zcdns-tunnel nodes.
type InterNodeForwardRequestPayload struct {
	BindAddr       string
	BindPort       uint32
	OriginalDomain string // The domain from the original client's request
	ForwardID      string // Unique ID for this forwarded request
}

// InterNodeForwardedChannelPayload is the extra data sent with a forwarded-tcpip channel
// when it's opened back to an intermediate zcdns-tunnel node.
type InterNodeForwardedChannelPayload struct {
	DestAddr       string
	DestPort       uint32
	OriginatorIP   string
	OriginatorPort uint32
	ForwardID      string // Unique ID to map back to original client
}
