package attachment

import (
	"fmt"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	directChannelLabel = "punaro-attachment-v2"
	maxDirectFrame     = 256 << 10
)

// DirectPeer is the adapter-side WebRTC transport used after authenticated
// signaling selects direct or TURN mode. The relay never instantiates it.
type DirectPeer struct {
	connection *webrtc.PeerConnection
}

// NewDirectPeer creates an adapter-side peer with caller-provided STUN/TURN
// servers. Passing no servers allows host/direct candidates only.
func NewDirectPeer(servers []webrtc.ICEServer) (*DirectPeer, error) {
	settings := webrtc.SettingEngine{}
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return newDirectPeer(servers, settings)
}

// newDirectPeer keeps production construction and deterministic transport
// tests on the same WebRTC configuration path.
func newDirectPeer(servers []webrtc.ICEServer, settings webrtc.SettingEngine) (*DirectPeer, error) {
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	connection, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: servers})
	if err != nil {
		return nil, fmt.Errorf("create attachment WebRTC peer: %w", err)
	}
	return &DirectPeer{connection: connection}, nil
}

// OpenChunkChannel creates the reliable ordered data channel used for encrypted
// chunk frames. It drops malformed/oversized inbound frames before caller code.
func (p *DirectPeer) OpenChunkChannel(onFrame func([]byte)) (*webrtc.DataChannel, error) {
	ordered := true
	channel, err := p.connection.CreateDataChannel(directChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return nil, fmt.Errorf("create attachment data channel: %w", err)
	}
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if message.IsString || len(message.Data) == 0 || len(message.Data) > maxDirectFrame {
			return
		}
		onFrame(append([]byte(nil), message.Data...))
	})
	return channel, nil
}

// PeerConnection returns the underlying connection only for the adapter's
// signed signaling state machine; callers must not expose it to the relay.
func (p *DirectPeer) PeerConnection() *webrtc.PeerConnection {
	return p.connection
}

// Close releases the adapter-side data channel and ICE resources.
func (p *DirectPeer) Close() error {
	return p.connection.Close()
}
