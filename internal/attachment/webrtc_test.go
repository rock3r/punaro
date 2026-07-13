package attachment

import (
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/vnet"
	"github.com/pion/webrtc/v4"
)

func TestDirectPeerCreatesReliableOrderedBoundedChunkChannel(t *testing.T) {
	peer, err := NewDirectPeer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	channel, err := peer.OpenChunkChannel(func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	if channel.Label() != directChannelLabel || !channel.Ordered() {
		t.Fatalf("channel label/ordered = %q/%v", channel.Label(), channel.Ordered())
	}
}

func TestDirectPeersDeliverEncryptedFrameOverLocalICE(t *testing.T) {
	router, senderSettings, receiverSettings := directPeerVNet(t)
	defer func() {
		if err := router.Stop(); err != nil {
			t.Errorf("stop virtual network: %v", err)
		}
	}()
	sender, err := newDirectPeer(nil, senderSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	receiver, err := newDirectPeer(nil, receiverSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	received := make(chan []byte, 1)
	receiver.PeerConnection().OnDataChannel(func(channel *webrtc.DataChannel) {
		channel.OnMessage(func(message webrtc.DataChannelMessage) { received <- message.Data })
	})
	channel, err := sender.OpenChunkChannel(func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{})
	channel.OnOpen(func() { close(opened) })
	offer, err := sender.PeerConnection().CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.PeerConnection().SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-webrtc.GatheringCompletePromise(sender.PeerConnection())
	if err := receiver.PeerConnection().SetRemoteDescription(*sender.PeerConnection().LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, err := receiver.PeerConnection().CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.PeerConnection().SetLocalDescription(answer); err != nil {
		t.Fatal(err)
	}
	<-webrtc.GatheringCompletePromise(receiver.PeerConnection())
	if err := sender.PeerConnection().SetRemoteDescription(*receiver.PeerConnection().LocalDescription()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("data channel did not open")
	}
	if err := channel.Send([]byte("encrypted-frame")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if string(got) != "encrypted-frame" {
			t.Fatalf("frame = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("frame not delivered")
	}
}

func directPeerVNet(t *testing.T) (*vnet.Router, webrtc.SettingEngine, webrtc.SettingEngine) {
	t.Helper()
	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	senderNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := router.AddNet(senderNet); err != nil {
		t.Fatal(err)
	}
	receiverNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"1.2.3.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := router.AddNet(receiverNet); err != nil {
		t.Fatal(err)
	}
	if err := router.Start(); err != nil {
		t.Fatal(err)
	}
	senderSettings := webrtc.SettingEngine{}
	senderSettings.SetNet(senderNet)
	senderSettings.SetICETimeouts(time.Second, time.Second, time.Second)
	receiverSettings := webrtc.SettingEngine{}
	receiverSettings.SetNet(receiverNet)
	receiverSettings.SetICETimeouts(time.Second, time.Second, time.Second)
	return router, senderSettings, receiverSettings
}
