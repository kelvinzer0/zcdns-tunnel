// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: internal/grpc/proto/gossip.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Node represents information about a cluster node
type Node struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       string                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	GossipPort    int32                  `protobuf:"varint,2,opt,name=gossip_port,json=gossipPort,proto3" json:"gossip_port,omitempty"`
	SshPort       int32                  `protobuf:"varint,3,opt,name=ssh_port,json=sshPort,proto3" json:"ssh_port,omitempty"`
	SshListenAddr string                 `protobuf:"bytes,4,opt,name=ssh_listen_addr,json=sshListenAddr,proto3" json:"ssh_listen_addr,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Node) Reset() {
	*x = Node{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{0}
}

func (x *Node) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Node) GetGossipPort() int32 {
	if x != nil {
		return x.GossipPort
	}
	return 0
}

func (x *Node) GetSshPort() int32 {
	if x != nil {
		return x.SshPort
	}
	return 0
}

func (x *Node) GetSshListenAddr() string {
	if x != nil {
		return x.SshListenAddr
	}
	return ""
}

// JoinRequest is sent when a node wants to join the cluster
type JoinRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	NewNode       *Node                  `protobuf:"bytes,1,opt,name=new_node,json=newNode,proto3" json:"new_node,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *JoinRequest) Reset() {
	*x = JoinRequest{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JoinRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinRequest) ProtoMessage() {}

func (x *JoinRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JoinRequest.ProtoReflect.Descriptor instead.
func (*JoinRequest) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{1}
}

func (x *JoinRequest) GetNewNode() *Node {
	if x != nil {
		return x.NewNode
	}
	return nil
}

// JoinResponse is the response to a join request
type JoinResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	KnownPeers    []*Node                `protobuf:"bytes,3,rep,name=known_peers,json=knownPeers,proto3" json:"known_peers,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *JoinResponse) Reset() {
	*x = JoinResponse{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JoinResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinResponse) ProtoMessage() {}

func (x *JoinResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JoinResponse.ProtoReflect.Descriptor instead.
func (*JoinResponse) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{2}
}

func (x *JoinResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *JoinResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *JoinResponse) GetKnownPeers() []*Node {
	if x != nil {
		return x.KnownPeers
	}
	return nil
}

// HeartbeatRequest is sent to check if a node is alive and share peer information
type HeartbeatRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Sender        *Node                  `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	KnownPeers    []*Node                `protobuf:"bytes,2,rep,name=known_peers,json=knownPeers,proto3" json:"known_peers,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HeartbeatRequest) Reset() {
	*x = HeartbeatRequest{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HeartbeatRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HeartbeatRequest) ProtoMessage() {}

func (x *HeartbeatRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HeartbeatRequest.ProtoReflect.Descriptor instead.
func (*HeartbeatRequest) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{3}
}

func (x *HeartbeatRequest) GetSender() *Node {
	if x != nil {
		return x.Sender
	}
	return nil
}

func (x *HeartbeatRequest) GetKnownPeers() []*Node {
	if x != nil {
		return x.KnownPeers
	}
	return nil
}

// HeartbeatResponse is the response to a heartbeat request
type HeartbeatResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	KnownPeers    []*Node                `protobuf:"bytes,3,rep,name=known_peers,json=knownPeers,proto3" json:"known_peers,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HeartbeatResponse) Reset() {
	*x = HeartbeatResponse{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HeartbeatResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HeartbeatResponse) ProtoMessage() {}

func (x *HeartbeatResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HeartbeatResponse.ProtoReflect.Descriptor instead.
func (*HeartbeatResponse) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{4}
}

func (x *HeartbeatResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *HeartbeatResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *HeartbeatResponse) GetKnownPeers() []*Node {
	if x != nil {
		return x.KnownPeers
	}
	return nil
}

// ForwardRequestMessage is sent to forward a tunnel request to the responsible node
type ForwardRequestMessage struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Domain        string                 `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	BindAddr      string                 `protobuf:"bytes,2,opt,name=bind_addr,json=bindAddr,proto3" json:"bind_addr,omitempty"`
	BindPort      uint32                 `protobuf:"varint,3,opt,name=bind_port,json=bindPort,proto3" json:"bind_port,omitempty"`
	ForwardId     string                 `protobuf:"bytes,4,opt,name=forward_id,json=forwardId,proto3" json:"forward_id,omitempty"`
	OriginalAddr  string                 `protobuf:"bytes,5,opt,name=original_addr,json=originalAddr,proto3" json:"original_addr,omitempty"`
	Sender        *Node                  `protobuf:"bytes,6,opt,name=sender,proto3" json:"sender,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ForwardRequestMessage) Reset() {
	*x = ForwardRequestMessage{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ForwardRequestMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ForwardRequestMessage) ProtoMessage() {}

func (x *ForwardRequestMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ForwardRequestMessage.ProtoReflect.Descriptor instead.
func (*ForwardRequestMessage) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{5}
}

func (x *ForwardRequestMessage) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *ForwardRequestMessage) GetBindAddr() string {
	if x != nil {
		return x.BindAddr
	}
	return ""
}

func (x *ForwardRequestMessage) GetBindPort() uint32 {
	if x != nil {
		return x.BindPort
	}
	return 0
}

func (x *ForwardRequestMessage) GetForwardId() string {
	if x != nil {
		return x.ForwardId
	}
	return ""
}

func (x *ForwardRequestMessage) GetOriginalAddr() string {
	if x != nil {
		return x.OriginalAddr
	}
	return ""
}

func (x *ForwardRequestMessage) GetSender() *Node {
	if x != nil {
		return x.Sender
	}
	return nil
}

// ForwardResponseMessage is the response to a forward request
type ForwardResponseMessage struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ForwardId     string                 `protobuf:"bytes,1,opt,name=forward_id,json=forwardId,proto3" json:"forward_id,omitempty"`
	Success       bool                   `protobuf:"varint,2,opt,name=success,proto3" json:"success,omitempty"`
	Port          uint32                 `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	Error         string                 `protobuf:"bytes,4,opt,name=error,proto3" json:"error,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ForwardResponseMessage) Reset() {
	*x = ForwardResponseMessage{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ForwardResponseMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ForwardResponseMessage) ProtoMessage() {}

func (x *ForwardResponseMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ForwardResponseMessage.ProtoReflect.Descriptor instead.
func (*ForwardResponseMessage) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{6}
}

func (x *ForwardResponseMessage) GetForwardId() string {
	if x != nil {
		return x.ForwardId
	}
	return ""
}

func (x *ForwardResponseMessage) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *ForwardResponseMessage) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *ForwardResponseMessage) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

// IntermediaryAddrMessage is sent to share intermediary address information
type IntermediaryAddrMessage struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Domain           string                 `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	ProtocolPrefix   string                 `protobuf:"bytes,2,opt,name=protocol_prefix,json=protocolPrefix,proto3" json:"protocol_prefix,omitempty"`
	PublicPort       uint32                 `protobuf:"varint,3,opt,name=public_port,json=publicPort,proto3" json:"public_port,omitempty"`
	IntermediaryAddr string                 `protobuf:"bytes,4,opt,name=intermediary_addr,json=intermediaryAddr,proto3" json:"intermediary_addr,omitempty"`
	ForwardId        string                 `protobuf:"bytes,5,opt,name=forward_id,json=forwardId,proto3" json:"forward_id,omitempty"`
	Sender           *Node                  `protobuf:"bytes,6,opt,name=sender,proto3" json:"sender,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *IntermediaryAddrMessage) Reset() {
	*x = IntermediaryAddrMessage{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IntermediaryAddrMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntermediaryAddrMessage) ProtoMessage() {}

func (x *IntermediaryAddrMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntermediaryAddrMessage.ProtoReflect.Descriptor instead.
func (*IntermediaryAddrMessage) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{7}
}

func (x *IntermediaryAddrMessage) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *IntermediaryAddrMessage) GetProtocolPrefix() string {
	if x != nil {
		return x.ProtocolPrefix
	}
	return ""
}

func (x *IntermediaryAddrMessage) GetPublicPort() uint32 {
	if x != nil {
		return x.PublicPort
	}
	return 0
}

func (x *IntermediaryAddrMessage) GetIntermediaryAddr() string {
	if x != nil {
		return x.IntermediaryAddr
	}
	return ""
}

func (x *IntermediaryAddrMessage) GetForwardId() string {
	if x != nil {
		return x.ForwardId
	}
	return ""
}

func (x *IntermediaryAddrMessage) GetSender() *Node {
	if x != nil {
		return x.Sender
	}
	return nil
}

// IntermediaryAddrResponse is the response to a share intermediary address request
type IntermediaryAddrResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *IntermediaryAddrResponse) Reset() {
	*x = IntermediaryAddrResponse{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IntermediaryAddrResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntermediaryAddrResponse) ProtoMessage() {}

func (x *IntermediaryAddrResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntermediaryAddrResponse.ProtoReflect.Descriptor instead.
func (*IntermediaryAddrResponse) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{8}
}

func (x *IntermediaryAddrResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *IntermediaryAddrResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

// IntermediaryAddrRequest is sent to request intermediary address information
type IntermediaryAddrRequest struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Domain         string                 `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	ProtocolPrefix string                 `protobuf:"bytes,2,opt,name=protocol_prefix,json=protocolPrefix,proto3" json:"protocol_prefix,omitempty"`
	PublicPort     uint32                 `protobuf:"varint,3,opt,name=public_port,json=publicPort,proto3" json:"public_port,omitempty"`
	ForwardId      string                 `protobuf:"bytes,4,opt,name=forward_id,json=forwardId,proto3" json:"forward_id,omitempty"`
	Sender         *Node                  `protobuf:"bytes,5,opt,name=sender,proto3" json:"sender,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *IntermediaryAddrRequest) Reset() {
	*x = IntermediaryAddrRequest{}
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IntermediaryAddrRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntermediaryAddrRequest) ProtoMessage() {}

func (x *IntermediaryAddrRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_grpc_proto_gossip_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntermediaryAddrRequest.ProtoReflect.Descriptor instead.
func (*IntermediaryAddrRequest) Descriptor() ([]byte, []int) {
	return file_internal_grpc_proto_gossip_proto_rawDescGZIP(), []int{9}
}

func (x *IntermediaryAddrRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *IntermediaryAddrRequest) GetProtocolPrefix() string {
	if x != nil {
		return x.ProtocolPrefix
	}
	return ""
}

func (x *IntermediaryAddrRequest) GetPublicPort() uint32 {
	if x != nil {
		return x.PublicPort
	}
	return 0
}

func (x *IntermediaryAddrRequest) GetForwardId() string {
	if x != nil {
		return x.ForwardId
	}
	return ""
}

func (x *IntermediaryAddrRequest) GetSender() *Node {
	if x != nil {
		return x.Sender
	}
	return nil
}

var File_internal_grpc_proto_gossip_proto protoreflect.FileDescriptor

const file_internal_grpc_proto_gossip_proto_rawDesc = "" +
	"\n" +
	" internal/grpc/proto/gossip.proto\x12\fzcdns.tunnel\"\x84\x01\n" +
	"\x04Node\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\tR\aaddress\x12\x1f\n" +
	"\vgossip_port\x18\x02 \x01(\x05R\n" +
	"gossipPort\x12\x19\n" +
	"\bssh_port\x18\x03 \x01(\x05R\asshPort\x12&\n" +
	"\x0fssh_listen_addr\x18\x04 \x01(\tR\rsshListenAddr\"<\n" +
	"\vJoinRequest\x12-\n" +
	"\bnew_node\x18\x01 \x01(\v2\x12.zcdns.tunnel.NodeR\anewNode\"s\n" +
	"\fJoinResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\x12\x14\n" +
	"\x05error\x18\x02 \x01(\tR\x05error\x123\n" +
	"\vknown_peers\x18\x03 \x03(\v2\x12.zcdns.tunnel.NodeR\n" +
	"knownPeers\"s\n" +
	"\x10HeartbeatRequest\x12*\n" +
	"\x06sender\x18\x01 \x01(\v2\x12.zcdns.tunnel.NodeR\x06sender\x123\n" +
	"\vknown_peers\x18\x02 \x03(\v2\x12.zcdns.tunnel.NodeR\n" +
	"knownPeers\"x\n" +
	"\x11HeartbeatResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\x12\x14\n" +
	"\x05error\x18\x02 \x01(\tR\x05error\x123\n" +
	"\vknown_peers\x18\x03 \x03(\v2\x12.zcdns.tunnel.NodeR\n" +
	"knownPeers\"\xd9\x01\n" +
	"\x15ForwardRequestMessage\x12\x16\n" +
	"\x06domain\x18\x01 \x01(\tR\x06domain\x12\x1b\n" +
	"\tbind_addr\x18\x02 \x01(\tR\bbindAddr\x12\x1b\n" +
	"\tbind_port\x18\x03 \x01(\rR\bbindPort\x12\x1d\n" +
	"\n" +
	"forward_id\x18\x04 \x01(\tR\tforwardId\x12#\n" +
	"\roriginal_addr\x18\x05 \x01(\tR\foriginalAddr\x12*\n" +
	"\x06sender\x18\x06 \x01(\v2\x12.zcdns.tunnel.NodeR\x06sender\"{\n" +
	"\x16ForwardResponseMessage\x12\x1d\n" +
	"\n" +
	"forward_id\x18\x01 \x01(\tR\tforwardId\x12\x18\n" +
	"\asuccess\x18\x02 \x01(\bR\asuccess\x12\x12\n" +
	"\x04port\x18\x03 \x01(\rR\x04port\x12\x14\n" +
	"\x05error\x18\x04 \x01(\tR\x05error\"\xf3\x01\n" +
	"\x17IntermediaryAddrMessage\x12\x16\n" +
	"\x06domain\x18\x01 \x01(\tR\x06domain\x12'\n" +
	"\x0fprotocol_prefix\x18\x02 \x01(\tR\x0eprotocolPrefix\x12\x1f\n" +
	"\vpublic_port\x18\x03 \x01(\rR\n" +
	"publicPort\x12+\n" +
	"\x11intermediary_addr\x18\x04 \x01(\tR\x10intermediaryAddr\x12\x1d\n" +
	"\n" +
	"forward_id\x18\x05 \x01(\tR\tforwardId\x12*\n" +
	"\x06sender\x18\x06 \x01(\v2\x12.zcdns.tunnel.NodeR\x06sender\"J\n" +
	"\x18IntermediaryAddrResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\x12\x14\n" +
	"\x05error\x18\x02 \x01(\tR\x05error\"\xc6\x01\n" +
	"\x17IntermediaryAddrRequest\x12\x16\n" +
	"\x06domain\x18\x01 \x01(\tR\x06domain\x12'\n" +
	"\x0fprotocol_prefix\x18\x02 \x01(\tR\x0eprotocolPrefix\x12\x1f\n" +
	"\vpublic_port\x18\x03 \x01(\rR\n" +
	"publicPort\x12\x1d\n" +
	"\n" +
	"forward_id\x18\x04 \x01(\tR\tforwardId\x12*\n" +
	"\x06sender\x18\x05 \x01(\v2\x12.zcdns.tunnel.NodeR\x06sender2\xd0\x03\n" +
	"\rGossipService\x12?\n" +
	"\x04Join\x12\x19.zcdns.tunnel.JoinRequest\x1a\x1a.zcdns.tunnel.JoinResponse\"\x00\x12N\n" +
	"\tHeartbeat\x12\x1e.zcdns.tunnel.HeartbeatRequest\x1a\x1f.zcdns.tunnel.HeartbeatResponse\"\x00\x12]\n" +
	"\x0eForwardRequest\x12#.zcdns.tunnel.ForwardRequestMessage\x1a$.zcdns.tunnel.ForwardResponseMessage\"\x00\x12h\n" +
	"\x15ShareIntermediaryAddr\x12%.zcdns.tunnel.IntermediaryAddrMessage\x1a&.zcdns.tunnel.IntermediaryAddrResponse\"\x00\x12e\n" +
	"\x13GetIntermediaryAddr\x12%.zcdns.tunnel.IntermediaryAddrRequest\x1a%.zcdns.tunnel.IntermediaryAddrMessage\"\x00B\"Z zcdns-tunnel/internal/grpc/protob\x06proto3"

var (
	file_internal_grpc_proto_gossip_proto_rawDescOnce sync.Once
	file_internal_grpc_proto_gossip_proto_rawDescData []byte
)

func file_internal_grpc_proto_gossip_proto_rawDescGZIP() []byte {
	file_internal_grpc_proto_gossip_proto_rawDescOnce.Do(func() {
		file_internal_grpc_proto_gossip_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_internal_grpc_proto_gossip_proto_rawDesc), len(file_internal_grpc_proto_gossip_proto_rawDesc)))
	})
	return file_internal_grpc_proto_gossip_proto_rawDescData
}

var file_internal_grpc_proto_gossip_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_internal_grpc_proto_gossip_proto_goTypes = []any{
	(*Node)(nil),                     // 0: zcdns.tunnel.Node
	(*JoinRequest)(nil),              // 1: zcdns.tunnel.JoinRequest
	(*JoinResponse)(nil),             // 2: zcdns.tunnel.JoinResponse
	(*HeartbeatRequest)(nil),         // 3: zcdns.tunnel.HeartbeatRequest
	(*HeartbeatResponse)(nil),        // 4: zcdns.tunnel.HeartbeatResponse
	(*ForwardRequestMessage)(nil),    // 5: zcdns.tunnel.ForwardRequestMessage
	(*ForwardResponseMessage)(nil),   // 6: zcdns.tunnel.ForwardResponseMessage
	(*IntermediaryAddrMessage)(nil),  // 7: zcdns.tunnel.IntermediaryAddrMessage
	(*IntermediaryAddrResponse)(nil), // 8: zcdns.tunnel.IntermediaryAddrResponse
	(*IntermediaryAddrRequest)(nil),  // 9: zcdns.tunnel.IntermediaryAddrRequest
}
var file_internal_grpc_proto_gossip_proto_depIdxs = []int32{
	0,  // 0: zcdns.tunnel.JoinRequest.new_node:type_name -> zcdns.tunnel.Node
	0,  // 1: zcdns.tunnel.JoinResponse.known_peers:type_name -> zcdns.tunnel.Node
	0,  // 2: zcdns.tunnel.HeartbeatRequest.sender:type_name -> zcdns.tunnel.Node
	0,  // 3: zcdns.tunnel.HeartbeatRequest.known_peers:type_name -> zcdns.tunnel.Node
	0,  // 4: zcdns.tunnel.HeartbeatResponse.known_peers:type_name -> zcdns.tunnel.Node
	0,  // 5: zcdns.tunnel.ForwardRequestMessage.sender:type_name -> zcdns.tunnel.Node
	0,  // 6: zcdns.tunnel.IntermediaryAddrMessage.sender:type_name -> zcdns.tunnel.Node
	0,  // 7: zcdns.tunnel.IntermediaryAddrRequest.sender:type_name -> zcdns.tunnel.Node
	1,  // 8: zcdns.tunnel.GossipService.Join:input_type -> zcdns.tunnel.JoinRequest
	3,  // 9: zcdns.tunnel.GossipService.Heartbeat:input_type -> zcdns.tunnel.HeartbeatRequest
	5,  // 10: zcdns.tunnel.GossipService.ForwardRequest:input_type -> zcdns.tunnel.ForwardRequestMessage
	7,  // 11: zcdns.tunnel.GossipService.ShareIntermediaryAddr:input_type -> zcdns.tunnel.IntermediaryAddrMessage
	9,  // 12: zcdns.tunnel.GossipService.GetIntermediaryAddr:input_type -> zcdns.tunnel.IntermediaryAddrRequest
	2,  // 13: zcdns.tunnel.GossipService.Join:output_type -> zcdns.tunnel.JoinResponse
	4,  // 14: zcdns.tunnel.GossipService.Heartbeat:output_type -> zcdns.tunnel.HeartbeatResponse
	6,  // 15: zcdns.tunnel.GossipService.ForwardRequest:output_type -> zcdns.tunnel.ForwardResponseMessage
	8,  // 16: zcdns.tunnel.GossipService.ShareIntermediaryAddr:output_type -> zcdns.tunnel.IntermediaryAddrResponse
	7,  // 17: zcdns.tunnel.GossipService.GetIntermediaryAddr:output_type -> zcdns.tunnel.IntermediaryAddrMessage
	13, // [13:18] is the sub-list for method output_type
	8,  // [8:13] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_internal_grpc_proto_gossip_proto_init() }
func file_internal_grpc_proto_gossip_proto_init() {
	if File_internal_grpc_proto_gossip_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_internal_grpc_proto_gossip_proto_rawDesc), len(file_internal_grpc_proto_gossip_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internal_grpc_proto_gossip_proto_goTypes,
		DependencyIndexes: file_internal_grpc_proto_gossip_proto_depIdxs,
		MessageInfos:      file_internal_grpc_proto_gossip_proto_msgTypes,
	}.Build()
	File_internal_grpc_proto_gossip_proto = out.File
	file_internal_grpc_proto_gossip_proto_goTypes = nil
	file_internal_grpc_proto_gossip_proto_depIdxs = nil
}
