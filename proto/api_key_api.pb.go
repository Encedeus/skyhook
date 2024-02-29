// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: api_key_api.proto

package protoapi

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AccountAPIKeyCreateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId      *UUID    `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Description string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	IpAddresses []string `protobuf:"bytes,3,rep,name=ip_addresses,json=ipAddresses,proto3" json:"ip_addresses,omitempty"`
}

func (x *AccountAPIKeyCreateRequest) Reset() {
	*x = AccountAPIKeyCreateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyCreateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyCreateRequest) ProtoMessage() {}

func (x *AccountAPIKeyCreateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyCreateRequest.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyCreateRequest) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{0}
}

func (x *AccountAPIKeyCreateRequest) GetUserId() *UUID {
	if x != nil {
		return x.UserId
	}
	return nil
}

func (x *AccountAPIKeyCreateRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *AccountAPIKeyCreateRequest) GetIpAddresses() []string {
	if x != nil {
		return x.IpAddresses
	}
	return nil
}

type AccountAPIKeyCreateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccountApiKey *AccountAPIKey `protobuf:"bytes,1,opt,name=account_api_key,json=accountApiKey,proto3" json:"account_api_key,omitempty"`
}

func (x *AccountAPIKeyCreateResponse) Reset() {
	*x = AccountAPIKeyCreateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyCreateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyCreateResponse) ProtoMessage() {}

func (x *AccountAPIKeyCreateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyCreateResponse.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyCreateResponse) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{1}
}

func (x *AccountAPIKeyCreateResponse) GetAccountApiKey() *AccountAPIKey {
	if x != nil {
		return x.AccountApiKey
	}
	return nil
}

type AccountAPIKeyDeleteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *UUID `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *AccountAPIKeyDeleteRequest) Reset() {
	*x = AccountAPIKeyDeleteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyDeleteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyDeleteRequest) ProtoMessage() {}

func (x *AccountAPIKeyDeleteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyDeleteRequest.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyDeleteRequest) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{2}
}

func (x *AccountAPIKeyDeleteRequest) GetId() *UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

type AccountAPIKeyDeleteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *AccountAPIKeyDeleteResponse) Reset() {
	*x = AccountAPIKeyDeleteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyDeleteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyDeleteResponse) ProtoMessage() {}

func (x *AccountAPIKeyDeleteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyDeleteResponse.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyDeleteResponse) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{3}
}

type AccountAPIKeyFindOneRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id *UUID `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *AccountAPIKeyFindOneRequest) Reset() {
	*x = AccountAPIKeyFindOneRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyFindOneRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyFindOneRequest) ProtoMessage() {}

func (x *AccountAPIKeyFindOneRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyFindOneRequest.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyFindOneRequest) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{4}
}

func (x *AccountAPIKeyFindOneRequest) GetId() *UUID {
	if x != nil {
		return x.Id
	}
	return nil
}

type AccountAPIKeyFindOneResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccountApiKey *AccountAPIKey `protobuf:"bytes,1,opt,name=account_api_key,json=accountApiKey,proto3" json:"account_api_key,omitempty"`
}

func (x *AccountAPIKeyFindOneResponse) Reset() {
	*x = AccountAPIKeyFindOneResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyFindOneResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyFindOneResponse) ProtoMessage() {}

func (x *AccountAPIKeyFindOneResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyFindOneResponse.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyFindOneResponse) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{5}
}

func (x *AccountAPIKeyFindOneResponse) GetAccountApiKey() *AccountAPIKey {
	if x != nil {
		return x.AccountApiKey
	}
	return nil
}

type AccountAPIKeyFindManyByUserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId *UUID `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
}

func (x *AccountAPIKeyFindManyByUserRequest) Reset() {
	*x = AccountAPIKeyFindManyByUserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyFindManyByUserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyFindManyByUserRequest) ProtoMessage() {}

func (x *AccountAPIKeyFindManyByUserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyFindManyByUserRequest.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyFindManyByUserRequest) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{6}
}

func (x *AccountAPIKeyFindManyByUserRequest) GetUserId() *UUID {
	if x != nil {
		return x.UserId
	}
	return nil
}

type AccountAPIKeyFindManyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccountApiKeys []*AccountAPIKey `protobuf:"bytes,1,rep,name=account_api_keys,json=accountApiKeys,proto3" json:"account_api_keys,omitempty"`
}

func (x *AccountAPIKeyFindManyResponse) Reset() {
	*x = AccountAPIKeyFindManyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_key_api_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccountAPIKeyFindManyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccountAPIKeyFindManyResponse) ProtoMessage() {}

func (x *AccountAPIKeyFindManyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_key_api_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccountAPIKeyFindManyResponse.ProtoReflect.Descriptor instead.
func (*AccountAPIKeyFindManyResponse) Descriptor() ([]byte, []int) {
	return file_api_key_api_proto_rawDescGZIP(), []int{7}
}

func (x *AccountAPIKeyFindManyResponse) GetAccountApiKeys() []*AccountAPIKey {
	if x != nil {
		return x.AccountApiKeys
	}
	return nil
}

var File_api_key_api_proto protoreflect.FileDescriptor

var file_api_key_api_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x70, 0x69, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x0d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x81, 0x01, 0x0a, 0x1a, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b,
	0x65, 0x79, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1e, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x05, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x70, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x70, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x65, 0x73, 0x22, 0x55, 0x0a, 0x1b, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41,
	0x50, 0x49, 0x4b, 0x65, 0x79, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x36, 0x0a, 0x0f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x61,
	0x70, 0x69, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x41,
	0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x52, 0x0d, 0x61, 0x63,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x22, 0x33, 0x0a, 0x1a, 0x41,
	0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x52, 0x02, 0x69, 0x64,
	0x22, 0x1d, 0x0a, 0x1b, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65,
	0x79, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x34, 0x0a, 0x1b, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79,
	0x46, 0x69, 0x6e, 0x64, 0x4f, 0x6e, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x55, 0x55, 0x49,
	0x44, 0x52, 0x02, 0x69, 0x64, 0x22, 0x56, 0x0a, 0x1c, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74,
	0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x46, 0x69, 0x6e, 0x64, 0x4f, 0x6e, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x36, 0x0a, 0x0f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74,
	0x5f, 0x61, 0x70, 0x69, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e,
	0x2e, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x52, 0x0d,
	0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x22, 0x44, 0x0a,
	0x22, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x46, 0x69,
	0x6e, 0x64, 0x4d, 0x61, 0x6e, 0x79, 0x42, 0x79, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x1e, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x52, 0x06, 0x75, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x22, 0x59, 0x0a, 0x1d, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50,
	0x49, 0x4b, 0x65, 0x79, 0x46, 0x69, 0x6e, 0x64, 0x4d, 0x61, 0x6e, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x38, 0x0a, 0x10, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f,
	0x61, 0x70, 0x69, 0x5f, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e,
	0x2e, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x52, 0x0e,
	0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x41, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x73, 0x42, 0x0f,
	0x5a, 0x0d, 0x2e, 0x2f, 0x67, 0x6f, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x61, 0x70, 0x69, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_key_api_proto_rawDescOnce sync.Once
	file_api_key_api_proto_rawDescData = file_api_key_api_proto_rawDesc
)

func file_api_key_api_proto_rawDescGZIP() []byte {
	file_api_key_api_proto_rawDescOnce.Do(func() {
		file_api_key_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_key_api_proto_rawDescData)
	})
	return file_api_key_api_proto_rawDescData
}

var file_api_key_api_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_api_key_api_proto_goTypes = []interface{}{
	(*AccountAPIKeyCreateRequest)(nil),         // 0: AccountAPIKeyCreateRequest
	(*AccountAPIKeyCreateResponse)(nil),        // 1: AccountAPIKeyCreateResponse
	(*AccountAPIKeyDeleteRequest)(nil),         // 2: AccountAPIKeyDeleteRequest
	(*AccountAPIKeyDeleteResponse)(nil),        // 3: AccountAPIKeyDeleteResponse
	(*AccountAPIKeyFindOneRequest)(nil),        // 4: AccountAPIKeyFindOneRequest
	(*AccountAPIKeyFindOneResponse)(nil),       // 5: AccountAPIKeyFindOneResponse
	(*AccountAPIKeyFindManyByUserRequest)(nil), // 6: AccountAPIKeyFindManyByUserRequest
	(*AccountAPIKeyFindManyResponse)(nil),      // 7: AccountAPIKeyFindManyResponse
	(*UUID)(nil),                               // 8: UUID
	(*AccountAPIKey)(nil),                      // 9: AccountAPIKey
}
var file_api_key_api_proto_depIdxs = []int32{
	8, // 0: AccountAPIKeyCreateRequest.user_id:type_name -> UUID
	9, // 1: AccountAPIKeyCreateResponse.account_api_key:type_name -> AccountAPIKey
	8, // 2: AccountAPIKeyDeleteRequest.id:type_name -> UUID
	8, // 3: AccountAPIKeyFindOneRequest.id:type_name -> UUID
	9, // 4: AccountAPIKeyFindOneResponse.account_api_key:type_name -> AccountAPIKey
	8, // 5: AccountAPIKeyFindManyByUserRequest.user_id:type_name -> UUID
	9, // 6: AccountAPIKeyFindManyResponse.account_api_keys:type_name -> AccountAPIKey
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_api_key_api_proto_init() }
func file_api_key_api_proto_init() {
	if File_api_key_api_proto != nil {
		return
	}
	file_generic_proto_init()
	file_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_api_key_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyCreateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyCreateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyDeleteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyDeleteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyFindOneRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyFindOneResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyFindManyByUserRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_key_api_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccountAPIKeyFindManyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_key_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_key_api_proto_goTypes,
		DependencyIndexes: file_api_key_api_proto_depIdxs,
		MessageInfos:      file_api_key_api_proto_msgTypes,
	}.Build()
	File_api_key_api_proto = out.File
	file_api_key_api_proto_rawDesc = nil
	file_api_key_api_proto_goTypes = nil
	file_api_key_api_proto_depIdxs = nil
}
