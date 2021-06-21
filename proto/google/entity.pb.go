// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.17.3
// source: google/entity.proto

package google

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

// Status
type Status int32

const (
	Status_UNKNOWN     Status = 0
	Status_OK          Status = 1
	Status_CONFIGURED  Status = 2
	Status_IN_PROGRESS Status = 3
	Status_ERROR       Status = 4
)

// Enum value maps for Status.
var (
	Status_name = map[int32]string{
		0: "UNKNOWN",
		1: "OK",
		2: "CONFIGURED",
		3: "IN_PROGRESS",
		4: "ERROR",
	}
	Status_value = map[string]int32{
		"UNKNOWN":     0,
		"OK":          1,
		"CONFIGURED":  2,
		"IN_PROGRESS": 3,
		"ERROR":       4,
	}
)

func (x Status) Enum() *Status {
	p := new(Status)
	*p = x
	return p
}

func (x Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Status) Descriptor() protoreflect.EnumDescriptor {
	return file_google_entity_proto_enumTypes[0].Descriptor()
}

func (Status) Type() protoreflect.EnumType {
	return &file_google_entity_proto_enumTypes[0]
}

func (x Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Status.Descriptor instead.
func (Status) EnumDescriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{0}
}

// Empty
type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{0}
}

// GoogleDataSource
type GoogleDataSource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GoogleDataSourceId uint32  `protobuf:"varint,1,opt,name=google_data_source_id,json=googleDataSourceId,proto3" json:"google_data_source_id,omitempty"`
	Name               string  `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description        string  `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	MaxScore           float32 `protobuf:"fixed32,4,opt,name=max_score,json=maxScore,proto3" json:"max_score,omitempty"`
	CreatedAt          int64   `protobuf:"varint,5,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt          int64   `protobuf:"varint,6,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
}

func (x *GoogleDataSource) Reset() {
	*x = GoogleDataSource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GoogleDataSource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GoogleDataSource) ProtoMessage() {}

func (x *GoogleDataSource) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GoogleDataSource.ProtoReflect.Descriptor instead.
func (*GoogleDataSource) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{1}
}

func (x *GoogleDataSource) GetGoogleDataSourceId() uint32 {
	if x != nil {
		return x.GoogleDataSourceId
	}
	return 0
}

func (x *GoogleDataSource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GoogleDataSource) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *GoogleDataSource) GetMaxScore() float32 {
	if x != nil {
		return x.MaxScore
	}
	return 0
}

func (x *GoogleDataSource) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *GoogleDataSource) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

// GCP
type GCP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GcpId             uint32 `protobuf:"varint,1,opt,name=gcp_id,json=gcpId,proto3" json:"gcp_id,omitempty"`
	Name              string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	ProjectId         uint32 `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	GcpOrganizationId string `protobuf:"bytes,4,opt,name=gcp_organization_id,json=gcpOrganizationId,proto3" json:"gcp_organization_id,omitempty"`
	GcpProjectId      string `protobuf:"bytes,5,opt,name=gcp_project_id,json=gcpProjectId,proto3" json:"gcp_project_id,omitempty"`
	VerificationCode  string `protobuf:"bytes,6,opt,name=verification_code,json=verificationCode,proto3" json:"verification_code,omitempty"`
	CreatedAt         int64  `protobuf:"varint,7,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt         int64  `protobuf:"varint,8,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
}

func (x *GCP) Reset() {
	*x = GCP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCP) ProtoMessage() {}

func (x *GCP) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCP.ProtoReflect.Descriptor instead.
func (*GCP) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{2}
}

func (x *GCP) GetGcpId() uint32 {
	if x != nil {
		return x.GcpId
	}
	return 0
}

func (x *GCP) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GCP) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *GCP) GetGcpOrganizationId() string {
	if x != nil {
		return x.GcpOrganizationId
	}
	return ""
}

func (x *GCP) GetGcpProjectId() string {
	if x != nil {
		return x.GcpProjectId
	}
	return ""
}

func (x *GCP) GetVerificationCode() string {
	if x != nil {
		return x.VerificationCode
	}
	return ""
}

func (x *GCP) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *GCP) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

// GCPDataSource
type GCPDataSource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GcpId              uint32  `protobuf:"varint,1,opt,name=gcp_id,json=gcpId,proto3" json:"gcp_id,omitempty"`                                            // gcp_data_source.gcp_id
	GoogleDataSourceId uint32  `protobuf:"varint,2,opt,name=google_data_source_id,json=googleDataSourceId,proto3" json:"google_data_source_id,omitempty"` // gcp_data_source.google_data_source_id
	ProjectId          uint32  `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`                                // gcp_data_source.project_id
	Status             Status  `protobuf:"varint,4,opt,name=status,proto3,enum=google.google.Status" json:"status,omitempty"`                             // gcp_data_source.status
	StatusDetail       string  `protobuf:"bytes,5,opt,name=status_detail,json=statusDetail,proto3" json:"status_detail,omitempty"`                        // gcp_data_source.status_detail
	ScanAt             int64   `protobuf:"varint,6,opt,name=scan_at,json=scanAt,proto3" json:"scan_at,omitempty"`                                         // gcp_data_source.scan_at
	CreatedAt          int64   `protobuf:"varint,7,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`                                // gcp_data_source.created_at
	UpdatedAt          int64   `protobuf:"varint,8,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`                                // gcp_data_source.updated_at
	GcpOrganizationId  string  `protobuf:"bytes,9,opt,name=gcp_organization_id,json=gcpOrganizationId,proto3" json:"gcp_organization_id,omitempty"`       // gcp.gcp_organization_id
	GcpProjectId       string  `protobuf:"bytes,10,opt,name=gcp_project_id,json=gcpProjectId,proto3" json:"gcp_project_id,omitempty"`                     // gcp.gcp_project_id
	Name               string  `protobuf:"bytes,11,opt,name=name,proto3" json:"name,omitempty"`                                                           // google_data_source.name
	Description        string  `protobuf:"bytes,12,opt,name=description,proto3" json:"description,omitempty"`                                             // google_data_source.description
	MaxScore           float32 `protobuf:"fixed32,13,opt,name=max_score,json=maxScore,proto3" json:"max_score,omitempty"`                                 // google_data_source.max_score
}

func (x *GCPDataSource) Reset() {
	*x = GCPDataSource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCPDataSource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCPDataSource) ProtoMessage() {}

func (x *GCPDataSource) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCPDataSource.ProtoReflect.Descriptor instead.
func (*GCPDataSource) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{3}
}

func (x *GCPDataSource) GetGcpId() uint32 {
	if x != nil {
		return x.GcpId
	}
	return 0
}

func (x *GCPDataSource) GetGoogleDataSourceId() uint32 {
	if x != nil {
		return x.GoogleDataSourceId
	}
	return 0
}

func (x *GCPDataSource) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *GCPDataSource) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *GCPDataSource) GetStatusDetail() string {
	if x != nil {
		return x.StatusDetail
	}
	return ""
}

func (x *GCPDataSource) GetScanAt() int64 {
	if x != nil {
		return x.ScanAt
	}
	return 0
}

func (x *GCPDataSource) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *GCPDataSource) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

func (x *GCPDataSource) GetGcpOrganizationId() string {
	if x != nil {
		return x.GcpOrganizationId
	}
	return ""
}

func (x *GCPDataSource) GetGcpProjectId() string {
	if x != nil {
		return x.GcpProjectId
	}
	return ""
}

func (x *GCPDataSource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GCPDataSource) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *GCPDataSource) GetMaxScore() float32 {
	if x != nil {
		return x.MaxScore
	}
	return 0
}

// GCPForUpsert
type GCPForUpsert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GcpId             uint32 `protobuf:"varint,1,opt,name=gcp_id,json=gcpId,proto3" json:"gcp_id,omitempty"` // Unique key for entity.
	Name              string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	ProjectId         uint32 `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	GcpOrganizationId string `protobuf:"bytes,4,opt,name=gcp_organization_id,json=gcpOrganizationId,proto3" json:"gcp_organization_id,omitempty"`
	GcpProjectId      string `protobuf:"bytes,5,opt,name=gcp_project_id,json=gcpProjectId,proto3" json:"gcp_project_id,omitempty"`
	VerificationCode  string `protobuf:"bytes,6,opt,name=verification_code,json=verificationCode,proto3" json:"verification_code,omitempty"`
}

func (x *GCPForUpsert) Reset() {
	*x = GCPForUpsert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCPForUpsert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCPForUpsert) ProtoMessage() {}

func (x *GCPForUpsert) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCPForUpsert.ProtoReflect.Descriptor instead.
func (*GCPForUpsert) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{4}
}

func (x *GCPForUpsert) GetGcpId() uint32 {
	if x != nil {
		return x.GcpId
	}
	return 0
}

func (x *GCPForUpsert) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GCPForUpsert) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *GCPForUpsert) GetGcpOrganizationId() string {
	if x != nil {
		return x.GcpOrganizationId
	}
	return ""
}

func (x *GCPForUpsert) GetGcpProjectId() string {
	if x != nil {
		return x.GcpProjectId
	}
	return ""
}

func (x *GCPForUpsert) GetVerificationCode() string {
	if x != nil {
		return x.VerificationCode
	}
	return ""
}

// GCPDataSourceForUpsert
type GCPDataSourceForUpsert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GcpId              uint32 `protobuf:"varint,1,opt,name=gcp_id,json=gcpId,proto3" json:"gcp_id,omitempty"`
	GoogleDataSourceId uint32 `protobuf:"varint,2,opt,name=google_data_source_id,json=googleDataSourceId,proto3" json:"google_data_source_id,omitempty"`
	ProjectId          uint32 `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	Status             Status `protobuf:"varint,4,opt,name=status,proto3,enum=google.google.Status" json:"status,omitempty"`
	StatusDetail       string `protobuf:"bytes,5,opt,name=status_detail,json=statusDetail,proto3" json:"status_detail,omitempty"`
	ScanAt             int64  `protobuf:"varint,6,opt,name=scan_at,json=scanAt,proto3" json:"scan_at,omitempty"`
}

func (x *GCPDataSourceForUpsert) Reset() {
	*x = GCPDataSourceForUpsert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_entity_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCPDataSourceForUpsert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCPDataSourceForUpsert) ProtoMessage() {}

func (x *GCPDataSourceForUpsert) ProtoReflect() protoreflect.Message {
	mi := &file_google_entity_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCPDataSourceForUpsert.ProtoReflect.Descriptor instead.
func (*GCPDataSourceForUpsert) Descriptor() ([]byte, []int) {
	return file_google_entity_proto_rawDescGZIP(), []int{5}
}

func (x *GCPDataSourceForUpsert) GetGcpId() uint32 {
	if x != nil {
		return x.GcpId
	}
	return 0
}

func (x *GCPDataSourceForUpsert) GetGoogleDataSourceId() uint32 {
	if x != nil {
		return x.GoogleDataSourceId
	}
	return 0
}

func (x *GCPDataSourceForUpsert) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *GCPDataSourceForUpsert) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *GCPDataSourceForUpsert) GetStatusDetail() string {
	if x != nil {
		return x.StatusDetail
	}
	return ""
}

func (x *GCPDataSourceForUpsert) GetScanAt() int64 {
	if x != nil {
		return x.ScanAt
	}
	return 0
}

var File_google_entity_proto protoreflect.FileDescriptor

var file_google_entity_proto_rawDesc = []byte{
	0x0a, 0x13, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x22, 0x07, 0x0a, 0x05, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0xd6, 0x01,
	0x0a, 0x10, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x12, 0x31, 0x0a, 0x15, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x5f, 0x64, 0x61, 0x74,
	0x61, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x12, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x6d,
	0x61, 0x78, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08,
	0x6d, 0x61, 0x78, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x90, 0x02, 0x0a, 0x03, 0x47, 0x43, 0x50, 0x12, 0x15,
	0x0a, 0x06, 0x67, 0x63, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x67, 0x63, 0x70, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70,
	0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x13, 0x67, 0x63, 0x70, 0x5f,
	0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x67, 0x63, 0x70, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69,
	0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e, 0x67, 0x63, 0x70, 0x5f,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x67, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x12, 0x2b,
	0x0a, 0x11, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x76, 0x65, 0x72, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0xcc, 0x03, 0x0a, 0x0d, 0x47, 0x43,
	0x50, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x67,
	0x63, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x67, 0x63, 0x70,
	0x49, 0x64, 0x12, 0x31, 0x0a, 0x15, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x5f, 0x64, 0x61, 0x74,
	0x61, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x12, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x64, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x17, 0x0a, 0x07, 0x73, 0x63, 0x61, 0x6e,
	0x5f, 0x61, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x73, 0x63, 0x61, 0x6e, 0x41,
	0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x2e, 0x0a, 0x13, 0x67, 0x63, 0x70, 0x5f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x67, 0x63,
	0x70, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12,
	0x24, 0x0a, 0x0e, 0x67, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x67, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x6a,
	0x65, 0x63, 0x74, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x6d,
	0x61, 0x78, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08,
	0x6d, 0x61, 0x78, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x22, 0xdb, 0x01, 0x0a, 0x0c, 0x47, 0x43, 0x50,
	0x46, 0x6f, 0x72, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x67, 0x63, 0x70,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x67, 0x63, 0x70, 0x49, 0x64,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63,
	0x74, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x13, 0x67, 0x63, 0x70, 0x5f, 0x6f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x11, 0x67, 0x63, 0x70, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e, 0x67, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x67, 0x63, 0x70,
	0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x12, 0x2b, 0x0a, 0x11, 0x76, 0x65, 0x72,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x22, 0xee, 0x01, 0x0a, 0x16, 0x47, 0x43, 0x50, 0x44, 0x61,
	0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x6f, 0x72, 0x55, 0x70, 0x73, 0x65, 0x72,
	0x74, 0x12, 0x15, 0x0a, 0x06, 0x67, 0x63, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x05, 0x67, 0x63, 0x70, 0x49, 0x64, 0x12, 0x31, 0x0a, 0x15, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x44,
	0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70,
	0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x17,
	0x0a, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x61, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x06, 0x73, 0x63, 0x61, 0x6e, 0x41, 0x74, 0x2a, 0x49, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x06,
	0x0a, 0x02, 0x4f, 0x4b, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47,
	0x55, 0x52, 0x45, 0x44, 0x10, 0x02, 0x12, 0x0f, 0x0a, 0x0b, 0x49, 0x4e, 0x5f, 0x50, 0x52, 0x4f,
	0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x03, 0x12, 0x09, 0x0a, 0x05, 0x45, 0x52, 0x52, 0x4f, 0x52,
	0x10, 0x04, 0x42, 0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x43, 0x79, 0x62, 0x65, 0x72, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x6d, 0x69, 0x6d, 0x6f,
	0x73, 0x61, 0x2d, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_google_entity_proto_rawDescOnce sync.Once
	file_google_entity_proto_rawDescData = file_google_entity_proto_rawDesc
)

func file_google_entity_proto_rawDescGZIP() []byte {
	file_google_entity_proto_rawDescOnce.Do(func() {
		file_google_entity_proto_rawDescData = protoimpl.X.CompressGZIP(file_google_entity_proto_rawDescData)
	})
	return file_google_entity_proto_rawDescData
}

var file_google_entity_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_google_entity_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_google_entity_proto_goTypes = []interface{}{
	(Status)(0),                    // 0: google.google.Status
	(*Empty)(nil),                  // 1: google.google.Empty
	(*GoogleDataSource)(nil),       // 2: google.google.GoogleDataSource
	(*GCP)(nil),                    // 3: google.google.GCP
	(*GCPDataSource)(nil),          // 4: google.google.GCPDataSource
	(*GCPForUpsert)(nil),           // 5: google.google.GCPForUpsert
	(*GCPDataSourceForUpsert)(nil), // 6: google.google.GCPDataSourceForUpsert
}
var file_google_entity_proto_depIdxs = []int32{
	0, // 0: google.google.GCPDataSource.status:type_name -> google.google.Status
	0, // 1: google.google.GCPDataSourceForUpsert.status:type_name -> google.google.Status
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_google_entity_proto_init() }
func file_google_entity_proto_init() {
	if File_google_entity_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_google_entity_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
		file_google_entity_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GoogleDataSource); i {
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
		file_google_entity_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCP); i {
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
		file_google_entity_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCPDataSource); i {
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
		file_google_entity_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCPForUpsert); i {
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
		file_google_entity_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCPDataSourceForUpsert); i {
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
			RawDescriptor: file_google_entity_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_google_entity_proto_goTypes,
		DependencyIndexes: file_google_entity_proto_depIdxs,
		EnumInfos:         file_google_entity_proto_enumTypes,
		MessageInfos:      file_google_entity_proto_msgTypes,
	}.Build()
	File_google_entity_proto = out.File
	file_google_entity_proto_rawDesc = nil
	file_google_entity_proto_goTypes = nil
	file_google_entity_proto_depIdxs = nil
}
