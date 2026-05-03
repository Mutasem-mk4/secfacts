// Code generated manually from api/proto/v1/axon.proto for repository builds.
package axonv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

type FindingType int32

const (
	FindingType_FINDING_TYPE_UNSPECIFIED FindingType = 0
	FindingType_FINDING_TYPE_SAST        FindingType = 1
	FindingType_FINDING_TYPE_DAST        FindingType = 2
	FindingType_FINDING_TYPE_SCA         FindingType = 3
	FindingType_FINDING_TYPE_CLOUD       FindingType = 4
	FindingType_FINDING_TYPE_SECRETS     FindingType = 5
)

var (
	FindingType_name = map[int32]string{
		0: "FINDING_TYPE_UNSPECIFIED",
		1: "FINDING_TYPE_SAST",
		2: "FINDING_TYPE_DAST",
		3: "FINDING_TYPE_SCA",
		4: "FINDING_TYPE_CLOUD",
		5: "FINDING_TYPE_SECRETS",
	}
	FindingType_value = map[string]int32{
		"FINDING_TYPE_UNSPECIFIED": 0,
		"FINDING_TYPE_SAST":        1,
		"FINDING_TYPE_DAST":        2,
		"FINDING_TYPE_SCA":         3,
		"FINDING_TYPE_CLOUD":       4,
		"FINDING_TYPE_SECRETS":     5,
	}
)

func (x FindingType) Enum() *FindingType {
	p := new(FindingType)
	*p = x
	return p
}

func (x FindingType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FindingType) Descriptor() protoreflect.EnumDescriptor {
	return file_api_proto_v1_axon_proto_enumTypes[0].Descriptor()
}

func (FindingType) Type() protoreflect.EnumType {
	return &file_api_proto_v1_axon_proto_enumTypes[0]
}

func (x FindingType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

type Severity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Score  float32 `protobuf:"fixed32,1,opt,name=score,proto3" json:"score,omitempty"`
	Label  string  `protobuf:"bytes,2,opt,name=label,proto3" json:"label,omitempty"`
	Vector string  `protobuf:"bytes,3,opt,name=vector,proto3" json:"vector,omitempty"`
}

type Vulnerability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Description string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	Cwe         []string `protobuf:"bytes,3,rep,name=cwe,proto3" json:"cwe,omitempty"`
	Aliases     []string `protobuf:"bytes,4,rep,name=aliases,proto3" json:"aliases,omitempty"`
}

type Location struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Path      string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	StartLine int32  `protobuf:"varint,2,opt,name=start_line,json=startLine,proto3" json:"start_line,omitempty"`
	StartCol  int32  `protobuf:"varint,3,opt,name=start_col,json=startCol,proto3" json:"start_col,omitempty"`
	EndLine   int32  `protobuf:"varint,4,opt,name=end_line,json=endLine,proto3" json:"end_line,omitempty"`
	EndCol    int32  `protobuf:"varint,5,opt,name=end_col,json=endCol,proto3" json:"end_col,omitempty"`
	Snippet   string `protobuf:"bytes,6,opt,name=snippet,proto3" json:"snippet,omitempty"`
}

type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uri     string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	Name    string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	Type    string `protobuf:"bytes,4,opt,name=type,proto3" json:"type,omitempty"`
}

type Evidence struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Provider      string                 `protobuf:"bytes,2,opt,name=provider,proto3" json:"provider,omitempty"`
	Type          FindingType            `protobuf:"varint,3,opt,name=type,proto3,enum=axon.v1.FindingType" json:"type,omitempty"`
	Vulnerability *Vulnerability         `protobuf:"bytes,4,opt,name=vulnerability,proto3" json:"vulnerability,omitempty"`
	Resource      *Resource              `protobuf:"bytes,5,opt,name=resource,proto3" json:"resource,omitempty"`
	Location      *Location              `protobuf:"bytes,6,opt,name=location,proto3" json:"location,omitempty"`
	Severity      *Severity              `protobuf:"bytes,7,opt,name=severity,proto3" json:"severity,omitempty"`
	Details       map[string]string      `protobuf:"bytes,8,rep,name=details,proto3" json:"details,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,9,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

type IngestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Evidence *Evidence `protobuf:"bytes,1,opt,name=evidence,proto3" json:"evidence,omitempty"`
}

type IngestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Accepted bool   `protobuf:"varint,2,opt,name=accepted,proto3" json:"accepted,omitempty"`
}

func (x *Severity) Reset()         { *x = Severity{} }
func (x *Severity) String() string { return protoimpl.X.MessageStringOf(x) }
func (*Severity) ProtoMessage()    {}
func (x *Severity) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*Severity) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{0}
}
func (x *Severity) GetScore() float32 {
	if x != nil {
		return x.Score
	}
	return 0
}
func (x *Severity) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}
func (x *Severity) GetVector() string {
	if x != nil {
		return x.Vector
	}
	return ""
}

func (x *Vulnerability) Reset()         { *x = Vulnerability{} }
func (x *Vulnerability) String() string { return protoimpl.X.MessageStringOf(x) }
func (*Vulnerability) ProtoMessage()    {}
func (x *Vulnerability) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*Vulnerability) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{1}
}
func (x *Vulnerability) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}
func (x *Vulnerability) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}
func (x *Vulnerability) GetCwe() []string {
	if x != nil {
		return x.Cwe
	}
	return nil
}
func (x *Vulnerability) GetAliases() []string {
	if x != nil {
		return x.Aliases
	}
	return nil
}

func (x *Location) Reset()         { *x = Location{} }
func (x *Location) String() string { return protoimpl.X.MessageStringOf(x) }
func (*Location) ProtoMessage()    {}
func (x *Location) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*Location) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{2}
}
func (x *Location) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}
func (x *Location) GetStartLine() int32 {
	if x != nil {
		return x.StartLine
	}
	return 0
}
func (x *Location) GetStartCol() int32 {
	if x != nil {
		return x.StartCol
	}
	return 0
}
func (x *Location) GetEndLine() int32 {
	if x != nil {
		return x.EndLine
	}
	return 0
}
func (x *Location) GetEndCol() int32 {
	if x != nil {
		return x.EndCol
	}
	return 0
}
func (x *Location) GetSnippet() string {
	if x != nil {
		return x.Snippet
	}
	return ""
}

func (x *Resource) Reset()         { *x = Resource{} }
func (x *Resource) String() string { return protoimpl.X.MessageStringOf(x) }
func (*Resource) ProtoMessage()    {}
func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*Resource) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{3}
}
func (x *Resource) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}
func (x *Resource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}
func (x *Resource) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}
func (x *Resource) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Evidence) Reset()         { *x = Evidence{} }
func (x *Evidence) String() string { return protoimpl.X.MessageStringOf(x) }
func (*Evidence) ProtoMessage()    {}
func (x *Evidence) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*Evidence) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{4}
}
func (x *Evidence) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}
func (x *Evidence) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}
func (x *Evidence) GetType() FindingType {
	if x != nil {
		return x.Type
	}
	return FindingType_FINDING_TYPE_UNSPECIFIED
}
func (x *Evidence) GetVulnerability() *Vulnerability {
	if x != nil {
		return x.Vulnerability
	}
	return nil
}
func (x *Evidence) GetResource() *Resource {
	if x != nil {
		return x.Resource
	}
	return nil
}
func (x *Evidence) GetLocation() *Location {
	if x != nil {
		return x.Location
	}
	return nil
}
func (x *Evidence) GetSeverity() *Severity {
	if x != nil {
		return x.Severity
	}
	return nil
}
func (x *Evidence) GetDetails() map[string]string {
	if x != nil {
		return x.Details
	}
	return nil
}
func (x *Evidence) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *IngestRequest) Reset()         { *x = IngestRequest{} }
func (x *IngestRequest) String() string { return protoimpl.X.MessageStringOf(x) }
func (*IngestRequest) ProtoMessage()    {}
func (x *IngestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*IngestRequest) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{5}
}
func (x *IngestRequest) GetEvidence() *Evidence {
	if x != nil {
		return x.Evidence
	}
	return nil
}

func (x *IngestResponse) Reset()         { *x = IngestResponse{} }
func (x *IngestResponse) String() string { return protoimpl.X.MessageStringOf(x) }
func (*IngestResponse) ProtoMessage()    {}
func (x *IngestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_proto_v1_axon_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
		return ms
	}
	return mi.MessageOf(x)
}
func (*IngestResponse) Descriptor() ([]byte, []int) {
	return file_api_proto_v1_axon_proto_rawDescGZIP(), []int{6}
}
func (x *IngestResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}
func (x *IngestResponse) GetAccepted() bool {
	if x != nil {
		return x.Accepted
	}
	return false
}

var File_api_proto_v1_axon_proto protoreflect.FileDescriptor

var file_api_proto_v1_axon_proto_rawDesc = []byte("axon")
var (
	file_api_proto_v1_axon_proto_rawDescOnce sync.Once
	file_api_proto_v1_axon_proto_rawDescData = file_api_proto_v1_axon_proto_rawDesc
)

func file_api_proto_v1_axon_proto_rawDescGZIP() []byte {
	file_api_proto_v1_axon_proto_rawDescOnce.Do(func() {
		file_api_proto_v1_axon_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_proto_v1_axon_proto_rawDescData)
	})
	return file_api_proto_v1_axon_proto_rawDescData
}

var file_api_proto_v1_axon_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_proto_v1_axon_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_api_proto_v1_axon_proto_goTypes = []any{
	(FindingType)(0),
	(*Severity)(nil),
	(*Vulnerability)(nil),
	(*Location)(nil),
	(*Resource)(nil),
	(*Evidence)(nil),
	(*IngestRequest)(nil),
	(*IngestResponse)(nil),
	(*timestamppb.Timestamp)(nil),
	nil,
}
var file_api_proto_v1_axon_proto_depIdxs = []int32{
	0, 2, 3, 1, 8, 5,
}

func init() { file_api_proto_v1_axon_proto_init() }
func file_api_proto_v1_axon_proto_init() {
	if File_api_proto_v1_axon_proto != nil {
		return
	}
	file_api_proto_v1_axon_proto_msgTypes[4].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_proto_v1_axon_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_proto_v1_axon_proto_goTypes,
		DependencyIndexes: file_api_proto_v1_axon_proto_depIdxs,
		EnumInfos:         file_api_proto_v1_axon_proto_enumTypes,
		MessageInfos:      file_api_proto_v1_axon_proto_msgTypes,
	}.Build()
	File_api_proto_v1_axon_proto = out.File
	file_api_proto_v1_axon_proto_rawDesc = nil
	file_api_proto_v1_axon_proto_goTypes = nil
	file_api_proto_v1_axon_proto_depIdxs = nil
}
