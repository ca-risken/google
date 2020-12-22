# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [google/entity.proto](#google/entity.proto)
    - [Empty](#google.google.Empty)
    - [GCP](#google.google.GCP)
    - [GCPForUpsert](#google.google.GCPForUpsert)
    - [GoogleDataSource](#google.google.GoogleDataSource)
  
    - [Status](#google.google.Status)
  
- [google/service.proto](#google/service.proto)
    - [DeleteGCPRequest](#google.google.DeleteGCPRequest)
    - [GetGCPRequest](#google.google.GetGCPRequest)
    - [GetGCPResponse](#google.google.GetGCPResponse)
    - [InvokeScanGCPRequest](#google.google.InvokeScanGCPRequest)
    - [ListGCPRequest](#google.google.ListGCPRequest)
    - [ListGCPResponse](#google.google.ListGCPResponse)
    - [ListGoogleDataSourceRequest](#google.google.ListGoogleDataSourceRequest)
    - [ListGoogleDataSourceResponse](#google.google.ListGoogleDataSourceResponse)
    - [PutGCPRequest](#google.google.PutGCPRequest)
    - [PutGCPResponse](#google.google.PutGCPResponse)
  
    - [GoogleService](#google.google.GoogleService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="google/entity.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## google/entity.proto



<a name="google.google.Empty"></a>

### Empty
Empty






<a name="google.google.GCP"></a>

### GCP
GCP


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gcp_id | [uint32](#uint32) |  |  |
| google_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| gcp_organization_id | [string](#string) |  |  |
| gcp_project_id | [string](#string) |  |  |
| status | [Status](#google.google.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="google.google.GCPForUpsert"></a>

### GCPForUpsert
GCPForUpsert


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gcp_id | [uint32](#uint32) |  | Unique key for entity. |
| google_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| gcp_organization_id | [string](#string) |  |  |
| gcp_project_id | [string](#string) |  |  |
| status | [Status](#google.google.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |






<a name="google.google.GoogleDataSource"></a>

### GoogleDataSource
GoogleDataSource


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| google_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| description | [string](#string) |  |  |
| max_score | [float](#float) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |





 


<a name="google.google.Status"></a>

### Status
Status

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| OK | 1 |  |
| CONFIGURED | 2 |  |
| NOT_CONFIGURED | 3 |  |
| ERROR | 4 |  |


 

 

 



<a name="google/service.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## google/service.proto



<a name="google.google.DeleteGCPRequest"></a>

### DeleteGCPRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gcp_id | [uint32](#uint32) |  |  |






<a name="google.google.GetGCPRequest"></a>

### GetGCPRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gcp_id | [uint32](#uint32) |  |  |






<a name="google.google.GetGCPResponse"></a>

### GetGCPResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gcp | [GCP](#google.google.GCP) |  |  |






<a name="google.google.InvokeScanGCPRequest"></a>

### InvokeScanGCPRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gcp_id | [uint32](#uint32) |  |  |






<a name="google.google.ListGCPRequest"></a>

### ListGCPRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| google_data_source_id | [uint32](#uint32) |  |  |
| gcp_id | [uint32](#uint32) |  |  |






<a name="google.google.ListGCPResponse"></a>

### ListGCPResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gcp | [GCP](#google.google.GCP) | repeated |  |






<a name="google.google.ListGoogleDataSourceRequest"></a>

### ListGoogleDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| google_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |






<a name="google.google.ListGoogleDataSourceResponse"></a>

### ListGoogleDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| google_data_source | [GoogleDataSource](#google.google.GoogleDataSource) | repeated |  |






<a name="google.google.PutGCPRequest"></a>

### PutGCPRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gcp | [GCPForUpsert](#google.google.GCPForUpsert) |  |  |






<a name="google.google.PutGCPResponse"></a>

### PutGCPResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gcp | [GCP](#google.google.GCP) |  |  |





 

 

 


<a name="google.google.GoogleService"></a>

### GoogleService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListGoogleDataSource | [ListGoogleDataSourceRequest](#google.google.ListGoogleDataSourceRequest) | [ListGoogleDataSourceResponse](#google.google.ListGoogleDataSourceResponse) | Google DataSource |
| ListGCP | [ListGCPRequest](#google.google.ListGCPRequest) | [ListGCPResponse](#google.google.ListGCPResponse) | GCP |
| GetGCP | [GetGCPRequest](#google.google.GetGCPRequest) | [GetGCPResponse](#google.google.GetGCPResponse) |  |
| PutGCP | [PutGCPRequest](#google.google.PutGCPRequest) | [PutGCPResponse](#google.google.PutGCPResponse) |  |
| DeleteGCP | [DeleteGCPRequest](#google.google.DeleteGCPRequest) | [Empty](#google.google.Empty) |  |
| InvokeScanGCP | [InvokeScanGCPRequest](#google.google.InvokeScanGCPRequest) | [Empty](#google.google.Empty) | Scan

For ondeamnd |
| InvokeScanAll | [Empty](#google.google.Empty) | [Empty](#google.google.Empty) | For scheduled |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

