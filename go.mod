module github.com/ca-risken/google

go 1.18

require (
	cloud.google.com/go/asset v1.8.0
	cloud.google.com/go/iam v0.5.0
	cloud.google.com/go/securitycenter v1.14.0
	cloud.google.com/go/storage v1.28.0
	github.com/aws/aws-sdk-go-v2 v1.17.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.19.15
	github.com/ca-risken/common/pkg/grpc_client v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/logging v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/portscan v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/profiler v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/sqs v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/tracer v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/core/proto/alert v0.0.0-20220428031553-0579e204c316
	github.com/ca-risken/core/proto/finding v0.0.0-20220428031553-0579e204c316
	github.com/ca-risken/datasource-api v0.4.1
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/gassara-kys/envconfig v1.4.4
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/sync v0.1.0
	google.golang.org/api v0.102.0
	google.golang.org/genproto v0.0.0-20221024183307-1bc688fe9f3e
	google.golang.org/grpc v1.51.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.43.1
)

require (
	cloud.google.com/go v0.104.0 // indirect
	cloud.google.com/go/compute v1.12.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.1 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.0.0-20211129110424-6491aa3bf583 // indirect
	github.com/DataDog/datadog-go v4.8.2+incompatible // indirect
	github.com/DataDog/datadog-go/v5 v5.0.2 // indirect
	github.com/DataDog/gostackparse v0.5.0 // indirect
	github.com/DataDog/sketches-go v1.2.1 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Ullaakut/nmap v2.0.2+incompatible // indirect
	github.com/Ullaakut/nmap/v2 v2.1.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/config v1.15.4 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.4 // indirect
	github.com/aws/smithy-go v1.13.4 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210804190019-f964ff605595 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/googleapis/gax-go/v2 v2.6.0 // indirect
	github.com/googleapis/go-type-adapters v1.0.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20220617031537-928513b29760 // indirect
	golang.org/x/net v0.0.0-20221014081412-f15817d10f9b // indirect
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783 // indirect
	golang.org/x/sys v0.0.0-20220728004956-3c1f35247d10 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	inet.af/netaddr v0.0.0-20220617031823-097006376321 // indirect
)
