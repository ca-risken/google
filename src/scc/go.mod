module github.com/ca-risken/google/src/scc

go 1.16

require (
	cloud.google.com/go v0.94.1 // indirect
	cloud.google.com/go/securitycenter v0.1.0
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go v1.42.22
	github.com/ca-risken/common/pkg/logging v0.0.0-20220113015330-0e8462d52b5b
	github.com/ca-risken/common/pkg/profiler v0.0.0-20220304031727-c94e2c463b27
	github.com/ca-risken/common/pkg/sqs v0.0.0-20220426050416-a654045b9fa5
	github.com/ca-risken/common/pkg/tracer v0.0.0-20220425094653-eace2e0a3d4a
	github.com/ca-risken/core/proto/alert v0.0.0-20211202081113-c4c0e9d1af86
	github.com/ca-risken/core/proto/finding v0.0.0-20220420065103-ec7428a46fe5
	github.com/ca-risken/google/pkg/common v0.0.0-20220106084245-d6fa7174f282
	github.com/ca-risken/google/proto/google v0.0.0-20210907055015-a746c2b3b5cf
	github.com/gassara-kys/envconfig v1.4.4
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	google.golang.org/api v0.56.0
	google.golang.org/genproto v0.0.0-20210903162649-d08c68adba83
	google.golang.org/grpc v1.45.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.38.0
)
