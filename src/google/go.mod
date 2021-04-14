module github.com/CyberAgent/mimosa-google/src/google

go 1.16

require (
	github.com/CyberAgent/mimosa-google/pkg/common v0.0.0-20210413063714-8c11dcfcd932
	github.com/CyberAgent/mimosa-google/proto/google v0.0.0-20210413063714-8c11dcfcd932
	github.com/aws/aws-sdk-go v1.38.18
	github.com/go-sql-driver/mysql v1.6.0
	github.com/jinzhu/gorm v1.9.16
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.6.1
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20210410081132-afb366fc7cd1 // indirect
	golang.org/x/sys v0.0.0-20210412220455-f1c623a9e750 // indirect
	google.golang.org/api v0.44.0
	google.golang.org/genproto v0.0.0-20210406143921-e86de6bf7a46 // indirect
	google.golang.org/grpc v1.37.0
)
