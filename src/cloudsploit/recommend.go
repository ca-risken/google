package main

import (
	"fmt"

	"github.com/ca-risken/google/pkg/common"
)

type dataSourceRecommend struct{}

func (d *dataSourceRecommend) DataSource() string {
	return common.CloudSploitDataSource
}

func (d *dataSourceRecommend) ScanFailureRisk() string {
	return fmt.Sprintf("Failed to scan %s, So you are not gathering the latest security threat information.", common.CloudSploitDataSource)
}

func (d *dataSourceRecommend) ScanFailureRecommend() string {
	return `Please review the following items and rescan,
	- Ensure the error message of the DataSource.
	- Ensure the access rights you set for the DataSource and the reachability of the network.
	- Refer to the documentation to make sure you have not omitted any of the steps you have set up.
	- https://docs.security-hub.jp/google/overview_gcp/
	- If this does not resolve the problem, or if you suspect that the problem is server-side, please contact the system administrators.`
}
