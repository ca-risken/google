package main

import (
	"context"
	"fmt"

	mimosasql "github.com/ca-risken/common/pkg/database/sql"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	"github.com/vikyd/zero"
	"gorm.io/gorm"
)

type googleRepoInterface interface {
	// google_data_source
	ListGoogleDataSource(ctx context.Context, googleDataSourceID uint32, name string) (*[]common.GoogleDataSource, error)

	// gcp
	ListGCP(ctx context.Context, projectID, gcpID uint32, gcpProjectID string) (*[]common.GCP, error)
	GetGCP(ctx context.Context, projectID, gcpID uint32) (*common.GCP, error)
	UpsertGCP(ctx context.Context, gcp *google.GCPForUpsert) (*common.GCP, error)
	DeleteGCP(ctx context.Context, projectID uint32, gcpID uint32) error

	// gcp_data_source
	ListGCPDataSource(ctx context.Context, projectID, gcpID uint32) (*[]gcpDataSource, error)
	GetGCPDataSource(ctx context.Context, projectID, gcpID, googleDataSourceID uint32) (*gcpDataSource, error)
	UpsertGCPDataSource(ctx context.Context, gcpDataSource *google.GCPDataSourceForUpsert) (*gcpDataSource, error)
	DeleteGCPDataSource(ctx context.Context, projectID, gcpID, googleDataSourceID uint32) error
	ListGCPDataSourceByDataSourceID(ctx context.Context, googleDataSourceID uint32) (*[]gcpDataSource, error)
}

type googleRepository struct {
	MasterDB *gorm.DB
	SlaveDB  *gorm.DB
}

func newGoogleRepository(ctx context.Context, conf *DBConfig) googleRepoInterface {
	repo := googleRepository{}
	repo.MasterDB = initDB(ctx, conf, true)
	repo.SlaveDB = initDB(ctx, conf, false)
	return &repo
}

type DBConfig struct {
	MasterHost     string
	MasterUser     string
	MasterPassword string
	SlaveHost      string
	SlaveUser      string
	SlavePassword  string

	Schema        string
	Port          int
	LogMode       bool
	MaxConnection int
}

func initDB(ctx context.Context, conf *DBConfig, isMaster bool) *gorm.DB {
	var user, pass, host string
	if isMaster {
		user = conf.MasterUser
		pass = conf.MasterPassword
		host = conf.MasterHost
	} else {
		user = conf.SlaveUser
		pass = conf.SlavePassword
		host = conf.SlaveHost
	}

	dsn := fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?charset=utf8mb4&interpolateParams=true&parseTime=true&loc=Local",
		user, pass, host, conf.Port, conf.Schema)
	db, err := mimosasql.Open(dsn, conf.LogMode, conf.MaxConnection)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	appLogger.Infof(ctx, "Connected to Database. isMaster: %t", isMaster)
	return db
}

func convertZeroValueToNull(input interface{}) interface{} {
	if zero.IsZeroVal(input) {
		return gorm.Expr("NULL")
	}
	return input
}
