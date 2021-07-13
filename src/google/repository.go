package main

import (
	"fmt"

	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

type googleRepoInterface interface {
	// google_data_source
	ListGoogleDataSource(googleDataSourceID uint32, name string) (*[]common.GoogleDataSource, error)

	// gcp
	ListGCP(projectID, gcpID uint32, gcpProjectID string) (*[]common.GCP, error)
	GetGCP(projectID, gcpID uint32) (*common.GCP, error)
	UpsertGCP(gcp *google.GCPForUpsert) (*common.GCP, error)
	DeleteGCP(projectID uint32, gcpID uint32) error

	// gcp_data_source
	ListGCPDataSource(projectID, gcpID uint32) (*[]gcpDataSource, error)
	GetGCPDataSource(projectID, gcpID, googleDataSourceID uint32) (*gcpDataSource, error)
	UpsertGCPDataSource(gcpDataSource *google.GCPDataSourceForUpsert) (*gcpDataSource, error)
	DeleteGCPDataSource(projectID, gcpID, googleDataSourceID uint32) error
}

type googleRepository struct {
	MasterDB *gorm.DB
	SlaveDB  *gorm.DB
}

func newGoogleRepository() googleRepoInterface {
	repo := googleRepository{}
	repo.MasterDB = initDB(true)
	repo.SlaveDB = initDB(false)
	return &repo
}

type dbConfig struct {
	MasterHost     string `split_words:"true" required:"true"`
	MasterUser     string `split_words:"true" required:"true"`
	MasterPassword string `split_words:"true" required:"true"`
	SlaveHost      string `split_words:"true"`
	SlaveUser      string `split_words:"true"`
	SlavePassword  string `split_words:"true"`

	Schema  string `required:"true"`
	Port    int    `required:"true"`
	LogMode bool   `split_words:"true" default:"false"`
}

func initDB(isMaster bool) *gorm.DB {
	conf := &dbConfig{}
	if err := envconfig.Process("DB", conf); err != nil {
		appLogger.Fatalf("Failed to load DB config. err: %+v", err)
	}

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
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}})
	if err != nil {
		appLogger.Fatalf("Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	if conf.LogMode {
		db.Logger.LogMode(logger.Info)
	}
	appLogger.Infof("Connected to Database. isMaster: %t", isMaster)
	return db
}

func convertZeroValueToNull(input interface{}) interface{} {
	if zero.IsZeroVal(input) {
		return gorm.Expr("NULL")
	}
	return input
}
