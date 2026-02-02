package database

import (
	"log"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB() {
	var err error
	dbPath := "xpfarm.db"

	// Use absolute path if possible, but for now relative to execution is fine
	// or we can use the user's home directory. Sticking to current directory as per plan.

	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	// Migrate the schema
	err = DB.AutoMigrate(&Asset{}, &Target{}, &ScanResult{}, &Setting{}, &Port{}, &WebAsset{}, &Vulnerability{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}
}

func GetDB() *gorm.DB {
	return DB
}
