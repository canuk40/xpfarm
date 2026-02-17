package database

import (
	"log"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB(debug bool) {
	var err error
	dbPath := "xpfarm.db"

	logMode := logger.Silent
	if debug {
		logMode = logger.Info
	}

	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logMode),
	})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	// SQLite Performance Optimizations
	sqlDB, err := DB.DB()
	if err == nil {
		if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
			log.Printf("Warning: failed to set journal_mode: %v", err)
		}
		if _, err := sqlDB.Exec("PRAGMA synchronous=NORMAL"); err != nil {
			log.Printf("Warning: failed to set synchronous: %v", err)
		}
		if _, err := sqlDB.Exec("PRAGMA cache_size=-64000"); err != nil { // 64MB cache
			log.Printf("Warning: failed to set cache_size: %v", err)
		}
		if _, err := sqlDB.Exec("PRAGMA busy_timeout=10000"); err != nil {
			log.Printf("Warning: failed to set busy_timeout: %v", err)
		}
	}

	// Migrate the schema
	err = DB.AutoMigrate(&Asset{}, &Target{}, &ScanResult{}, &Setting{}, &Port{}, &WebAsset{}, &Vulnerability{}, &CVE{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}
}

func GetDB() *gorm.DB {
	return DB
}
