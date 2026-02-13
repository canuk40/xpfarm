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
		if _, err := sqlDB.Exec("PRAGMA busy_timeout=5000"); err != nil {
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
