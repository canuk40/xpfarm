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

	// SQLite Performance Optimizations & Concurrency Fixes
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
		if _, err := sqlDB.Exec("PRAGMA busy_timeout=30000"); err != nil { // Increase to 30 seconds
			log.Printf("Warning: failed to set busy_timeout: %v", err)
		}

		// Prevent "database is locked" during heavy concurrent scanning
		// Serialize all write operations to SQLite by limiting to a single connection.
		// WAL mode allows concurrent reads while one connection is writing.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}

	// Migrate the schema
	err = DB.AutoMigrate(&Asset{}, &Target{}, &ScanResult{}, &Setting{}, &Port{}, &WebAsset{}, &Vulnerability{}, &CVE{}, &SavedSearch{}, &NucleiTemplate{}, &ScanProfile{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	// Seed default searches if none exist
	var count int64
	DB.Model(&SavedSearch{}).Count(&count)
	if count == 0 {
		defaultSearches := []SavedSearch{
			{Name: "HELP: Explore Query Syntax (#description)", QueryData: `{"rules":[{"field":"target.type","operator":"equals","value":"domain"},{"logical":"AND","field":"target.value","operator":"glob","value":"*.corp.local"},{"logical":"AND","field":"target.status","operator":"equals","value":"up"},{"logical":"OR","field":"web.tech_stack","operator":"glob","value":"*mico-*_key*"},{"logical":"AND","field":"web.status_code","operator":"equals","value":"200"},{"logical":"AND","field":"web.url","operator":"regex","value":"^https?://.*\\.js$"},{"logical":"AND","field":"web.title","operator":"contains","value":"Dashboard"},{"logical":"OR","field":"port.port","operator":"not_equals","value":"80"},{"logical":"AND","field":"port.service","operator":"contains","value":"ssh"},{"logical":"OR","field":"vuln.name","operator":"contains","value":"CVE-2024"},{"logical":"AND","field":"vuln.severity","operator":"regex","value":"^(critical|high)$"}]}`},
			{Name: "Critical / High Vulns", QueryData: `{"rules":[{"field":"vuln.severity","operator":"regex","value":"^(critical|high)$"}]}`},
			{Name: "Exposed Admin Panels", QueryData: `{"rules":[{"field":"web.url","operator":"glob","value":"*admin*"},{"logical":"OR","field":"web.title","operator":"glob","value":"*login*"}]}`},
			{Name: "Web Servers on Non-Standard Ports", QueryData: `{"rules":[{"field":"port.port","operator":"not_equals","value":"80"},{"logical":"AND","field":"port.port","operator":"not_equals","value":"443"},{"logical":"AND","field":"port.service","operator":"contains","value":"http"}]}`},
			{Name: "React / Vue Applications", QueryData: `{"rules":[{"field":"web.tech_stack","operator":"glob","value":"*react*"},{"logical":"OR","field":"web.tech_stack","operator":"glob","value":"*vue*"}]}`},
		}
		DB.Create(&defaultSearches)
	}
}

func GetDB() *gorm.DB {
	return DB
}
