package database

import (
	"log"
	"time"

	"xpfarm/internal/crypto"
	"xpfarm/internal/storage/findings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB(debug bool) {
	// Init encryption key before anything touches the DB
	if err := crypto.Init(); err != nil {
		log.Printf("Warning: failed to init crypto: %v — secrets will be stored unencrypted", err)
	}

	var err error
	dbPath := "data/xpfarm.db"

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
		if _, err := sqlDB.Exec("PRAGMA journal_size_limit=67108864"); err != nil { // Cap WAL at 64MB
			log.Printf("Warning: failed to set journal_size_limit: %v", err)
		}

		// WAL mode serializes writes internally; allow multiple readers in parallel.
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	// Migrate the schema — core tables
	err = DB.AutoMigrate(&Asset{}, &Target{}, &ScanResult{}, &Setting{}, &Port{}, &WebAsset{}, &Vulnerability{}, &CVE{}, &SavedSearch{}, &NucleiTemplate{}, &ScanProfile{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	// Migrate the normalized findings tables
	if err := findings.Migrate(DB); err != nil {
		log.Fatal("failed to migrate findings tables:", err)
	}

	// Seed default searches if none exist
	var count int64
	DB.Model(&SavedSearch{}).Count(&count)
	if count == 0 {
		defaultSearches := []SavedSearch{
			{Name: "Critical / High Vulns", QueryData: `{"source":"vulnerabilities","columns":["vuln.name","vuln.severity","vuln.template_id","target.value"],"distinct":false,"rules":[{"field":"vuln.severity","value":"^(critical|high)$"}]}`},
			{Name: "Exposed Admin Panels", QueryData: `{"source":"web_assets","columns":["web.url","web.title","web.status_code","target.value"],"distinct":false,"rules":[{"field":"web.url","value":"admin"},{"logical":"OR","field":"web.title","value":"login"}]}`},
			{Name: "Non-Standard HTTP Ports", QueryData: `{"source":"ports","columns":["port.port","port.service","port.product","target.value"],"distinct":false,"rules":[{"field":"port.port","value":"^(80|443)$","negate":true},{"logical":"AND","field":"port.service","value":"http"}]}`},
			{Name: "React / Vue Apps", QueryData: `{"source":"web_assets","columns":["web.url","web.tech_stack","web.title","target.value"],"distinct":false,"rules":[{"field":"web.tech_stack","value":"react|vue"}]}`},
			{Name: "All Unique Ports", QueryData: `{"source":"ports","columns":["port.port","port.service"],"distinct":true,"rules":[]}`},
			{Name: "All URLs With Host", QueryData: `{"source":"web_assets","columns":["web.url","target.value","asset.name"],"distinct":false,"rules":[]}`},
		}
		DB.Create(&defaultSearches)
	}
}

func GetDB() *gorm.DB {
	return DB
}
