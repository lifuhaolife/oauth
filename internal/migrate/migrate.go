package migrate

import (
	"crypto/md5"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// schemaMigration 迁移版本追踪表
type schemaMigration struct {
	Version     string    `gorm:"primaryKey;size:20"`
	Description string    `gorm:"size:255"`
	AppliedAt   time.Time `gorm:"autoCreateTime"`
	Checksum    string    `gorm:"size:32"` // MD5 hex
}

func (schemaMigration) TableName() string {
	return "schema_migrations"
}

// migrationFile 描述一个迁移文件
type migrationFile struct {
	version     string // 如 "1"
	description string // 如 "init"
	filename    string // 如 "V1__init.sql"
	content     []byte
	checksum    string
}

// RunMigrations 执行所有未应用的 SQL 迁移文件
// 流程：
//  1. 建 schema_migrations 表（如不存在）
//  2. 扫描 embed 内的 SQL，按版本号升序排序
//  3. 跳过已记录的版本；已记录但 checksum 不匹配则停止（防止篡改）
//  4. 事务内执行新版本 SQL，成功后写入 schema_migrations
func RunMigrations(db *gorm.DB) error {
	// 1. 创建版本追踪表
	if err := db.AutoMigrate(&schemaMigration{}); err != nil {
		return fmt.Errorf("[Migration] 创建 schema_migrations 表失败: %v", err)
	}

	// 2. 扫描迁移文件
	files, err := scanMigrations()
	if err != nil {
		return fmt.Errorf("[Migration] 扫描迁移文件失败: %v", err)
	}

	// 3. 加载已应用的版本
	applied := make(map[string]schemaMigration)
	var rows []schemaMigration
	if err := db.Find(&rows).Error; err != nil {
		return fmt.Errorf("[Migration] 查询已应用版本失败: %v", err)
	}
	for _, r := range rows {
		applied[r.Version] = r
	}

	// 4. 按顺序执行未应用的迁移
	for _, f := range files {
		if existing, ok := applied[f.version]; ok {
			// 已应用：校验 checksum 防篡改
			if existing.Checksum != f.checksum {
				return fmt.Errorf("[Migration] 版本 %s 的 SQL 文件已被修改（checksum 不匹配），停止迁移", f.version)
			}
			log.Printf("[Migration] 跳过 %s（已应用）", f.filename)
			continue
		}

		// 未应用：在事务中执行
		log.Printf("[Migration] 执行 %s ...", f.filename)
		err := db.Transaction(func(tx *gorm.DB) error {
			// 分号分割多条语句依次执行
			statements := splitStatements(string(f.content))
			for _, stmt := range statements {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				if err := tx.Exec(stmt).Error; err != nil {
					return fmt.Errorf("执行语句失败: %v\nSQL: %.200s", err, stmt)
				}
			}
			// 记录版本
			record := schemaMigration{
				Version:     f.version,
				Description: f.description,
				Checksum:    f.checksum,
			}
			return tx.Create(&record).Error
		})
		if err != nil {
			return fmt.Errorf("[Migration] %s 执行失败: %v", f.filename, err)
		}
		log.Printf("[Migration] 应用 %s 成功", f.filename)
	}

	return nil
}

// scanMigrations 扫描 embed 文件系统，解析迁移文件并按版本升序排序
func scanMigrations() ([]migrationFile, error) {
	var files []migrationFile

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		name := entry.Name() // 例：V1__init.sql
		if !strings.HasPrefix(name, "V") {
			continue
		}

		// 解析版本号和描述
		withoutExt := strings.TrimSuffix(name, ".sql") // V1__init
		parts := strings.SplitN(withoutExt[1:], "__", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的迁移文件名：%s（期望格式 V{N}__{description}.sql）", name)
		}
		version := parts[0]
		description := strings.ReplaceAll(parts[1], "_", " ")

		content, err := migrationsFS.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			return nil, err
		}

		checksum := fmt.Sprintf("%x", md5.Sum(content))

		files = append(files, migrationFile{
			version:     version,
			description: description,
			filename:    name,
			content:     content,
			checksum:    checksum,
		})
	}

	// 按版本号数值升序排序
	sort.Slice(files, func(i, j int) bool {
		vi := parseVersionNum(files[i].version)
		vj := parseVersionNum(files[j].version)
		return vi < vj
	})

	return files, nil
}

// parseVersionNum 将版本字符串解析为整数（用于排序）
func parseVersionNum(v string) int {
	n := 0
	fmt.Sscanf(v, "%d", &n)
	return n
}

// splitStatements 按分号分割 SQL 文件为独立语句（忽略注释行）
func splitStatements(sql string) []string {
	var result []string
	for _, stmt := range strings.Split(sql, ";") {
		// 过滤纯注释行
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		// 去掉仅含注释的空语句
		lines := strings.Split(stmt, "\n")
		var meaningful []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "--") {
				meaningful = append(meaningful, line)
			}
		}
		if len(meaningful) > 0 {
			result = append(result, stmt)
		}
	}
	return result
}
