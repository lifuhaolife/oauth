-- 鉴权服务数据库初始化脚本
-- MySQL 8.0+

CREATE DATABASE IF NOT EXISTS auth_service DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE auth_service;

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL COMMENT '用户名',
    password_hash VARCHAR(255) NOT NULL COMMENT 'BCrypt 密码哈希',
    phone_encrypted VARBINARY(255) NULL COMMENT 'AES 加密的手机号，无手机号时为 NULL',
    wechat_openid VARCHAR(64) DEFAULT NULL COMMENT '微信 OpenID',
    wechat_unionid VARCHAR(64) DEFAULT NULL COMMENT '微信 UnionID',
    avatar VARCHAR(255) DEFAULT '' COMMENT '头像 URL',
    nickname VARCHAR(100) DEFAULT '' COMMENT '昵称',
    status TINYINT UNSIGNED DEFAULT 1 COMMENT '状态：0-禁用 1-正常',
    role VARCHAR(20) DEFAULT 'user' COMMENT '角色：user/admin',
    last_login_at TIMESTAMP NULL DEFAULT NULL COMMENT '最后登录时间',
    last_login_ip VARCHAR(45) DEFAULT '' COMMENT '最后登录 IP',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',

    UNIQUE KEY uk_username (username),
    UNIQUE KEY uk_wechat_openid (wechat_openid),
    KEY idx_status (status),
    KEY idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表';

-- Token 黑名单表
CREATE TABLE IF NOT EXISTS token_blacklist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    jti VARCHAR(64) NOT NULL COMMENT 'JWT ID',
    expired_at TIMESTAMP NOT NULL COMMENT '过期时间',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',

    UNIQUE KEY uk_jti (jti),
    KEY idx_expired_at (expired_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Token 黑名单表';

-- 登录日志表
CREATE TABLE IF NOT EXISTS login_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED DEFAULT NULL COMMENT '用户 ID',
    login_type VARCHAR(20) NOT NULL COMMENT '登录类型：PASSWORD/WECHAT',
    ip_address VARCHAR(45) DEFAULT '' COMMENT 'IP 地址',
    user_agent TEXT COMMENT 'User-Agent',
    status TINYINT UNSIGNED NOT NULL COMMENT '状态：0-失败 1-成功',
    fail_reason VARCHAR(255) DEFAULT '' COMMENT '失败原因',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',

    KEY idx_user_id (user_id),
    KEY idx_created_at (created_at),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='登录日志表';

-- 密钥记录表 (审计用)
CREATE TABLE IF NOT EXISTS key_store_record (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(50) NOT NULL COMMENT '密钥名称',
    key_fingerprint VARCHAR(64) DEFAULT '' COMMENT '密钥指纹',
    is_used TINYINT UNSIGNED DEFAULT 0 COMMENT '是否已使用：0-否 1-是',
    used_at TIMESTAMP NULL DEFAULT NULL COMMENT '使用时间',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    expired_at TIMESTAMP NOT NULL COMMENT '过期时间',

    UNIQUE KEY uk_key_name (key_name),
    KEY idx_expired_at (expired_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='密钥记录表';

-- 插入默认管理员账号 (密码需要 BCrypt 哈希，这里仅做示例)
-- 默认账号：admin / Admin@123
-- 实际使用时请生成正确的 BCrypt 哈希
INSERT INTO users (username, password_hash, phone_encrypted, role, status)
VALUES ('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', NULL, 'admin', 1)
ON DUPLICATE KEY UPDATE username=username;
