-- Tobi AIM Security Schema V3
-- Supports Replay Protection, Rate Limits, Kill-Switch Policies, Force Update & Binary Build Manifests

CREATE TABLE IF NOT EXISTS `api_nonces` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `nonce_hex` VARCHAR(80) NOT NULL UNIQUE,
    `created_at` INT UNSIGNED NOT NULL,
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `rate_limits` (
    `bucket_key` VARCHAR(128) PRIMARY KEY,
    `window_start` INT UNSIGNED NOT NULL,
    `hit_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `blocked_until` INT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `server_policies` (
    `package_id` VARCHAR(128) PRIMARY KEY, -- '__global__' for system-wide defaults
    `server_open` TINYINT(1) NOT NULL DEFAULT 1,
    `server_closed_message` TEXT NULL,
    `force_update` TINYINT(1) NOT NULL DEFAULT 0,
    `min_required_version` VARCHAR(32) NOT NULL DEFAULT '2.1.0',
    `latest_version` VARCHAR(32) NOT NULL DEFAULT '2.1.0',
    `download_url` VARCHAR(512) NULL,
    `update_message` TEXT NULL,
    `enforce_binary_hash` TINYINT(1) NOT NULL DEFAULT 0,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `build_manifests` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `package_id` VARCHAR(128) NOT NULL,
    `version` VARCHAR(32) NOT NULL,
    `build` VARCHAR(32) NOT NULL DEFAULT '',
    `app_hash` CHAR(64) NOT NULL,
    `sec_hash` CHAR(64) NOT NULL,
    `active` TINYINT(1) NOT NULL DEFAULT 1,
    `revoked` TINYINT(1) NOT NULL DEFAULT 0,
    `note` VARCHAR(255) NOT NULL DEFAULT '',
    `registered_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY `uniq_pkg_hashes` (`package_id`, `app_hash`, `sec_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `license_keys` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `license_key` VARCHAR(128) NOT NULL UNIQUE,
    `duration` VARCHAR(32) NOT NULL DEFAULT '30d',
    `expiry_date` DATETIME NULL,
    `expiry_ts` BIGINT NOT NULL DEFAULT 0,
    `max_devices` INT UNSIGNED NOT NULL DEFAULT 1,
    `role` VARCHAR(32) NOT NULL DEFAULT 'vip',
    `status` VARCHAR(32) NOT NULL DEFAULT 'active',
    `is_used` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `key_devices` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `license_key_id` BIGINT UNSIGNED NOT NULL,
    `device_fp` CHAR(64) NOT NULL,
    `activated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_seen` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `last_ip` VARCHAR(64) NOT NULL DEFAULT '',
    UNIQUE KEY `uniq_key_dev` (`license_key_id`, `device_fp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `security_logs` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `event_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `action` VARCHAR(64) NOT NULL,
    `key_masked` VARCHAR(64) NOT NULL DEFAULT '',
    `device_fp` VARCHAR(80) NOT NULL DEFAULT '',
    `ip_addr` VARCHAR(64) NOT NULL DEFAULT '',
    `details` TEXT NULL,
    INDEX `idx_event_time` (`event_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `banned_devices` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `hwid` VARCHAR(128) NOT NULL UNIQUE,
    `reason` VARCHAR(255) NOT NULL DEFAULT '',
    `banned_by` VARCHAR(64) NOT NULL DEFAULT 'admin',
    `source_key` VARCHAR(128) NOT NULL DEFAULT '',
    `active` TINYINT(1) NOT NULL DEFAULT 1,
    `banned_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `server_users` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(32) NOT NULL DEFAULT 'member',
    `hwid` VARCHAR(128) NOT NULL DEFAULT '',
    `device_fp_hash` CHAR(64) NOT NULL DEFAULT '',
    `device_label` VARCHAR(128) NOT NULL DEFAULT '',
    `active_session_token` CHAR(64) NOT NULL DEFAULT '',
    `active_ua_hash` CHAR(64) NOT NULL DEFAULT '',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `is_hwid_blocked` TINYINT(1) NOT NULL DEFAULT 0,
    `expiry_date` VARCHAR(32) NOT NULL DEFAULT 'permanent',
    `last_login` DATETIME NULL,
    `last_ip` VARCHAR(64) NOT NULL DEFAULT '',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
