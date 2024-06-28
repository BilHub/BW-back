-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema pgvdb_schema
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema pgvdb_schema
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `pgvdb_schema` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `pgvdb_schema` ;

-- -----------------------------------------------------
-- Table `pgvdb_schema`.`asset_type`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`asset_type` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`asset_type` (
  `id` VARCHAR(4) NOT NULL,
  `description` VARCHAR(256) NOT NULL,
  `sub_type` VARCHAR(4) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  INDEX `fk_asset_sub_type_idx` (`sub_type` ASC) VISIBLE,
  CONSTRAINT `fk_asset_sub_type`
    FOREIGN KEY (`sub_type`)
    REFERENCES `pgvdb_schema`.`asset_type` (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`asset`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`asset` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`asset` (
  `id_cpe` VARCHAR(256) NOT NULL,
  `type` VARCHAR(4) NOT NULL,
  `producer` VARCHAR(128) NOT NULL,
  `name` VARCHAR(128) NOT NULL,
  `version` VARCHAR(32) NULL DEFAULT NULL,
  `links` VARCHAR(512) NULL DEFAULT NULL,
  PRIMARY KEY (`id_cpe`),
  UNIQUE INDEX `id_cpe_UNIQUE` (`id_cpe` ASC) VISIBLE,
  INDEX `fk_asset_type_asset_idx` (`type` ASC) VISIBLE,
  CONSTRAINT `fk_asset_type_asset`
    FOREIGN KEY (`type`)
    REFERENCES `pgvdb_schema`.`asset_type` (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`client_group`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`client_group` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`client_group` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(128) NOT NULL,
  `alerts` INT NULL DEFAULT NULL,
  `type` VARCHAR(128) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 3
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`client_asset`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`client_asset` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`client_asset` (
  `id_cpe` VARCHAR(256) NOT NULL,
  `type` VARCHAR(4) NOT NULL,
  `producer` VARCHAR(128) NOT NULL,
  `name` VARCHAR(128) NOT NULL,
  `version` VARCHAR(32) NULL DEFAULT NULL,
  `links` VARCHAR(512) NULL DEFAULT NULL,
  PRIMARY KEY (`id_cpe`),
  UNIQUE INDEX `id_cpe_UNIQUE` (`id_cpe` ASC) VISIBLE,
  INDEX `fk_asset_type_asset_idx` (`type` ASC) VISIBLE,
  CONSTRAINT `fk_asset_type_asset_client`
    FOREIGN KEY (`type`)
    REFERENCES `pgvdb_schema`.`asset_type` (`id`)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`asset_usage`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`asset_usage` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`asset_usage` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `asset` VARCHAR(256) NOT NULL,
  `asset_ref` VARCHAR(32) NULL DEFAULT NULL,
  `groupe` INT NOT NULL,
  `status` INT NULL DEFAULT '0',
  `modified` TINYINT(1) NULL DEFAULT '0',
  `importance` INT NULL DEFAULT NULL,
  `nb_asset` INT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `unique_asset_group_idx` (`asset_ref` ASC, `asset` ASC, `groupe` ASC) VISIBLE,
  INDEX `fk_asset_usage_asset_idx` (`asset` ASC) VISIBLE,
  INDEX `fk_asset_usage_group_idx` (`groupe` ASC) VISIBLE,
  CONSTRAINT `fk_asset_usage_group`
    FOREIGN KEY (`groupe`)
    REFERENCES `pgvdb_schema`.`client_group` (`id`)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT,
  CONSTRAINT `fk_client_asset_usage`
    FOREIGN KEY (`asset`)
    REFERENCES `pgvdb_schema`.`client_asset` (`id_cpe`))
ENGINE = InnoDB
AUTO_INCREMENT = 182
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`aut_alert`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`aut_alert` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`aut_alert` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `title` VARCHAR(255) NULL DEFAULT NULL,
  `message` TEXT NOT NULL,
  `links` TEXT NULL DEFAULT NULL,
  `created_at` DATETIME NOT NULL,
  `status` INT NULL DEFAULT '0',
  `solutions` TEXT NULL DEFAULT NULL,
  `published_on` DATETIME NULL DEFAULT NULL,
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 123564
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`client`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`client` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`client` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `firstname` VARCHAR(64) NOT NULL,
  `lastname` VARCHAR(64) NOT NULL,
  `tel_mobile` VARCHAR(16) NULL DEFAULT NULL,
  `tel_regular` VARCHAR(16) NULL DEFAULT NULL,
  `mail` VARCHAR(64) NOT NULL,
  `groupe` INT NOT NULL,
  `role` VARCHAR(64) NULL DEFAULT NULL,
  `status` INT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `unique_client_mail_idx` (`mail` ASC) VISIBLE,
  INDEX `fk_client_group_client_idx` (`groupe` ASC) VISIBLE,
  CONSTRAINT `fk_client_group_client`
    FOREIGN KEY (`groupe`)
    REFERENCES `pgvdb_schema`.`client_group` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 7
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`cve_temp`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`cve_temp` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`cve_temp` (
  `id` VARCHAR(16) NOT NULL,
  `title` VARCHAR(255) NULL DEFAULT NULL,
  `description` TEXT NULL DEFAULT NULL,
  `links` TEXT NULL DEFAULT NULL,
  `published_at` DATETIME NULL DEFAULT NULL,
  `cvss3` FLOAT NULL DEFAULT NULL,
  `mitigations` VARCHAR(512) NULL DEFAULT NULL,
  `workarounds` VARCHAR(512) NULL DEFAULT NULL,
  `last_modified` DATETIME NULL DEFAULT NULL,
  `cvss2` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`client_vulnerable_asset`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`client_vulnerable_asset` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`client_vulnerable_asset` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `asset` VARCHAR(255) NOT NULL,
  `cve` VARCHAR(16) NOT NULL,
  `date` DATETIME NULL DEFAULT NULL,
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  INDEX `fk_asset_vulnerable_asset__idx` (`asset` ASC) VISIBLE,
  INDEX `fk_client_vulnerable_asset_cve_idx` (`cve` ASC) VISIBLE,
  CONSTRAINT `fk_asset_client_vulnerable_asset`
    FOREIGN KEY (`asset`)
    REFERENCES `pgvdb_schema`.`client_asset` (`id_cpe`),
  CONSTRAINT `fk_client_vulnerable_asset_cve_temp`
    FOREIGN KEY (`cve`)
    REFERENCES `pgvdb_schema`.`cve_temp` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 10946177
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`cve`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`cve` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`cve` (
  `id` VARCHAR(16) NOT NULL,
  `title` VARCHAR(255) NULL DEFAULT NULL,
  `description` TEXT NULL DEFAULT NULL,
  `links` TEXT NULL DEFAULT NULL,
  `published_at` DATETIME NULL DEFAULT NULL,
  `cvss3` FLOAT NULL DEFAULT NULL,
  `mitigations` VARCHAR(512) NULL DEFAULT NULL,
  `workarounds` VARCHAR(512) NULL DEFAULT NULL,
  `last_modified` DATETIME NULL DEFAULT NULL,
  `cvss2` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`source`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`source` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`source` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `full_url` VARCHAR(512) NOT NULL,
  `digest` VARCHAR(32) NOT NULL,
  `url` VARCHAR(512) NULL DEFAULT NULL,
  `host` VARCHAR(256) NULL DEFAULT NULL,
  `mtbc` INT NULL DEFAULT '120',
  `port` INT NULL DEFAULT NULL,
  `sourcename` VARCHAR(128) NULL DEFAULT NULL,
  `category` INT NOT NULL,
  `language` VARCHAR(32) NULL DEFAULT NULL,
  `enabled` TINYINT(1) NULL DEFAULT '1',
  `use_keywords_matching` TINYINT(1) NULL DEFAULT '0',
  `rating` INT NULL DEFAULT NULL,
  `type` VARCHAR(45) NULL DEFAULT NULL,
  `last_update` DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `digest_UNIQUE` (`digest` ASC) VISIBLE,
  UNIQUE INDEX `full_url_UNIQUE` (`full_url` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 13
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`temp_vulnerable_asset`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`temp_vulnerable_asset` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`temp_vulnerable_asset` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `asset` VARCHAR(255) NOT NULL,
  `cve` VARCHAR(16) NOT NULL,
  `date` DATETIME NULL DEFAULT NULL,
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  INDEX `fk_asset_vulnerable_asset__idx` (`asset` ASC) VISIBLE,
  INDEX `fk_client_vulnerable_asset_cve_idx` (`cve` ASC) VISIBLE,
  CONSTRAINT `fk_client_asset_temp_vulnerable_asset`
    FOREIGN KEY (`asset`)
    REFERENCES `pgvdb_schema`.`client_asset` (`id_cpe`)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT,
  CONSTRAINT `fk_cve_temp_vulnerable_asset`
    FOREIGN KEY (`cve`)
    REFERENCES `pgvdb_schema`.`cve_temp` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 10943201
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`usage_aut_alert`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`usage_aut_alert` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`usage_aut_alert` (
  `aut_alert` INT NOT NULL,
  `usage_id` INT NOT NULL,
  `cve` VARCHAR(16) NOT NULL,
  `status` INT NULL DEFAULT '0',
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`aut_alert`, `usage_id`, `cve`),
  INDEX `fk_usage_aut_alert_asset_usage_idx` (`usage_id` ASC) VISIBLE,
  INDEX `fk_cve_temp_usage_aut_alert_idx` (`cve` ASC) VISIBLE,
  CONSTRAINT `fk_aut_alerte_usage_aut_alert`
    FOREIGN KEY (`aut_alert`)
    REFERENCES `pgvdb_schema`.`aut_alert` (`id`),
  CONSTRAINT `fk_cve_temp_usage_aut_alert`
    FOREIGN KEY (`cve`)
    REFERENCES `pgvdb_schema`.`cve_temp` (`id`),
  CONSTRAINT `fk_usage_aut_alert_asset_usage`
    FOREIGN KEY (`usage_id`)
    REFERENCES `pgvdb_schema`.`asset_usage` (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`vulnerable_asset`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`vulnerable_asset` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`vulnerable_asset` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `asset` VARCHAR(255) NOT NULL,
  `cve` VARCHAR(16) NOT NULL,
  `date` DATETIME NULL DEFAULT NULL,
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `unique_vulnerable_asset_idx` (`asset` ASC, `cve` ASC) VISIBLE,
  INDEX `fk_asset_vulnerable_asset__idx` (`asset` ASC) VISIBLE,
  INDEX `fk_vulnerable_asset_cve_idx` (`cve` ASC) VISIBLE,
  CONSTRAINT `fk_asset_vulnerable_asset_`
    FOREIGN KEY (`asset`)
    REFERENCES `pgvdb_schema`.`asset` (`id_cpe`),
  CONSTRAINT `fk_vulnerable_asset_cve`
    FOREIGN KEY (`cve`)
    REFERENCES `pgvdb_schema`.`cve` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 10574777
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `pgvdb_schema`.`vulnerable_asset_archive`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `pgvdb_schema`.`vulnerable_asset_archive` ;

CREATE TABLE IF NOT EXISTS `pgvdb_schema`.`vulnerable_asset_archive` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `item` INT NULL DEFAULT NULL,
  `asset` VARCHAR(255) NOT NULL,
  `cve` VARCHAR(16) NOT NULL,
  `date` DATETIME NULL DEFAULT NULL,
  `score` FLOAT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `unique_vulnerable_asset_archive_idx` (`asset` ASC, `cve` ASC) VISIBLE,
  INDEX `fk_asset_vulnerable_asset_archive_idx` (`asset` ASC) VISIBLE,
  INDEX `fk_vulnerable_asset_archive_cve_idx` (`cve` ASC) VISIBLE,
  CONSTRAINT `fk_asset_vulnerable_asset_archive`
    FOREIGN KEY (`asset`)
    REFERENCES `pgvdb_schema`.`asset` (`id_cpe`)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT,
  CONSTRAINT `fk_vulnerable_asset_archive_cve`
    FOREIGN KEY (`cve`)
    REFERENCES `pgvdb_schema`.`cve` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 16407070
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;