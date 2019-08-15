CREATE DATABASE `secure_auth`;

CREATE TABLE `secure_auth`.`audit` (
  `audit_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `audit_event` varchar(255) DEFAULT NULL,
  `audit_epoch` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `user_id` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`audit_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `audit-user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE `users` (
  `user_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_email_hash` varchar(255) CHARACTER SET latin1 NOT NULL,
  `user_display` varchar(255) NOT NULL,
  `user_secret` varchar(255) CHARACTER SET latin1 NOT NULL,
  `user_password` varchar(255) CHARACTER SET latin1 NOT NULL,
  `user_level` tinyint(255) NOT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `email` (`user_email_hash`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;