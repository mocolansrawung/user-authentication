DROP TABLE IF EXISTS `user`;

CREATE TABLE `user` (
  `id` VARCHAR(55) PRIMARY KEY NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `username` VARCHAR(255) UNIQUE NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) UNIQUE NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by` VARCHAR(55) NOT NULL,
  `updated_at` TIMESTAMP NULL DEFAULT NULL,
  `updated_by` VARCHAR(55) NULL DEFAULT NULL,
  `deleted_at` TIMESTAMP NULL DEFAULT NULL,
  `deleted_by` VARCHAR(55) NULL DEFAULT NULL
);

INSERT INTO `user` (`id`, `username`, `password`, `email`, `created_by`)
VALUES 
('550e8400-e29b-41d4-a716-446655440000', 'john', 'john123', 'john@example.com', 'admin');
