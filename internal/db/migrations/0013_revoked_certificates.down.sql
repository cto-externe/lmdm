ALTER TABLE devices DROP COLUMN IF EXISTS current_cert_serial;
DROP TABLE IF EXISTS revoked_certificates;
