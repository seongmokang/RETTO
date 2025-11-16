-- scan_history 테이블에 point_yn 컬럼 추가
ALTER TABLE scan_history
ADD COLUMN IF NOT EXISTS point_yn BOOLEAN DEFAULT FALSE;

-- 기존 데이터는 모두 FALSE로 설정 (아직 포인트를 받지 않은 상태)
UPDATE scan_history SET point_yn = FALSE WHERE point_yn IS NULL;

-- 인덱스 추가 (성능 향상)
CREATE INDEX IF NOT EXISTS idx_scan_history_point_yn ON scan_history(point_yn);
