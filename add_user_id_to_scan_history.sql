-- scan_history 테이블에 user_id 컬럼 추가 (NULL 허용으로 비로그인 스캔도 지원)
-- user_id가 이미 존재하는 경우 ALTER를 건너뜁니다
DO $$
BEGIN
    -- user_id 컬럼이 없으면 추가
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name='scan_history' AND column_name='user_id'
    ) THEN
        ALTER TABLE scan_history
        ADD COLUMN user_id INTEGER;

        -- users 테이블과 외래 키 관계 설정 (사용자 삭제 시 스캔 이력도 함께 삭제)
        ALTER TABLE scan_history
        ADD CONSTRAINT fk_scan_history_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

        -- 인덱스 추가 (성능 향상)
        CREATE INDEX idx_scan_history_user_id ON scan_history(user_id);

        RAISE NOTICE 'user_id 컬럼이 scan_history 테이블에 추가되었습니다.';
    ELSE
        -- user_id 컬럼이 이미 있으면 NULL 허용으로 변경
        ALTER TABLE scan_history
        ALTER COLUMN user_id DROP NOT NULL;

        RAISE NOTICE 'user_id 컬럼이 이미 존재합니다. NULL 허용으로 설정되었습니다.';
    END IF;
END $$;

-- 기존 데이터의 user_id가 NULL인 경우 처리 (필요시)
-- UPDATE scan_history SET user_id = NULL WHERE user_id = 0;
