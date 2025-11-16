-- 리또 포인트 시스템 DB 스키마

-- 1. 회원별 리또 포인트 잔액 테이블
CREATE TABLE IF NOT EXISTS retto_points (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 리또 포인트 적립/사용 내역 테이블
CREATE TABLE IF NOT EXISTS retto_point_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,  -- 양수: 적립, 음수: 사용
    transaction_type VARCHAR(50) NOT NULL,  -- 'scan', 'win', 'use', 'admin' 등
    description TEXT,  -- 상세 설명
    metadata JSONB,  -- 추가 정보 (회차, 등수 등)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_retto_points_user_id ON retto_points(user_id);
CREATE INDEX IF NOT EXISTS idx_retto_point_history_user_id ON retto_point_history(user_id);
CREATE INDEX IF NOT EXISTS idx_retto_point_history_created_at ON retto_point_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_retto_point_history_type ON retto_point_history(transaction_type);

-- updated_at 자동 업데이트 트리거
CREATE OR REPLACE FUNCTION update_retto_points_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_retto_points_updated_at
    BEFORE UPDATE ON retto_points
    FOR EACH ROW
    EXECUTE FUNCTION update_retto_points_updated_at();

-- 기존 사용자들에 대한 초기 포인트 레코드 생성
INSERT INTO retto_points (user_id, balance)
SELECT id, 0 FROM users
ON CONFLICT (user_id) DO NOTHING;
