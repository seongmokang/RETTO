-- RETTO 로또 스캐너 데이터베이스 스키마

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    kakao_id BIGINT UNIQUE NOT NULL,
    email VARCHAR(255),
    nickname VARCHAR(100),
    profile_image_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- 사용자 세션 테이블
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 로또 스캔 이력 테이블
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    round INTEGER NOT NULL,
    scanned_numbers INTEGER[] NOT NULL,
    matched_count INTEGER,
    rank INTEGER,
    prize_amount VARCHAR(100),
    has_bonus BOOLEAN DEFAULT FALSE,
    unique_id VARCHAR(10),
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 기존 테이블에 unique_id 컬럼 추가 (이미 존재하는 경우 무시)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'scan_history' AND column_name = 'unique_id'
    ) THEN
        ALTER TABLE scan_history ADD COLUMN unique_id VARCHAR(10);
    END IF;
END $$;

-- 당첨 번호 캐시 테이블
CREATE TABLE IF NOT EXISTS winning_numbers (
    id SERIAL PRIMARY KEY,
    round INTEGER UNIQUE NOT NULL,
    numbers INTEGER[] NOT NULL,
    bonus INTEGER NOT NULL,
    draw_date DATE,
    first_prize_amount BIGINT,
    first_winner_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_users_kakao_id ON users(kakao_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_round ON scan_history(round);
CREATE INDEX IF NOT EXISTS idx_winning_numbers_round ON winning_numbers(round);

-- updated_at 자동 업데이트 함수
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- users 테이블에 트리거 추가
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
