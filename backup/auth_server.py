#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RETTO 로또 스캐너 인증 서버
카카오 로그인, 사용자 관리, 세션 관리 기능을 제공합니다.
"""

from flask import Flask, jsonify, request, session
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import os
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
import logging

# 환경 변수 로드
load_dotenv()

# Flask 앱 생성
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# CORS 설정
CORS(app, supports_credentials=True)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 카카오 API 설정
KAKAO_REST_API_KEY = os.getenv('KAKAO_REST_API_KEY')
KAKAO_REDIRECT_URI = os.getenv('KAKAO_REDIRECT_URI', 'http://localhost:5002/api/auth/kakao/callback')
KAKAO_AUTH_URL = 'https://kauth.kakao.com/oauth/authorize'
KAKAO_TOKEN_URL = 'https://kauth.kakao.com/oauth/token'
KAKAO_USER_INFO_URL = 'https://kapi.kakao.com/v2/user/me'

# PostgreSQL 연결 설정
def get_db_connection():
    """PostgreSQL 데이터베이스 연결"""
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            database=os.getenv('DB_NAME', 'retto'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD', ''),
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        logger.error(f"DB 연결 실패: {str(e)}")
        return None


# ==================== 카카오 로그인 엔드포인트 ====================

@app.route('/api/auth/kakao/login', methods=['GET'])
def kakao_login():
    """
    카카오 로그인 시작 - 카카오 인증 페이지로 리다이렉트할 URL 반환
    """
    if not KAKAO_REST_API_KEY:
        return jsonify({
            'success': False,
            'error': '카카오 API 키가 설정되지 않았습니다.'
        }), 500

    # 카카오 로그인 URL 생성
    kakao_auth_url = f"{KAKAO_AUTH_URL}?client_id={KAKAO_REST_API_KEY}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code"

    return jsonify({
        'success': True,
        'auth_url': kakao_auth_url
    }), 200


@app.route('/api/auth/kakao/callback', methods=['GET'])
def kakao_callback():
    """
    카카오 로그인 콜백 - 인증 코드를 받아서 액세스 토큰 발급 및 사용자 정보 저장
    """
    code = request.args.get('code')

    if not code:
        return jsonify({
            'success': False,
            'error': '인증 코드가 없습니다.'
        }), 400

    try:
        # 1. 액세스 토큰 발급
        token_response = requests.post(
            KAKAO_TOKEN_URL,
            data={
                'grant_type': 'authorization_code',
                'client_id': KAKAO_REST_API_KEY,
                'redirect_uri': KAKAO_REDIRECT_URI,
                'code': code
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        token_data = token_response.json()

        if 'error' in token_data:
            logger.error(f"토큰 발급 실패: {token_data}")
            return jsonify({
                'success': False,
                'error': '토큰 발급에 실패했습니다.'
            }), 400

        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in', 21600)  # 기본 6시간

        # 2. 사용자 정보 조회
        user_response = requests.get(
            KAKAO_USER_INFO_URL,
            headers={'Authorization': f'Bearer {access_token}'}
        )

        user_data = user_response.json()

        if 'id' not in user_data:
            logger.error(f"사용자 정보 조회 실패: {user_data}")
            return jsonify({
                'success': False,
                'error': '사용자 정보를 가져올 수 없습니다.'
            }), 400

        # 3. DB에 사용자 정보 저장 또는 업데이트
        kakao_id = user_data['id']
        kakao_account = user_data.get('kakao_account', {})
        profile = kakao_account.get('profile', {})

        email = kakao_account.get('email')
        nickname = profile.get('nickname')
        profile_image_url = profile.get('profile_image_url')

        conn = get_db_connection()
        if not conn:
            return jsonify({
                'success': False,
                'error': 'DB 연결에 실패했습니다.'
            }), 500

        try:
            cur = conn.cursor()

            # 사용자 존재 여부 확인
            cur.execute('SELECT id FROM users WHERE kakao_id = %s', (kakao_id,))
            user = cur.fetchone()

            if user:
                # 기존 사용자 업데이트
                cur.execute('''
                    UPDATE users
                    SET email = %s, nickname = %s, profile_image_url = %s, last_login = %s
                    WHERE kakao_id = %s
                    RETURNING id
                ''', (email, nickname, profile_image_url, datetime.now(), kakao_id))
                user_id = cur.fetchone()['id']
                logger.info(f"기존 사용자 로그인: user_id={user_id}, kakao_id={kakao_id}")
            else:
                # 신규 사용자 생성
                cur.execute('''
                    INSERT INTO users (kakao_id, email, nickname, profile_image_url, last_login)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                ''', (kakao_id, email, nickname, profile_image_url, datetime.now()))
                user_id = cur.fetchone()['id']
                logger.info(f"신규 사용자 가입: user_id={user_id}, kakao_id={kakao_id}")

            # 세션 토큰 생성
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(seconds=expires_in)

            # 세션 저장
            cur.execute('''
                INSERT INTO user_sessions (user_id, session_token, access_token, refresh_token, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, session_token, access_token, refresh_token, expires_at))

            conn.commit()
            cur.close()
            conn.close()

            # 성공 응답
            return jsonify({
                'success': True,
                'data': {
                    'session_token': session_token,
                    'user': {
                        'id': user_id,
                        'kakao_id': kakao_id,
                        'email': email,
                        'nickname': nickname,
                        'profile_image_url': profile_image_url
                    }
                }
            }), 200

        except Exception as e:
            conn.rollback()
            logger.error(f"DB 작업 중 오류: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'DB 작업 중 오류가 발생했습니다.'
            }), 500
        finally:
            if conn:
                conn.close()

    except Exception as e:
        logger.error(f"카카오 로그인 처리 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '로그인 처리 중 오류가 발생했습니다.'
        }), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """
    로그아웃 - 세션 삭제
    """
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '세션 토큰이 없습니다.'
        }), 401

    # Bearer 토큰 형식 처리
    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    conn = get_db_connection()
    if not conn:
        return jsonify({
            'success': False,
            'error': 'DB 연결에 실패했습니다.'
        }), 500

    try:
        cur = conn.cursor()
        cur.execute('DELETE FROM user_sessions WHERE session_token = %s', (session_token,))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': '로그아웃되었습니다.'
        }), 200

    except Exception as e:
        logger.error(f"로그아웃 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '로그아웃 처리 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """
    현재 로그인한 사용자 정보 조회
    """
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '인증이 필요합니다.'
        }), 401

    # Bearer 토큰 형식 처리
    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    conn = get_db_connection()
    if not conn:
        return jsonify({
            'success': False,
            'error': 'DB 연결에 실패했습니다.'
        }), 500

    try:
        cur = conn.cursor()

        # 세션 및 사용자 정보 조회
        cur.execute('''
            SELECT u.id, u.kakao_id, u.email, u.nickname, u.profile_image_url, u.created_at, u.last_login
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s AND s.expires_at > %s
        ''', (session_token, datetime.now()))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({
                'success': False,
                'error': '유효하지 않은 세션입니다.'
            }), 401

        return jsonify({
            'success': True,
            'data': {
                'id': user['id'],
                'kakao_id': user['kakao_id'],
                'email': user['email'],
                'nickname': user['nickname'],
                'profile_image_url': user['profile_image_url'],
                'created_at': user['created_at'].isoformat() if user['created_at'] else None,
                'last_login': user['last_login'].isoformat() if user['last_login'] else None
            }
        }), 200

    except Exception as e:
        logger.error(f"사용자 정보 조회 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '사용자 정보 조회 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


# ==================== 스캔 이력 관리 ====================

@app.route('/api/scan/history', methods=['POST'])
def save_scan_history():
    """
    스캔 이력 저장
    """
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '인증이 필요합니다.'
        }), 401

    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    data = request.json
    round_num = data.get('round')
    scanned_numbers = data.get('numbers')
    matched_count = data.get('matched_count')
    rank = data.get('rank')
    prize_amount = data.get('prize_amount')
    has_bonus = data.get('has_bonus', False)

    if not round_num or not scanned_numbers:
        return jsonify({
            'success': False,
            'error': '필수 정보가 누락되었습니다.'
        }), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({
            'success': False,
            'error': 'DB 연결에 실패했습니다.'
        }), 500

    try:
        cur = conn.cursor()

        # 사용자 확인
        cur.execute('''
            SELECT user_id FROM user_sessions
            WHERE session_token = %s AND expires_at > %s
        ''', (session_token, datetime.now()))

        session_data = cur.fetchone()

        if not session_data:
            return jsonify({
                'success': False,
                'error': '유효하지 않은 세션입니다.'
            }), 401

        user_id = session_data['user_id']

        # 스캔 이력 저장
        cur.execute('''
            INSERT INTO scan_history
            (user_id, round, scanned_numbers, matched_count, rank, prize_amount, has_bonus)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (user_id, round_num, scanned_numbers, matched_count, rank, prize_amount, has_bonus))

        history_id = cur.fetchone()['id']

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'history_id': history_id
            }
        }), 200

    except Exception as e:
        logger.error(f"스캔 이력 저장 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '스캔 이력 저장 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/scan/history', methods=['GET'])
def get_scan_history():
    """
    사용자의 스캔 이력 조회
    """
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '인증이 필요합니다.'
        }), 401

    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    conn = get_db_connection()
    if not conn:
        return jsonify({
            'success': False,
            'error': 'DB 연결에 실패했습니다.'
        }), 500

    try:
        cur = conn.cursor()

        # 사용자 확인
        cur.execute('''
            SELECT user_id FROM user_sessions
            WHERE session_token = %s AND expires_at > %s
        ''', (session_token, datetime.now()))

        session_data = cur.fetchone()

        if not session_data:
            return jsonify({
                'success': False,
                'error': '유효하지 않은 세션입니다.'
            }), 401

        user_id = session_data['user_id']

        # 스캔 이력 조회
        cur.execute('''
            SELECT id, round, scanned_numbers, matched_count, rank, prize_amount, has_bonus, scanned_at
            FROM scan_history
            WHERE user_id = %s
            ORDER BY scanned_at DESC
            LIMIT 50
        ''', (user_id,))

        history = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': [{
                'id': h['id'],
                'round': h['round'],
                'numbers': h['scanned_numbers'],
                'matched_count': h['matched_count'],
                'rank': h['rank'],
                'prize_amount': h['prize_amount'],
                'has_bonus': h['has_bonus'],
                'scanned_at': h['scanned_at'].isoformat() if h['scanned_at'] else None
            } for h in history]
        }), 200

    except Exception as e:
        logger.error(f"스캔 이력 조회 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '스캔 이력 조회 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


# ==================== 헬스체크 및 기타 ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """서버 상태 확인"""
    return jsonify({
        'status': 'healthy',
        'message': 'RETTO Auth Server is running'
    }), 200


@app.route('/', methods=['GET'])
def index():
    """API 정보 페이지"""
    return jsonify({
        'name': 'RETTO Authentication & User Management API',
        'version': '1.0.0',
        'endpoints': {
            'GET /api/auth/kakao/login': '카카오 로그인 시작',
            'GET /api/auth/kakao/callback': '카카오 로그인 콜백',
            'POST /api/auth/logout': '로그아웃',
            'GET /api/auth/me': '현재 사용자 정보 조회',
            'POST /api/scan/history': '스캔 이력 저장',
            'GET /api/scan/history': '스캔 이력 조회',
            'GET /api/health': '서버 상태 확인'
        }
    }), 200


if __name__ == '__main__':
    print("=" * 60)
    print("🔐 RETTO 인증 서버 시작")
    print("=" * 60)
    print(f"📍 서버 주소: http://localhost:5003")
    print(f"📍 카카오 로그인: http://localhost:5003/api/auth/kakao/login")
    print(f"📍 상태 확인: http://localhost:5003/api/health")
    print("=" * 60)
    print("⚠️  종료하려면 Ctrl+C를 누르세요")
    print("=" * 60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5003)
