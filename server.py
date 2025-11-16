#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RETTO 로또 스캐너 통합 서버
로또 API, 카카오 인증, 사용자 관리, 정적 파일 서빙을 모두 제공합니다.
"""

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from lotto_crawler import get_lotto_numbers
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
app = Flask(__name__, static_folder='.')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# CORS 설정
CORS(app, supports_credentials=True)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 카카오 API 설정
KAKAO_REST_API_KEY = os.getenv('KAKAO_REST_API_KEY')
KAKAO_REDIRECT_URI = os.getenv('KAKAO_REDIRECT_URI')
KAKAO_AUTH_URL = 'https://kauth.kakao.com/oauth/authorize'
KAKAO_TOKEN_URL = 'https://kauth.kakao.com/oauth/token'
KAKAO_USER_INFO_URL = 'https://kapi.kakao.com/v2/user/me'


# ==================== 데이터베이스 연결 ====================

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

        # 한국 시간대 설정
        cur = conn.cursor()
        cur.execute("SET TIMEZONE='Asia/Seoul'")
        conn.commit()
        cur.close()

        return conn
    except Exception as e:
        logger.error(f"DB 연결 실패: {str(e)}")
        return None


# ==================== 정적 파일 서빙 ====================

@app.route('/')
def serve_index():
    """메인 페이지"""
    return send_from_directory('.', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """정적 파일 서빙"""
    return send_from_directory('.', path)


# ==================== 로또 API 엔드포인트 ====================

@app.route('/api/lotto/<int:draw_no>', methods=['GET'])
def get_lotto_winning_numbers(draw_no):
    """
    특정 회차의 로또 당첨 번호를 조회합니다.
    """
    logger.info(f"로또 {draw_no}회차 당첨 번호 조회 요청")

    # 회차 번호 유효성 검증
    if draw_no < 1 or draw_no > 9999:
        return jsonify({
            'success': False,
            'error': '유효하지 않은 회차 번호입니다.'
        }), 400

    try:
        # 당첨 번호 크롤링
        result = get_lotto_numbers(draw_no)

        if result is None:
            logger.warning(f"{draw_no}회차 당첨 번호를 찾을 수 없음")
            return jsonify({
                'success': False,
                'error': f'{draw_no}회차의 당첨 번호를 찾을 수 없습니다.'
            }), 404

        logger.info(f"{draw_no}회차 당첨 번호 조회 성공: {result['formatted']}")

        # 성공 응답
        response_data = {
            'round': result['draw_no'],
            'numbers': result['main_numbers'],
            'bonus': result['bonus_number'],
            'formatted': result['formatted']
        }

        # 추첨일 정보가 있으면 포함
        if 'draw_date' in result:
            response_data['date'] = result['draw_date']

        return jsonify({
            'success': True,
            'data': response_data
        }), 200

    except Exception as e:
        logger.error(f"서버 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '서버 오류가 발생했습니다.'
        }), 500


# ==================== 카카오 로그인 엔드포인트 ====================

@app.route('/api/auth/kakao/login', methods=['GET'])
def kakao_login():
    """카카오 로그인 시작 - 카카오 인증 페이지로 리다이렉트할 URL 반환"""
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
    """카카오 로그인 콜백 - 인증 코드를 받아서 액세스 토큰 발급 및 사용자 정보 저장"""
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
    """로그아웃 - 세션 삭제"""
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
    """현재 로그인한 사용자 정보 조회"""
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
    """스캔 이력 저장 (로그인 선택사항)"""
    session_token = request.headers.get('Authorization')

    # Bearer 토큰 형식 처리
    if session_token and session_token.startswith('Bearer '):
        session_token = session_token[7:]

    data = request.json
    round_num = data.get('round')
    scanned_numbers = data.get('numbers')
    matched_count = data.get('matched_count')
    rank = data.get('rank')
    prize_amount = data.get('prize_amount')
    has_bonus = data.get('has_bonus', False)
    unique_id = data.get('unique_id')

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
        user_id = None

        # 세션 토큰이 있으면 사용자 확인 (로그인 상태)
        if session_token:
            cur.execute('''
                SELECT user_id FROM user_sessions
                WHERE session_token = %s AND expires_at > %s
            ''', (session_token, datetime.now()))

            session_data = cur.fetchone()

            if session_data:
                user_id = session_data['user_id']
                logger.info(f"로그인 사용자의 스캔 이력 저장: user_id={user_id}")
            else:
                logger.warning("유효하지 않은 세션 토큰, 비로그인 스캔으로 처리")
        else:
            logger.info("비로그인 사용자의 스캔 이력 저장")

        # 로그인 사용자인 경우, 동일한 로또 번호로 이미 스캔한 이력이 있는지 확인
        if user_id:
            # 번호 배열을 정렬하여 비교 (순서 무관)
            sorted_numbers = sorted(scanned_numbers)

            cur.execute('''
                SELECT id, scanned_numbers
                FROM scan_history
                WHERE user_id = %s AND round = %s
            ''', (user_id, round_num))

            existing_scans = cur.fetchall()

            # 동일한 번호 조합이 있는지 확인
            duplicate_id = None
            for scan in existing_scans:
                if sorted(scan['scanned_numbers']) == sorted_numbers:
                    duplicate_id = scan['id']
                    break

            if duplicate_id:
                # 중복된 스캔이 있으면 scanned_at만 업데이트
                cur.execute('''
                    UPDATE scan_history
                    SET scanned_at = CURRENT_TIMESTAMP,
                        matched_count = %s,
                        rank = %s,
                        prize_amount = %s,
                        has_bonus = %s
                    WHERE id = %s
                    RETURNING id, point_yn
                ''', (matched_count, rank, prize_amount, has_bonus, duplicate_id))

                result = cur.fetchone()
                history_id = result['id']
                point_yn = result['point_yn']
                logger.info(f"중복 스캔 감지, 기존 이력 업데이트: history_id={history_id}, point_yn={point_yn}")

                conn.commit()
                cur.close()
                conn.close()

                return jsonify({
                    'success': True,
                    'data': {
                        'history_id': history_id,
                        'user_id': user_id,
                        'is_duplicate': True,
                        'point_yn': point_yn
                    }
                }), 200

        # 스캔 이력 저장 (user_id는 로그인 상태에서만 저장)
        cur.execute('''
            INSERT INTO scan_history
            (user_id, round, scanned_numbers, matched_count, rank, prize_amount, has_bonus, unique_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, point_yn
        ''', (user_id, round_num, scanned_numbers, matched_count, rank, prize_amount, has_bonus, unique_id))

        result = cur.fetchone()
        history_id = result['id']
        point_yn = result['point_yn']

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'history_id': history_id,
                'user_id': user_id,  # 로그인 상태 확인용
                'is_duplicate': False,
                'point_yn': point_yn
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
    """사용자의 스캔 이력 조회"""
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
            SELECT id, round, scanned_numbers, matched_count, rank, prize_amount, has_bonus, scanned_at, point_yn
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
                'scanned_at': h['scanned_at'].isoformat() if h['scanned_at'] else None,
                'point_yn': h['point_yn']
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


# ==================== 리또 포인트 관리 ====================

@app.route('/api/retto/points/claim', methods=['POST'])
def claim_retto_points():
    """광고 시청 후 리또 포인트 적립"""
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '인증이 필요합니다.'
        }), 401

    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    data = request.json
    history_id = data.get('history_id')

    if not history_id:
        return jsonify({
            'success': False,
            'error': 'history_id가 필요합니다.'
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

        # 스캔 이력 조회 및 포인트 수령 여부 확인
        cur.execute('''
            SELECT round, scanned_numbers, matched_count, rank, unique_id, point_yn
            FROM scan_history
            WHERE id = %s AND user_id = %s
        ''', (history_id, user_id))

        scan_data = cur.fetchone()

        if not scan_data:
            return jsonify({
                'success': False,
                'error': '스캔 이력을 찾을 수 없습니다.'
            }), 404

        # 이미 포인트를 받았는지 확인 (point_yn 기준)
        if scan_data['point_yn']:
            return jsonify({
                'success': False,
                'error': '이미 포인트를 받은 스캔입니다.'
            }), 400

        # 포인트 계산 (스캔 기본 1점)
        points_earned = 1
        point_description = f"{scan_data['round']}회 로또 스캔"
        transaction_type = 'scan'

        # 포인트 잔액 업데이트 (없으면 생성)
        cur.execute('''
            INSERT INTO retto_points (user_id, balance)
            VALUES (%s, %s)
            ON CONFLICT (user_id)
            DO UPDATE SET balance = retto_points.balance + %s
        ''', (user_id, points_earned, points_earned))

        # 포인트 적립 내역 저장
        import json
        metadata = {
            'round': scan_data['round'],
            'rank': scan_data['rank'],
            'matched_count': scan_data['matched_count'],
            'unique_id': scan_data['unique_id'],
            'history_id': history_id
        }

        cur.execute('''
            INSERT INTO retto_point_history
            (user_id, amount, transaction_type, description, metadata)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        ''', (user_id, points_earned, transaction_type, point_description, json.dumps(metadata)))

        point_history_id = cur.fetchone()['id']

        # scan_history의 point_yn을 TRUE로 업데이트
        cur.execute('''
            UPDATE scan_history
            SET point_yn = TRUE
            WHERE id = %s
        ''', (history_id,))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'points_earned': points_earned,
                'point_history_id': point_history_id
            }
        }), 200

    except Exception as e:
        logger.error(f"리또 포인트 적립 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '리또 포인트 적립 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/retto/points', methods=['GET'])
def get_retto_points():
    """사용자의 리또 포인트 잔액 조회"""
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

        # 포인트 잔액 조회
        cur.execute('''
            SELECT balance, updated_at
            FROM retto_points
            WHERE user_id = %s
        ''', (user_id,))

        points_data = cur.fetchone()

        if not points_data:
            # 포인트 레코드가 없으면 생성
            cur.execute('''
                INSERT INTO retto_points (user_id, balance)
                VALUES (%s, 0)
                RETURNING balance, updated_at
            ''', (user_id,))
            points_data = cur.fetchone()
            conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'balance': points_data['balance'],
                'updated_at': points_data['updated_at'].isoformat() if points_data['updated_at'] else None
            }
        }), 200

    except Exception as e:
        logger.error(f"리또 포인트 조회 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '리또 포인트 조회 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/retto/points/history', methods=['GET'])
def get_retto_point_history():
    """사용자의 리또 포인트 적립/사용 내역 조회"""
    session_token = request.headers.get('Authorization')

    if not session_token:
        return jsonify({
            'success': False,
            'error': '인증이 필요합니다.'
        }), 401

    if session_token.startswith('Bearer '):
        session_token = session_token[7:]

    # 쿼리 파라미터
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    transaction_type = request.args.get('type')  # 'scan', 'win', 'use', 'admin'

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

        # 포인트 내역 조회
        if transaction_type:
            cur.execute('''
                SELECT id, amount, transaction_type, description, metadata, created_at
                FROM retto_point_history
                WHERE user_id = %s AND transaction_type = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            ''', (user_id, transaction_type, limit, offset))
        else:
            cur.execute('''
                SELECT id, amount, transaction_type, description, metadata, created_at
                FROM retto_point_history
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            ''', (user_id, limit, offset))

        history = cur.fetchall()

        # 전체 개수 조회
        if transaction_type:
            cur.execute('''
                SELECT COUNT(*) as total
                FROM retto_point_history
                WHERE user_id = %s AND transaction_type = %s
            ''', (user_id, transaction_type))
        else:
            cur.execute('''
                SELECT COUNT(*) as total
                FROM retto_point_history
                WHERE user_id = %s
            ''', (user_id,))

        total_count = cur.fetchone()['total']

        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'history': [{
                    'id': h['id'],
                    'amount': h['amount'],
                    'transaction_type': h['transaction_type'],
                    'description': h['description'],
                    'metadata': h['metadata'],
                    'created_at': h['created_at'].isoformat() if h['created_at'] else None
                } for h in history],
                'pagination': {
                    'total': total_count,
                    'limit': limit,
                    'offset': offset
                }
            }
        }), 200

    except Exception as e:
        logger.error(f"리또 포인트 내역 조회 중 오류: {str(e)}")
        return jsonify({
            'success': False,
            'error': '리또 포인트 내역 조회 중 오류가 발생했습니다.'
        }), 500
    finally:
        if conn:
            conn.close()


# ==================== 헬스체크 ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """서버 상태 확인"""
    return jsonify({
        'status': 'healthy',
        'message': 'RETTO Server is running'
    }), 200


# ==================== 에러 핸들러 ====================

@app.errorhandler(404)
def not_found(error):
    """404 에러 핸들러"""
    return jsonify({
        'success': False,
        'error': '요청한 리소스를 찾을 수 없습니다.'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """500 에러 핸들러"""
    return jsonify({
        'success': False,
        'error': '내부 서버 오류가 발생했습니다.'
    }), 500


if __name__ == '__main__':
    # 환경에 따른 설정
    port = int(os.getenv('PORT', 5002))
    debug = os.getenv('FLASK_ENV') != 'production'

    print("=" * 60)
    print("🎰 RETTO 로또 스캐너 서버 시작")
    print("=" * 60)
    print(f"📍 서버 주소: http://localhost:{port}")
    print(f"📍 메인 페이지: http://localhost:{port}/")
    print(f"📍 로또 API: http://localhost:{port}/api/lotto/<회차번호>")
    print(f"📍 카카오 로그인: http://localhost:{port}/api/auth/kakao/login")
    print(f"📍 상태 확인: http://localhost:{port}/api/health")
    print(f"📍 디버그 모드: {'ON' if debug else 'OFF'}")
    print("=" * 60)
    print("⚠️  종료하려면 Ctrl+C를 누르세요")
    print("=" * 60 + "\n")

    # 서버 실행
    app.run(debug=debug, host='0.0.0.0', port=port)
