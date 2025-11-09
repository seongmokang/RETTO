#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
로또 당첨 번호 API 서버
Flask를 사용하여 로또 당첨 번호 조회 API를 제공합니다.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from lotto_crawler import get_lotto_numbers
import logging

# Flask 앱 생성
app = Flask(__name__)

# CORS 설정 (모든 도메인에서 접근 가능)
CORS(app)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/api/lotto/<int:draw_no>', methods=['GET'])
def get_lotto_winning_numbers(draw_no):
    """
    특정 회차의 로또 당첨 번호를 조회합니다.

    Args:
        draw_no (int): 로또 회차 번호

    Returns:
        JSON: 당첨 번호 정보 또는 에러 메시지
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


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    서버 상태 확인 엔드포인트
    """
    return jsonify({
        'status': 'healthy',
        'message': 'Lotto API Server is running'
    }), 200


@app.route('/', methods=['GET'])
def index():
    """
    API 정보 페이지
    """
    return jsonify({
        'name': 'Lotto Winning Numbers API',
        'version': '1.0.0',
        'endpoints': {
            'GET /api/lotto/<draw_no>': '특정 회차의 당첨 번호 조회',
            'GET /api/health': '서버 상태 확인'
        },
        'example': {
            'url': '/api/lotto/1194',
            'response': {
                'success': True,
                'data': {
                    'round': 1194,
                    'numbers': [3, 13, 15, 24, 33, 37],
                    'bonus': 2,
                    'formatted': '3 13 15 24 33 37 + 2'
                }
            }
        }
    }), 200


@app.errorhandler(404)
def not_found(error):
    """404 에러 핸들러"""
    return jsonify({
        'success': False,
        'error': '요청한 엔드포인트를 찾을 수 없습니다.'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """500 에러 핸들러"""
    return jsonify({
        'success': False,
        'error': '내부 서버 오류가 발생했습니다.'
    }), 500


if __name__ == '__main__':
    print("=" * 60)
    print("🎰 로또 당첨 번호 API 서버 시작")
    print("=" * 60)
    print(f"📍 서버 주소: http://localhost:5002")
    print(f"📍 API 엔드포인트: http://localhost:5002/api/lotto/<회차번호>")
    print(f"📍 예시: http://localhost:5002/api/lotto/1194")
    print(f"📍 상태 확인: http://localhost:5002/api/health")
    print("=" * 60)
    print("⚠️  종료하려면 Ctrl+C를 누르세요")
    print("=" * 60 + "\n")

    # 서버 실행 (디버그 모드, 포트 5002)
    app.run(debug=True, host='0.0.0.0', port=5002)
