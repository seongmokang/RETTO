#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
로또 6/45 당첨 번호 조회
동행복권 공식 API를 사용하여 회차별 당첨 번호를 조회합니다.
"""

import requests


def get_lotto_numbers(draw_no):
    """
    특정 회차의 로또 당첨 번호를 조회합니다.

    Args:
        draw_no (int): 로또 회차 번호

    Returns:
        dict: 당첨 번호 정보 (main_numbers, bonus_number, draw_date)
        None: 조회 실패 시
    """
    # 동행복권 공식 API URL
    url = f"https://www.dhlottery.co.kr/common.do?method=getLottoNumber&drwNo={draw_no}"

    try:
        print(f"[API 조회] {draw_no}회차 URL: {url}")

        # API 요청
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # HTTP 에러 체크

        print(f"[API 조회] HTTP 상태 코드: {response.status_code}")

        # JSON 응답 파싱
        data = response.json()

        print(f"[API 조회] 응답 데이터: {data}")

        # API 응답 확인
        if data.get('returnValue') != 'success':
            print(f"[API 조회] 경고: {draw_no}회차의 당첨 번호를 찾을 수 없습니다.")
            return None

        # 당첨 번호 추출
        main_numbers = [
            data.get('drwtNo1'),
            data.get('drwtNo2'),
            data.get('drwtNo3'),
            data.get('drwtNo4'),
            data.get('drwtNo5'),
            data.get('drwtNo6')
        ]

        # None 값 체크
        if None in main_numbers:
            print(f"[API 조회] 경고: 일부 당첨 번호가 누락되었습니다.")
            return None

        bonus_number = data.get('bnusNo')
        if bonus_number is None:
            print(f"[API 조회] 경고: 보너스 번호가 누락되었습니다.")
            return None

        # 추첨일 정보
        draw_date = data.get('drwNoDate')

        result = {
            'draw_no': draw_no,
            'main_numbers': main_numbers,
            'bonus_number': bonus_number,
            'formatted': f"{' '.join(map(str, main_numbers))} + {bonus_number}"
        }

        if draw_date:
            result['draw_date'] = draw_date

        print(f"[API 조회] ✓ {draw_no}회차 조회 성공: {result['formatted']}")
        return result

    except requests.exceptions.Timeout:
        print(f"[API 조회] 타임아웃 오류: 서버 응답 시간 초과")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[API 조회] 연결 오류: 인터넷 연결을 확인하세요")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[API 조회] HTTP 오류: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[API 조회] 네트워크 오류: {e}")
        return None
    except ValueError as e:
        print(f"[API 조회] JSON 파싱 오류: {e}")
        return None
    except Exception as e:
        print(f"[API 조회] 예외 발생: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """메인 실행 함수"""
    # 예제: 1194회차 당첨 번호 크롤링
    draw_no = 1194

    print(f"로또 {draw_no}회차 당첨 번호 크롤링 중...")
    result = get_lotto_numbers(draw_no)

    print(result)

    # if result:
    #     print(f"\n✓ {result['draw_no']}회차 당첨 번호:")
    #     print(f"  메인 번호: {result['main_numbers']}")
    #     print(f"  보너스 번호: {result['bonus_number']}")
    #     print(f"  표시: {result['formatted']}")
    # else:
    #     print("크롤링 실패")

    # # 여러 회차 크롤링 예제
    # print("\n" + "="*50)
    # print("최근 3개 회차 크롤링 예제:")
    # for i in range(3):
    #     draw = 1194 - i
    #     result = get_lotto_numbers(draw)
    #     if result:
    #         print(f"{result['draw_no']}회: {result['formatted']}")


if __name__ == "__main__":
    main()
