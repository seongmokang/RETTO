# 로또 6/45 QR 스캐너

로또 용지의 QR 코드를 스캔하여 실시간으로 당첨 번호와 비교하는 웹 애플리케이션입니다.

## 주요 기능

- 📱 QR 코드 스캔으로 로또 번호 자동 인식
- 🔍 실시간 당첨 번호 크롤링
- ✅ 자동 당첨 확인 (1등~5등)
- 🎮 여러 게임 동시 확인 가능

## 설치 및 실행

### 1. 필요한 라이브러리 설치

```bash
pip install -r requirements.txt
```

또는 개별 설치:

```bash
pip install Flask flask-cors requests beautifulsoup4
```

### 2. API 서버 실행

```bash
python api_server.py
```

서버가 실행되면 다음과 같이 표시됩니다:
```
============================================================
🎰 로또 당첨 번호 API 서버 시작
============================================================
📍 서버 주소: http://localhost:5000
📍 API 엔드포인트: http://localhost:5000/api/lotto/<회차번호>
📍 예시: http://localhost:5000/api/lotto/1194
📍 상태 확인: http://localhost:5000/api/health
============================================================
```

### 3. 웹 애플리케이션 실행

`index.html` 파일을 브라우저에서 열기:

- **방법 1**: 파일을 더블클릭하여 브라우저에서 열기
- **방법 2**: 간단한 HTTP 서버 실행 (권장)
  ```bash
  # Python 3
  python -m http.server 8080

  # 그 다음 브라우저에서:
  # http://localhost:8080
  ```

## 사용 방법

1. **API 서버 실행 확인**: `python api_server.py`로 서버가 실행 중인지 확인
2. **웹 페이지 열기**: `index.html`을 브라우저에서 열기
3. **QR 코드 스캔**:
   - "카메라 시작" 버튼 클릭
   - 로또 용지 우측 상단의 QR 코드를 카메라에 비추기
   - 자동으로 회차 정보 추출 및 당첨 번호 조회
   - 모든 게임의 당첨 여부를 자동으로 확인

## 파일 구조

```
RETTO/
├── index.html              # 프론트엔드 웹 애플리케이션
├── api_server.py           # Flask API 서버
├── lotto_crawler.py        # 로또 당첨 번호 크롤러
├── requirements.txt        # Python 의존성 패키지
└── README.md              # 프로젝트 설명서
```

## API 엔드포인트

### GET /api/lotto/<회차번호>

특정 회차의 로또 당첨 번호를 조회합니다.

**요청 예시:**
```
GET http://localhost:5000/api/lotto/1194
```

**응답 예시:**
```json
{
  "success": true,
  "data": {
    "round": 1194,
    "numbers": [3, 13, 15, 24, 33, 37],
    "bonus": 2,
    "formatted": "3 13 15 24 33 37 + 2"
  }
}
```

### GET /api/health

서버 상태를 확인합니다.

**응답 예시:**
```json
{
  "status": "healthy",
  "message": "Lotto API Server is running"
}
```

## 기술 스택

### 프론트엔드
- React 18 (via CDN)
- Tailwind CSS
- jsQR (QR 코드 스캔)
- MediaDevices API (카메라 접근)

### 백엔드
- Python 3
- Flask (API 서버)
- Flask-CORS (CORS 지원)
- Requests (HTTP 요청)
- BeautifulSoup4 (웹 크롤링)

## 주의사항

- API 서버가 실행되지 않으면 당첨 번호 조회가 불가능합니다
- 카메라 권한을 허용해야 QR 스캔이 가능합니다
- HTTPS가 아닌 환경에서는 일부 브라우저에서 카메라 접근이 제한될 수 있습니다

## 트러블슈팅

### "서버 연결 실패" 에러
- API 서버가 실행 중인지 확인: `python api_server.py`
- 포트 5000이 사용 가능한지 확인

### 카메라가 작동하지 않는 경우
- 브라우저에서 카메라 권한을 허용했는지 확인
- 다른 앱에서 카메라를 사용 중이지 않은지 확인
- HTTPS 환경에서 실행 권장

### QR 코드 인식이 안 되는 경우
- QR 코드가 카메라 화면 중앙에 오도록 배치
- 조명을 밝게 하여 QR 코드가 선명하게 보이도록 조정
- QR 코드와 카메라 사이의 거리 조절

## 라이선스

개인 및 비상업적 용도로 자유롭게 사용 가능합니다.
