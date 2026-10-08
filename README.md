# 룰렛

폴더별로 룰렛을 만들고, 언제 무엇이 당첨됐는지 기록·통계로 보는 웹앱입니다.
라이브: https://roulette.yndl.dev

## 기능
- **폴더**: '점심', '산책'처럼 용도별 룰렛을 여러 개 만들고 이름 변경·삭제·순서 변경(데스크톱 드래그)
- **룰렛**: 항목 2–50개(한 줄에 하나, 쉼표 가능), `crypto.getRandomValues` 기반 균등 추첨, 포인터 위치와 기록이 항상 일치, '당첨 항목 제외' 옵션
- **기록**: 폴더별 당첨 시각(한국 시간)·항목·당시 항목 수, 날짜별 묶음, 기록 지우기
- **통계**: 총 회수, 항목별 횟수/비율 막대그래프, 최다·최소, 연속 당첨, 마지막 당첨일
- **계정 (Google 로그인)**: 로그인하면 폴더·항목·기록이 서버에 저장되어 모든 기기에서 동기화. 처음 로그인할 때 이 브라우저의 게스트 데이터를 가져올 수 있음
- **게스트 모드**: 로그인 없이도 사용 가능(브라우저 localStorage). JSON 내보내기/가져오기, 항목 공유 링크
- 다크 모드, `prefers-reduced-motion`, 모바일(iPhone Safari) 대응. 외부 라이브러리·빌드 없음

## 구조
| 파일 | 설명 |
|---|---|
| `index.html` | 프론트엔드 전체 (인라인 CSS/JS). 서버 없이 열면 게스트 모드로만 동작 (GitHub Pages) |
| `server.py` | Python 표준 라이브러리만 사용하는 서버: 정적 파일 + JSON API + Google 로그인 세션 |
| `tests/test_server.py` | 토큰 검증·API·권한 분리 테스트 (`python3 -m unittest discover -s tests`) |
| `config.local.json` | (git 제외) `{"google_client_id": "..."}` |
| `data/roulette.db` | (git 제외) SQLite DB |

## 직접 운영하기
```bash
python3 server.py            # 기본 127.0.0.1:8793
# 환경 변수: ROULETTE_PORT, ROULETTE_HOST, ROULETTE_DATA_DIR, ROULETTE_CONFIG, ROULETTE_GOOGLE_CLIENT_ID
```
Python 3.9+ 만 있으면 되고 추가 패키지는 필요 없습니다. 리버스 프록시/터널(예: Cloudflare Tunnel) 뒤에서 **HTTPS로** 서비스하세요(세션 쿠키가 `Secure`).

## Google 로그인 설정
1. Google Cloud Console → API 및 서비스 → 사용자 인증 정보 → **OAuth 클라이언트 ID 만들기** → 유형 **웹 애플리케이션**
2. **승인된 JavaScript 원본**에 서비스 주소 추가 (예: `https://roulette.yndl.dev`). 리디렉션 URI는 필요 없습니다.
3. 프로젝트 폴더에 `config.local.json` 생성:
   ```json
   {"google_client_id": "1234567890-xxxx.apps.googleusercontent.com"}
   ```
   (또는 환경 변수 `ROULETTE_GOOGLE_CLIENT_ID`). 파일 변경은 재시작 없이 반영됩니다. 클라이언트 보안 비밀(secret)은 필요 없습니다.
4. 설정 전에는 화면에 "구글 로그인 설정 전"이 표시되고 게스트 모드로 동작합니다.

## 보안 메모
- Google ID 토큰은 서버에서 직접 검증합니다: Google JWKS(캐시)로 RS256 서명, `aud`(클라이언트 ID), `iss`, `exp` 확인
- 검증 후 자체 세션 발급: 무작위 토큰을 `__Host-roulette_sid` 쿠키(HttpOnly, Secure, SameSite=Lax, 90일)로 주고 DB에는 SHA-256 해시만 저장. 로그아웃 시 서버에서 삭제
- 변경 요청은 `X-Requested-With: roulette` 헤더 + Origin/Sec-Fetch-Site 검사(CSRF 방어)
- 모든 쿼리는 세션 사용자 기준으로 제한. 입력 제한: 폴더 100개, 항목 50개, 항목 100자, 폴더 이름 40자, 폴더당 기록 3000건, 요청 본문 64KB(가져오기 8MB)
- CSP, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` 헤더. 서버는 `index.html`만 정적으로 제공(다른 파일 노출 없음)
