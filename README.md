# T08 · 소개 페이지에 패스키 달기

공개 결과물: https://aleph-passkey-intro.rlatmdgus4141.chatgpt.site/

T01 본문을 보존하고 가상 메모 공간을 WebAuthn 패스키로 잠갔습니다. [인증 설명서](t08/AUTH_IMPLEMENTATION.md), [요청·응답 근거](t08/service-results.json). 2026-10-06 실제 브라우저에서 두 계정·두 키, 양방향 거절, 질문 재사용·서명 변조·키 삭제·등록 취소를 확인했습니다. 실제 원본은 제출 확인 ZIP에 보존하며 공개 설명서에는 검사 범위와 결과를 구분했습니다.

## 실행

Node 24와 pnpm 11.25.0. `pnpm install --frozen-lockfile`, `node tests/t08.test.mjs`, `pnpm exec tsc --noEmit`, `pnpm run build`. D1 마이그레이션: `drizzle/0000_abnormal_thunderbird.sql`. Sites가 배포할 때 적용합니다.

RP ID·Origin은 `lib/passkeys.ts`의 배포 주소로 고정했습니다. 도메인을 바꾸면 이 값도 바꾸고 새 키를 등록해야 합니다. root `index.html`은 기존 GitHub Pages 소개 보존용이며 Sites 확장 페이지는 `app/route.ts`입니다.

실제 자료·쿠키·비밀값을 저장소에 올리지 마세요. 시험의 P-256 개인키는 메모리에만 만들며 파일·서버 요청에 넣지 않습니다.
