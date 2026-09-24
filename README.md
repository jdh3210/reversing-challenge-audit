# reversing-challenge-audit

직접 제작한 Windows x64 리버싱 CTF 챌린지를 **공격자 관점으로 재감사**하여 설계 결함 5건을 도출하고, 그중 3건을 수정한 v2를 구현·검증한 기록.

핵심 발견은 **무결성 확인을 위해 넣은 MZ 시그니처 검사가 XOR 키 전수조사의 정답 판별기(오라클)로 전락**했다는 점이다. 방어를 추가했는데 난이도가 내려간 사례다.

> 신규 취약점 발견이 아니다. 사용한 기법(Reflective DLL Injection · IAT 후킹 · TLS 콜백 안티디버깅)은 모두 널리 공개된 것이며, 이 레포의 내용은 **그 기법들로 만든 자작 산출물을 스스로 공격해 결함을 찾아내고 고친 과정**이다.

---

## 문서

| 문서 | 용도 |
|---|---|
| **[PORTFOLIO_reversing_challenge.html](PORTFOLIO_reversing_challenge.html)** | 전체 보고서. 스크린샷 포함 단일 HTML (브라우저로 바로 열림) |
| [AUDIT.md](AUDIT.md) | 결함 감사 상세 — REV-01~05 각각의 공격 시나리오·수정·검증 |
| [docs/v2_changes.md](docs/v2_changes.md) | v2 구현 가이드 (변경 위치·주의사항) |
| [src/v1/readme.txt](src/v1/readme.txt) · [src/v2/readme.txt](src/v2/readme.txt) | 빌드 절차 및 빌드 옵션 의존성 |

보고서 본문은 `PORTFOLIO_reversing_challenge.md`이고, HTML은 `build_html.py`로 생성한다(이미지는 파일 안에 내장).

```
python build_html.py
```

---

## 결함 요약

| ID | 결함 | 심각도 | v2 |
|---|---|---|---|
| REV-04 | 복호화 결과의 `MZ` 검사가 XOR 키 전수조사의 정답 판별기로 동작 | 높음 | **수정** |
| REV-01 | 플래그가 `printf` 인자에 평문으로 존재 | 높음 | **수정** |
| REV-02 | 미끼 비밀번호가 가짜 플래그를 출력 (플래그 포맷 노출) | 중간 | **수정** |
| REV-03 | 복호화 키가 코드 무결성에 묶여 있지 않음 | 중간 | 미해결 |
| REV-05 | 복호화 이후 DLL이 RWX 메모리에 평문 상주 | 중간 | 미해결 |

우선순위는 심각도가 아니라 **"의도한 풀이 경로를 얼마나 무의미하게 만드는가"**로 정했다. 상세는 [AUDIT.md](AUDIT.md).

---

## 검증 결과

v1과 v2를 동일 조건에서 실행해 대조했다. 증거 스크린샷은 `img/`에 있다.

| # | 항목 | v1 | v2 |
|---|---|---|---|
| ① | `brute.py` (MZ 오라클 전수조사) | `key found: 0xA1` | `no MZ oracle` |
| ② | 복호화된 DLL에 `strings \| findstr "DH{"` | 플래그 노출 | 출력 없음 |
| ③ | IDA `my_strcmp` 슈도코드 | `printf` 인자에 평문 | 복호화 후 해시 비교만 |
| ④ | `EASY_REVERSING` 입력 | 가짜 플래그 출력 | `Wrong~` |
| ⑤ | **정답 입력 (회귀 검증)** | 플래그 출력 | **플래그 출력 (동일)** |

⑤가 중요하다. **보안을 고쳤는데 문제가 안 풀리면 수정이 아니라 파괴다.**

---

## 구조

```
.
├─ README.md
├─ AUDIT.md                             결함 감사 상세
├─ PORTFOLIO_reversing_challenge.md     보고서 본문 (원본)
├─ PORTFOLIO_reversing_challenge.html   보고서 (생성물, 이미지 내장)
├─ build_html.py                        md -> html 변환기
├─ img/                                 흐름도 + 검증 스크린샷
├─ docs/
│   └─ v2_changes.md
└─ src/
    ├─ v1/   dllmain.cpp · encoder.py · main.c · brute.py · extract.py
    └─ v2/   flag_gen.py · dllmain_v2.cpp · encoder_v2.py · main_v2.c
```

---

## 빌드

v2는 4단계 파이프라인이다. XOR 키가 DLL 파일 크기에서 유도되므로 **앞 단계를 다시 실행하면 뒤 단계를 모두 다시 실행해야 한다.**

```
cd src/v2
python flag_gen.py
cl /LD /EHsc /utf-8 /MD dllmain_v2.cpp /Fe:RealDll.dll
python encoder_v2.py
cl /utf-8 /MD main_v2.c /Fe:challenge_v2.exe
```

### `/MD`는 선택이 아니다

IAT 후킹이 EXE의 import table에서 `strcmp`를 찾는 데 의존한다. `/MT`(정적 CRT)로 빌드하면 `strcmp`가 정적 링크되어 import table에 나타나지 않고, `hook_IAT()`가 대상을 찾지 못해 **후킹이 조용히 실패한다.** 빌드 에러도 런타임 에러도 없이 REV-01·REV-02 수정이 동시에 무력화된다.

`cl.exe`를 커맨드라인에서 옵션 없이 쓰면 기본값이 `/MT`다. Visual Studio 프로젝트 기본값(`/MD`)과 다르다. 빌드 후 확인:

```
dumpbin /imports challenge_v2.exe | findstr /i strcmp
```

---

## 주의

- **`RealDll.dll` / `challenge_*.exe`는 백신에 탐지될 수 있다.** 셸코드 복호화 · 메모리 내 DLL 로드 · IAT 후킹을 수행하므로 기법 특성상 정상적인 탐지다. 악성 동작은 없으며 전체 소스가 이 레포에 있다.
- **정답과 플래그가 소스·문서에 공개되어 있다.** 이 레포의 목적은 완료된 작업의 감사 기록이므로 의도된 것이다. 챌린지로 재사용하려면 `src/v2/flag_gen.py`의 `PASSWORD`·`FLAG`를 교체하고 재빌드해야 한다.
- 로컬에서 바이너리를 완전히 통제하는 CTF 환경을 전제하므로, **완전한 anti-reversing은 성립하지 않는다.** v2의 목표는 절대적 보호가 아니라 의도한 풀이 경로를 무의미하게 만드는 설계 결함의 제거다. 남은 한계는 [AUDIT.md](AUDIT.md)의 "위협 모델과 한계"에 명시했다.
