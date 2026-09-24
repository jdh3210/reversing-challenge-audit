# v2 최소안 구현 가이드

대상 결함: **REV-01 / REV-02 / REV-04**
REV-03(`.text` 체크섬 바인딩)과 REV-05(복호화 이후 메모리 상주)는 이번 범위에서 제외하고
한계 및 향후 과제로 명시한다.

작업 전 `src/v1/`을 그대로 보존하고 `src/v2/`에 복사본을 만들어 작업한다.

---

## 변경 요약

| 파일 | 결함 | 변경 내용 |
|---|---|---|
| `flag_gen.py` (신규) | REV-01 | 입력 유도 키로 플래그 암호화, `flag_blob.h` 생성 |
| `dllmain.cpp` | REV-01 | 평문 플래그 제거, 런타임 복호화로 교체 |
| `dllmain.cpp` | REV-02 | 후킹 지점에서 미끼 비교를 실패 처리 |
| `encoder.py` | REV-04 | MZ / PE 시그니처 / DOS 스텁 제거 후 암호화 |
| `main.c` | REV-04 | MZ 검사 코드 삭제 |

### 빌드 순서 변경

```
[v1]  dllmain.cpp -> RealDll.dll -> encoder.py -> shellcode.h -> main.c -> challenge.exe
[v2]  flag_gen.py -> flag_blob.h -> dllmain.cpp -> RealDll.dll -> encoder.py -> shellcode.h -> main.c -> challenge.exe
                    ^^^^^^^^^^^^ 신규 단계
```

---

## 1. `dllmain.cpp` — REV-01, REV-02

### 1-1. include 및 헬퍼 추가

`#include "pch.h"` 아래에 추가한다.

```cpp
#include "flag_blob.h"   // flag_gen.py가 생성

#define FNV64_OFFSET 0xCBF29CE484222325ULL
#define FNV64_PRIME  0x100000001B3ULL

// flag_gen.py의 fnv1a64와 바이트 단위로 동일해야 한다
static unsigned long long fnv1a64(const unsigned char* data, size_t len) {
    unsigned long long h = FNV64_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= FNV64_PRIME;       // unsigned long long이므로 2^64로 자동 랩어라운드
    }
    return h;
}

// flag_gen.py의 keystream과 동일. 8바이트 블록, 리틀엔디안 순서
static void keystream(unsigned long long seed, unsigned char* out, size_t len) {
    unsigned long long h = seed;
    size_t produced = 0;
    while (produced < len) {
        h *= FNV64_PRIME;
        h ^= (h >> 29);
        for (int i = 0; i < 8 && produced < len; i++, produced++) {
            out[produced] = (unsigned char)((h >> (8 * i)) & 0xFF);
        }
    }
}
```

### 1-2. `my_strcmp` 전체 교체

```cpp
int my_strcmp(const char* str1, const char* str2) {
    if (original_strcmp == NULL) {
        original_strcmp = strcmp;
    }

    // ── REV-02 ──────────────────────────────────────────────
    // v1은 main()에서 EASY_REVERSING이 일치하면 가짜 플래그를 출력했다.
    // 후킹 지점에서 이 비교 자체를 실패시켜 미끼 경로를 차단한다.
    // 문자열은 .rdata에 그대로 남겨 단서로는 기능하되, 입력해도 Wrong으로 떨어진다.
    // 이미 설치한 후킹을 두 번째 목적으로 재사용하는 구조다.
    if (original_strcmp(str2, "EASY_REVERSING") == 0) {
        return 1;
    }

    // ── REV-01 ──────────────────────────────────────────────
    // v1은 플래그를 printf 인자에 평문 문자열로 보유했다.
    // v2는 사용자 입력에서 유도한 키스트림으로만 복호화한다.
    // 오답이면 복호화 결과가 쓰레기이고 해시 검증에서 걸러지므로,
    // 플래그가 바이너리에도 메모리에도 존재하지 않는다.
    size_t in_len = 0;
    while (str1[in_len] != '\0') in_len++;

    unsigned long long seed = fnv1a64((const unsigned char*)str1, in_len);

    unsigned char ks[sizeof(enc_flag)];
    unsigned char out[sizeof(enc_flag) + 1] = { 0 };

    keystream(seed, ks, sizeof(enc_flag));
    for (size_t i = 0; i < sizeof(enc_flag); i++) {
        out[i] = enc_flag[i] ^ ks[i];
    }

    // 입력이 아니라 '복호화 결과'를 검증한다.
    // 해시 충돌로 통과하더라도 출력되는 것은 플래그가 아니므로
    // 공격자에게 유효한 정보를 주지 않는다.
    if (fnv1a64(out, sizeof(enc_flag)) == FLAG_HASH) {
        printf("You've got it! %s\n", (char*)out);
        printf("Program will exit in 10 seconds~\n");
        Sleep(10000);
        ExitProcess(0);
    }

    // 실패 경로에서는 복호화 버퍼를 즉시 파기한다.
    // SecureZeroMemory는 컴파일러 최적화로 제거되지 않는다.
    SecureZeroMemory(out, sizeof(out));
    SecureZeroMemory(ks, sizeof(ks));

    return original_strcmp(str1, str2);
}
```

**삭제되는 것**: `encrypted_flag` 배열, `0xBE` XOR 루프, `real_flag` 버퍼,
그리고 `"You've got it! Real Flag is DH{r3fl3ct1v3_m4st3r}"` 평문 문자열.

> v1에서 정답 비밀번호는 XOR로 난독화하고 플래그는 평문으로 두었다.
> 보호 대상을 정확히 반대로 고른 것이었고, v2는 이를 뒤집는다.
> 이 문장을 AUDIT.md의 REV-01에 그대로 쓰면 좋다.

---

## 2. `encoder.py` — REV-04

`dll_data`를 읽은 직후, XOR 암호화 **전에** 삽입한다.

```python
# ── REV-04 ──────────────────────────────────────────────
# v1은 복호화 결과를 MZ 시그니처로 검증했고, 그 검증 코드가 그대로
# 브루트포스 정답 판별기로 쓰였다. 판별 근거가 되는 상수들을 미리 제거한다.
# Reflective Loader는 e_lfanew만 참조하고 시그니처를 검사하지 않으므로
# 복원 없이도 정상 로드된다.
dll_data = bytearray(dll_data)

e_lfanew = int.from_bytes(dll_data[0x3C:0x40], "little")

dll_data[0x00:0x02] = b"\x00\x00"                        # MZ 제거
dll_data[e_lfanew:e_lfanew + 4] = b"\x00\x00\x00\x00"    # PE\0\0 제거
dll_data[0x40:e_lfanew] = b"\x00" * (e_lfanew - 0x40)    # DOS 스텁 문자열 제거

dll_data = bytes(dll_data)
print(f"header stub applied (e_lfanew = 0x{e_lfanew:X})")
```

DOS 스텁까지 지우는 이유는 `This program cannot be run in DOS mode` 문자열이
MZ와 동일한 역할의 판별 근거이기 때문이다.

---

## 3. `main.c` — REV-04

TLS Callback의 MZ 검사 블록을 제거한다.

```c
// 변경 전
if (shellcode[0] == 0x4D && shellcode[1] == 0x5A) {
    sub_140001000(shellcode);
}
else {
    return;
}

// 변경 후
// REV-04: MZ 매직 검사 제거.
// 이 검사는 무결성 확인 목적이었으나 실제로는 공격자에게
// 브루트포스 정답 판별기를 제공하고 있었다.
sub_140001000(shellcode);
```

`sub_140001000`은 `e_lfanew`만 읽고 `e_magic`이나 `Signature`를 검사하지 않으므로
헤더 스터빙 이후에도 그대로 동작한다. 빌드 후 반드시 실행해서 확인할 것.

### 함수명 정리 (선택)

공개 소스에서는 `sub_140001000` / `sub_140002000` 대신
`ReflectiveLoader` / `TlsCallback`으로 바꾸고 주석으로 IDA 표기를 남기는 편이 읽기 좋다.

```c
// IDA 기준 sub_140001000
ULONG_PTR ReflectiveLoader(LPVOID dllBuffer) { ... }
```

---

## 4. 검증 증거 수집

AUDIT.md의 "수정 후 검증" 칸을 채울 재료다. **v1과 v2를 같은 조건에서 돌려 비교**한다.

### 4-1. 브루트포스 스크립트 (REV-04 검증용)

```python
# brute.py — v1에서는 즉시 키를 찾고, v2에서는 찾지 못한다
import re

data = open("shellcode.bin", "rb").read()   # IDA에서 덤프한 shellcode 배열

for key in range(256):
    dec = bytes(b ^ key for b in data)
    if dec[0:2] == b"MZ":
        print(f"[+] key found: 0x{key:02X}")
        break
else:
    print("[-] no key found by MZ oracle")
```

### 4-2. 캡처할 화면

| 항목 | v1 | v2 |
|---|---|---|
| `brute.py` 실행 | `key found: 0x7F` | `no key found` |
| 복호화된 DLL에 `strings` | `DH{r3fl3ct1v3_m4st3r}` 노출 | 플래그 문자열 없음 |
| IDA에서 `my_strcmp` 슈도코드 | `printf` 인자에 플래그 | 복호화 루틴만 보임 |
| `EASY_REVERSING` 입력 | `flag is DH{too_easy_password}` | `Wrong~` |
| 정답 입력 | 플래그 출력 | 플래그 출력 (기능 동일 확인) |

마지막 행이 중요하다. **보안을 고쳤는데 문제가 안 풀리면 수정이 아니라 파괴**이므로,
정답 경로가 여전히 동작한다는 증거를 같이 남긴다.

---

## 5. 한계에 반드시 적을 것

v2로도 남는 문제다. 감추지 말고 명시한다.

1. **브루트포스 자체는 여전히 가능하다.** MZ 오라클은 제거했으나 섹션 이름(`.text`,
   `.rdata`), import DLL 이름(`KERNEL32.dll`), 함수 이름 문자열이 복호화 결과에 남아
   동일한 판별 근거로 쓰일 수 있다. 공격 비용을 올렸을 뿐 차단하지 못했다.

2. **쉘코드 복호화 키는 원리적으로 비밀이 될 수 없다.** 프로그램이 사용자 입력 없이
   스스로 키를 유도해야 하므로, 어떤 방식으로 구성하든 정적 분석으로 추적 가능하다.
   구조적 대응은 `.text` 체크섬을 키 재료에 묶어 변조 시 복호화가 실패하게 하는 것이며,
   이는 REV-03의 수정 방안으로 향후 과제에 해당한다.

3. **복호화 이후 메모리 상주(REV-05)는 미해결이다.** TLS Callback 종료 후
   프로세스를 어태치하거나 `PEB.BeingDebugged`를 패치하면 안티디버깅이 무력화되고,
   in-place 복호화이므로 메모리 덤프로 DLL을 획득할 수 있다.
   다만 헤더 스터빙으로 인해 덤프 결과는 시그니처가 손상된 PE이므로 복구 작업이 추가된다.

4. **위협 모델의 한계.** 본 챌린지는 공격자가 로컬에서 바이너리를 완전히 통제하는
   CTF 환경을 전제한다. 이 조건에서 완전한 anti-reversing은 성립하지 않는다.
   v2의 목표는 절대적 보호가 아니라, **의도한 풀이 경로를 무의미하게 만드는
   설계 결함을 제거**하는 것이다.

---

## 6. 예상 질문

구현하면서 답을 준비해둘 것.

- MZ 검사가 왜 오라클이 되는가
- REV-04가 REV-01보다 위험도가 높은 이유는
- 해시를 저장하면 오프라인 공격이 가능하지 않은가
  (→ 해시는 판정용이고 플래그 보호는 입력 유도 키가 담당한다.
     해시를 깨서 정답을 찾았다면 그것은 문제를 푼 것이다)
- `FirstThunk`와 `OriginalFirstThunk`의 역할 차이는
- `PEB.BeingDebugged`는 정확히 어떻게 사용되는가
- 로컬 환경에서 완전한 anti-reversing이 가능한가
