=========================================
 v2 빌드 절차
=========================================

v1 대비 변경 사항은 docs/v2_changes.md 참조.
구현 범위: REV-01, REV-02, REV-04
제외(향후 과제): REV-03, REV-05

[환경]
- Windows x64
- MSVC (x64 Native Tools Command Prompt)
- Python 3.x

-----------------------------------------
[빌드 옵션 — 반드시 확인]
-----------------------------------------

EXE는 반드시 /MD (동적 CRT) 로 빌드할 것.

IAT 후킹이 EXE의 import table에서 strcmp를 찾는 데 의존한다.
/MT로 빌드하면 strcmp가 정적 링크되어 import table에 없고, hook_IAT()가
대상을 찾지 못해 후킹이 조용히 실패한다. 빌드/런타임 에러가 전혀 없이
EASY_REVERSING이 미끼 플래그를 그대로 출력하고(REV-02 무력화) 정답을
입력해도 Wrong~ 만 나온다(REV-01 무력화).

  * cl.exe 커맨드라인 기본값은 /MT 다. 반드시 /MD를 명시할 것.

DLL도 /MD 권장. /MT면 EXE와 별개의 CRT 인스턴스를 갖게 되어, 플래그를
printf로 출력한 직후 ExitProcess(0)을 호출할 때 버퍼가 flush되지 않을
수 있다.

빌드 후 확인:
  dumpbin /imports challenge_v2.exe | findstr /i strcmp
  -> strcmp가 잡혀야 정상

-----------------------------------------
[순서]  v1에 flag_gen.py 단계가 앞에 추가됨
-----------------------------------------

1. flag_gen.py -> flag_blob.h                      [v2 신규]

   플래그를 정답 입력에서 유도한 키스트림으로 암호화하고, 판정용 해시와
   함께 헤더로 출력한다. 빌드 순서상 가장 먼저 실행해야 한다.

     python flag_gen.py

   -> enc_flag[] 와 FLAG_HASH 를 담은 flag_blob.h 생성

2. dllmain_v2.cpp -> RealDll.dll

   strcmp를 후킹한다. flag_blob.h를 include하므로 1번이 선행되어야 한다.

     cl /LD /EHsc /utf-8 /MD dllmain_v2.cpp /Fe:RealDll.dll

   * dllmain_v2.cpp는 pch.h를 쓰지 않으므로 커맨드라인 빌드가 그대로 된다.
   * flag_blob.h 관련 C4819 경고는 인코딩 경고이며 무시해도 된다.

3. encoder_v2.py -> shellcode.h

   XOR 암호화 전에 헤더 스터빙(MZ / PE\0\0 / DOS 스텁 제거)을 적용한다.
   RealDll.dll을 같은 폴더에 두고:

     python encoder_v2.py

   -> "header stub applied (e_lfanew = 0x...)" 출력 확인

   * 복호화 결과의 첫 2바이트가 4D 5A 가 아니라 00 00 인 것이 정상이다.
     Reflective Loader는 e_lfanew만 참조하고 시그니처를 검사하지 않는다.

4. main_v2.c -> challenge_v2.exe

   TLS Callback에서 복호화 후 Reflective DLL Injection을 수행한다.
   v1과 달리 MZ 매직 검사가 없다(REV-04). shellcode.h를 같은 폴더에 두고:

     cl /utf-8 /MD main_v2.c /Fe:challenge_v2.exe

-----------------------------------------
[단계 의존성 — 주의]
-----------------------------------------

key2가 DLL 파일 크기에서 유도되므로 DLL을 다시 빌드하면 암호화 키가
바뀐다. 어느 단계를 다시 하면 그 뒤 단계를 전부 다시 해야 한다.

  flag_gen.py     수정 -> 2, 3, 4 다시
  dllmain_v2.cpp  수정 -> 3, 4 다시
  encoder_v2.py   수정 -> 4 다시

한 번에 다시 돌리려면:

  del *.obj
  python flag_gen.py
  cl /LD /EHsc /utf-8 /MD dllmain_v2.cpp /Fe:RealDll.dll
  python encoder_v2.py
  cl /utf-8 /MD main_v2.c /Fe:challenge_v2.exe

-----------------------------------------
[동작 확인]
-----------------------------------------

challenge_v2.exe 실행 후:
  EASY_REVERSING      -> Wrong~          (REV-02: 미끼 경로 차단)
  R3FL3CTIV3_MAST3R   -> 진짜 플래그 출력 (기능 동일 확인)

두 번째가 중요하다. 보안을 고쳤는데 문제가 안 풀리면 수정이 아니라
파괴이므로, 정답 경로가 여전히 동작한다는 증거를 같이 남긴다.

둘 중 하나라도 어긋나면 후킹이 실패한 것이다.
[빌드 옵션]의 /MD 항목부터 확인할 것.