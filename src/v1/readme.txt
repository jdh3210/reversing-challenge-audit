=========================================
 v1 빌드 절차
=========================================

[환경]
- Windows x64
- MSVC (Visual Studio 또는 x64 Native Tools Command Prompt)
- Python 3.x

-----------------------------------------
[빌드 옵션 — 반드시 확인]
-----------------------------------------

EXE는 반드시 /MD (동적 CRT) 로 빌드할 것.

이 챌린지의 핵심 동작은 EXE의 IAT에서 strcmp를 찾아 후킹하는 것이다.
/MT (정적 CRT) 로 빌드하면 strcmp가 EXE에 정적 링크되어 import table에
나타나지 않고, hook_IAT()가 대상을 찾지 못해 후킹이 조용히 실패한다.
빌드 에러도 런타임 에러도 없이, 정답을 입력해도 Wrong~ 만 출력된다.

  * cl.exe를 커맨드라인에서 옵션 없이 쓰면 기본값이 /MT 다.
    Visual Studio 프로젝트 기본값(/MD)과 다르므로 반드시 명시할 것.

DLL도 /MD 권장.
/MT면 DLL이 EXE와 별개의 CRT 인스턴스를 갖게 되어, 플래그를 printf로
출력한 직후 ExitProcess(0)을 호출할 때 출력 버퍼가 flush되지 않고
프로세스가 종료될 수 있다.

빌드 후 확인:
  dumpbin /imports challenge.exe | findstr /i strcmp
  -> strcmp가 잡혀야 정상

-----------------------------------------
[순서]
-----------------------------------------

1. dllmain.cpp -> RealDll.dll

   strcmp를 후킹하고 진짜 플래그를 숨기는 DLL을 생성한다.

     cl /LD /EHsc /utf-8 /MD dllmain.cpp /Fe:RealDll.dll

   * dllmain.cpp에는 #include "pch.h" 가 있어 Visual Studio의 미리
     컴파일된 헤더 사용이 전제다. 커맨드라인 cl로 빌드하려면 해당 줄을
     제거하거나 빈 pch.h를 같은 폴더에 만들어야 한다.

2. encoder.py -> shellcode.h

   RealDll.dll을 3개의 키로 XOR 암호화한다.
     key1 = 디버깅 여부 체크
     key2 = 파일 크기
     key3 = 팀명
     final_key = key1 ^ key2 ^ key3

   RealDll.dll을 encoder.py와 같은 폴더에 두고:

     python encoder.py

3. main.c -> challenge.exe

   TLS Callback에서 shellcode.h를 복호화한 후 Reflective DLL Injection을
   수행한다. shellcode.h를 main.c와 같은 폴더에 두고:

     cl /utf-8 /MD main.c /Fe:challenge.exe

-----------------------------------------
[단계 의존성 — 주의]
-----------------------------------------

key2가 DLL 파일 크기에서 유도되므로 DLL을 다시 빌드하면 암호화 키가
바뀐다. 어느 단계를 다시 하면 그 뒤 단계를 전부 다시 해야 한다.

  dllmain.cpp 수정 -> 2, 3 다시
  encoder.py  수정 -> 3 다시

-----------------------------------------
[동작 확인]
-----------------------------------------

challenge.exe 실행 후:
  EASY_REVERSING      -> 가짜 플래그 출력 (미끼)
  R3FL3CTIV3_MAST3R   -> 진짜 플래그 출력

정답을 넣었는데 Wrong~ 이 나오면 후킹 실패다.
[빌드 옵션]의 /MD 항목부터 확인할 것.