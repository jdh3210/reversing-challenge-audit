"""
encoder_v2.py — v2 쉘코드 암호화기

v1 대비 변경:
- REV-04(초기 수정): 암호화 전 PE 시그니처와 DOS 스텁을 제거하여
                     "복호화 결과의 MZ 매직"을 판별 근거로 삼는
                     특정 브루트포스 스크립트를 무력화
- REV-04(재수정):    치환값을 상수 0에서 "원본 평문 자신"으로 변경.
                     1바이트 XOR 하에서 암호문[i] = 평문[i] XOR key 이므로,
                     치환 후 평문[i] = 원본평문[i] 이면 암호문도 원래 값
                     을 그대로 유지한다. 상수 0으로 치환하는 경우
                     암호문[0] = 0 XOR key = key 가 되어 키를 직접
                     노출하는 문제가 있었다.

알려진 한계:
- 1바이트 XOR 자체가 근본 결함이다. 256개 키 전수조사로 복원 가능하며,
  섹션 이름(.text, .rdata)이나 import DLL 이름이 복호화 결과의 판별
  근거로 사용될 수 있다. 본 수정은 "치환 바이트가 키를 직접 노출하는
  명백한 실수"를 바로잡는 것이며, 1바이트 XOR의 근본 약점을 해결하지
  는 않는다. 구조적 해결은 v3 과제로 분리한다.
"""

from datetime import datetime

with open("RealDll.dll", "rb") as f:
    dll_data = f.read()
print(f"DLL Size is {len(dll_data)} bytes.")

# ──────────────────────────────────────────────────────────────
# REV-04: PE 시그니처 영역 처리
#
# 원본 평문의 특정 바이트 위치에 알려진 상수가 존재하면
# key = 암호문[i] XOR 알려진_평문[i] 로 즉시 복원된다.
# 가장 직접적인 노출원인 MZ(0x4D 0x5A), PE\0\0(0x50 0x45 0x00 0x00),
# DOS 스텁 문자열("This program cannot be run in DOS mode")을 다룬다.
#
# 초기 수정에서는 이 영역을 0으로 채웠다. 그러나 상수 0도 "알려진 평문"
# 이므로 암호문[i] = 0 XOR key = key 가 되어 오히려 키를 직접 노출한다.
#
# 재수정: 치환하지 않고 원본 그대로 둔다.
# 이 경우 공격자는 "이 바이트가 MZ라는 사실"로 키를 복원할 수 있다는
# 점에서 보호 효과는 없지만, 적어도 "0으로 치환했다"로 인한 추가 노출은
# 발생하지 않는다. 1바이트 XOR 자체의 결함이므로 encoder 레벨에서
# 근본 해결은 불가능하다.
#
# 따라서 이 섹션은 "초기 수정의 실수를 정정하고, 1바이트 XOR의 한계를
# 문서화" 하는 것이 목적이다.
# ──────────────────────────────────────────────────────────────

# 참고용: 초기 수정 시 적용했던 치환 (주석 처리)
# dll_data = bytearray(dll_data)
# e_lfanew = int.from_bytes(dll_data[0x3C:0x40], "little")
# dll_data[0x00:0x02] = b"\x00\x00"
# dll_data[e_lfanew:e_lfanew + 4] = b"\x00\x00\x00\x00"
# dll_data[0x40:e_lfanew] = b"\x00" * (e_lfanew - 0x40)
# dll_data = bytes(dll_data)

check_debugged = 0
key1 = 0x77 * (1 - check_debugged)

key2 = (len(dll_data) >> 8) & 0xFF

team_name = "TEAMH4C"
total = 0
for c in team_name:
    total = total + ord(c)
key3 = total & 0xFF

final_key = key1 ^ key2 ^ key3

print(f"first key is debugging status: 0x{key1:02X}")
print(f"second key is file length: 0x{key2:02X}")
print(f"third key is team name: 0x{key3:02X}")
print(f"final key is key1^key2^key3: 0x{final_key:02X}")

encrypted_data_list = []
for byte in dll_data:
    encrypted_data = byte ^ final_key
    encrypted_data_list.append(encrypted_data)

print(f"Encrypted size is {len(encrypted_data_list)} bytes")

with open("shellcode.h", "w") as f:
    f.write("unsigned char shellcode[] = {\n")

    for i in range(0, len(encrypted_data_list), 16):
        split_data = encrypted_data_list[i:i + 16]
        line_data = "    "

        for index, byte in enumerate(split_data):
            if index > 0:
                line_data = line_data + ", "
            line_data = line_data + f"0x{byte:02X}"

        if i + 16 < len(encrypted_data_list):
            line_data = line_data + ","

        f.write(line_data + "\n")

    f.write("};\n")
    f.write(f"unsigned int shellcode_len = {len(encrypted_data_list)};\n")

print("shellcode file created~")
