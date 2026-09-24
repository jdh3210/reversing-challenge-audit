from datetime import datetime

with open("RealDll.dll", "rb") as f:
    dll_data = f.read()
print(f"DLL Size is {len(dll_data)} bytes.")

# REV-04: MZ / PE 시그니처 / DOS 스텁을 제거해 브루트포스 판별 근거를 없앤다 (XOR 암호화 전에 적용)
dll_data = bytearray(dll_data)

e_lfanew = int.from_bytes(dll_data[0x3C:0x40], "little")

dll_data[0x00:0x02] = b"\x00\x00"                        # MZ 제거
dll_data[e_lfanew:e_lfanew + 4] = b"\x00\x00\x00\x00"    # PE\0\0 제거
dll_data[0x40:e_lfanew] = b"\x00" * (e_lfanew - 0x40)    # DOS 스텁 문자열 제거

dll_data = bytes(dll_data)
print(f"header stub applied (e_lfanew = 0x{e_lfanew:X})")

check_debugged = 0
key1 = 0x77 * (1 - check_debugged)

key2 = (len(dll_data) >> 8)  & 0xFF

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

encrypted_data_list  = []
for byte in dll_data:
    encrypted_data = byte ^ final_key
    encrypted_data_list.append(encrypted_data)

print(f"Encrypted size is {len(encrypted_data_list)} bytes")

with open("shellcode.h", "w") as f:
    f.write("unsigned char shellcode[] = {\n")

    for i in range(0, len(encrypted_data_list), 16):
        split_data = encrypted_data_list[i:i+16]
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
