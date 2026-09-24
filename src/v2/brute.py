# brute.py — v2 폴더에 shellcode.h에서 배열만 추출한 .bin 파일 만들고 실행
data = open("shellcode.bin", "rb").read()
for key in range(256):
    dec = bytes(b ^ key for b in data)
    if dec[0:2] == b"MZ":
        print(f"[+] key found: 0x{key:02X}")
        break
else:
    print("[-] no MZ oracle: key not found")