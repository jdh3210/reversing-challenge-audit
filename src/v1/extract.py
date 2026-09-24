# extract.py — shellcode.h와 같은 폴더에서 실행
import re
with open("shellcode.h", "r") as f:
    content = f.read()
hex_vals = re.findall(r'0x([0-9A-Fa-f]{2})', content)
data = bytes(int(h, 16) for h in hex_vals)
with open("shellcode.bin", "wb") as f:
    f.write(data)
print(f"{len(data)} bytes extracted")