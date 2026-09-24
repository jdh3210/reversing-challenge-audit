"""
flag_gen.py — v2 플래그 블롭 생성기

v1은 플래그를 printf에 평문 문자열로 보유했다(REV-01).
v2는 플래그를 사용자 입력에서 유도한 키스트림으로만 복호화할 수 있게 한다.
따라서 오답 입력 상태에서는 플래그가 바이너리에도, 프로세스 메모리에도 존재하지 않는다.

출력: flag_blob.h  (dllmain.cpp에서 include)

빌드 순서상 가장 먼저 실행해야 한다.
  flag_gen.py -> flag_blob.h -> RealDll.dll -> encoder.py -> shellcode.h -> challenge.exe
"""

PASSWORD = "R3FL3CTIV3_MAST3R"
FLAG = "DH{r3fl3ct1v3_m4st3r}"

FNV64_OFFSET = 0xCBF29CE484222325
FNV64_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF


def fnv1a64(data: bytes) -> int:
    """FNV-1a 64비트. C측 구현과 바이트 단위로 동일해야 한다."""
    h = FNV64_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & MASK64
    return h


def keystream(seed: int, length: int) -> bytes:
    """seed에서 length 바이트의 키스트림을 생성. 8바이트 블록 단위, 리틀엔디안."""
    out = bytearray()
    h = seed
    while len(out) < length:
        h = (h * FNV64_PRIME) & MASK64
        h ^= (h >> 29)
        out += h.to_bytes(8, "little")
    return bytes(out[:length])


def main():
    flag_bytes = FLAG.encode()

    # 정답 입력에서 유도한 키스트림으로 플래그를 암호화
    seed = fnv1a64(PASSWORD.encode())
    ks = keystream(seed, len(flag_bytes))
    enc = bytes(a ^ b for a, b in zip(flag_bytes, ks))

    # 복호화 결과가 진짜 플래그인지 판정하는 데 쓰는 해시.
    # 입력의 해시가 아니라 '복호화된 결과'의 해시라는 점이 중요하다.
    # 오답 입력 -> 쓰레기 복호화 -> 해시 불일치 -> 아무것도 출력되지 않음
    flag_hash = fnv1a64(flag_bytes)

    # 자체 검증
    dec = bytes(a ^ b for a, b in zip(enc, keystream(seed, len(enc))))
    assert dec == flag_bytes, "복호화 검증 실패"
    assert fnv1a64(dec) == flag_hash, "해시 검증 실패"

    lines = []
    lines.append("#pragma once")
    lines.append("// flag_gen.py가 생성한 파일. 직접 수정하지 말 것.")
    lines.append("")
    lines.append("static const unsigned char enc_flag[] = {")
    for i in range(0, len(enc), 12):
        chunk = enc[i:i + 12]
        body = ", ".join(f"0x{b:02X}" for b in chunk)
        comma = "," if i + 12 < len(enc) else ""
        lines.append(f"    {body}{comma}")
    lines.append("};")
    lines.append("")
    lines.append(f"static const unsigned long long FLAG_HASH = 0x{flag_hash:016X}ULL;")
    lines.append("")

    with open("flag_blob.h", "w") as f:
        f.write("\n".join(lines))

    print(f"password  : {PASSWORD}")
    print(f"flag      : {FLAG} ({len(flag_bytes)} bytes)")
    print(f"seed      : 0x{seed:016X}")
    print(f"flag hash : 0x{flag_hash:016X}")
    print("flag_blob.h 생성 완료")


if __name__ == "__main__":
    main()
