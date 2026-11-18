import socket, string, re

HOST, PORT = "target_host", 1337  # fill in the actual challenge values

def peek(addr_hex):
    s = socket.create_connection((HOST, PORT), timeout=2)
    s.recv(4096)
    s.sendall(b"peek\n")
    s.recv(4096)
    s.sendall(addr_hex.encode() + b"\n")
    data = s.recv(4096)
    s.close()
    return data

out = bytearray()
for addr in range(0x0000, 0x0900, 2):   # SRAM on an atmega328-class chip is ~2KB
    resp = peek("%04x" % addr)
    m = re.search(rb"([0-9a-fA-F]{2})\s*([0-9a-fA-F]{2})", resp)
    if m:
        out += bytes.fromhex(m.group(1).decode())
        out += bytes.fromhex(m.group(2).decode())

text = bytes(ch if chr(ch) in string.printable else 0x2e for ch in out)
print(text.decode(errors="replace"))