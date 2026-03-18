import socket, struct, threading, sys, time

"""
Crowfall zone server TCP sniffer / minimal responder.

Protocol (from BasicHeader in dump.cs):
  [Magic1:1][Magic2:1][messageLength:4LE][messageType:4LE][messageNumber:4LE][Byte1:1][Byte2:1]
  Total header: 16 bytes, followed by payload of (messageLength - 16) bytes.

Known message flow:
  Client -> Server: PhysicsConnectionRequest  (empty payload)
  Server -> Client: PhysicsConnectionResponse  (AuthToken:string, ExpectedContextId:int)
  Client -> Server: PhysicsAuthenticationConfirmation (SessionGuid:string)
  Client <-> Server: PhysicsPingMsg / PhysicsPingReplyMsg
"""

BIND_ADDR = '0.0.0.0'
BIND_PORT = 8900


def hexdump(data, prefix="  "):
    """Pretty hex dump."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}: {hex_part:<48} {ascii_part}")
    return "\n".join(lines)


def parse_header(data):
    """Parse a 16-byte BasicHeader. Returns (magic1, magic2, msg_len, msg_type, msg_num, b1, b2)."""
    if len(data) < 16:
        return None
    magic1, magic2 = data[0], data[1]
    msg_len = struct.unpack_from('<I', data, 2)[0]
    msg_type = struct.unpack_from('<i', data, 6)[0]
    msg_num = struct.unpack_from('<i', data, 10)[0]
    b1, b2 = data[14], data[15]
    return (magic1, magic2, msg_len, msg_type, msg_num, b1, b2)


def recv_exact(conn, n, timeout=10):
    """Receive exactly n bytes."""
    conn.settimeout(timeout)
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle(conn, addr):
    print(f"\n{'='*60}")
    print(f"[ZONE] Connection from {addr}")
    print(f"{'='*60}")
    sys.stdout.flush()

    msg_count = 0
    try:
        while True:
            # Read header (16 bytes)
            header_data = recv_exact(conn, 16, timeout=30)
            if header_data is None:
                print(f"[ZONE] Connection closed by client")
                break

            hdr = parse_header(header_data)
            if hdr is None:
                print(f"[ZONE] Bad header data:")
                print(hexdump(header_data))
                break

            magic1, magic2, msg_len, msg_type, msg_num, b1, b2 = hdr
            payload_len = msg_len - 16 if msg_len > 16 else 0

            # Read payload
            payload = b''
            if payload_len > 0:
                payload = recv_exact(conn, payload_len, timeout=10)
                if payload is None:
                    print(f"[ZONE] Connection closed during payload read")
                    break

            msg_count += 1
            full_msg = header_data + payload

            print(f"\n[MSG #{msg_count}] Type={msg_type} Num={msg_num} "
                  f"Len={msg_len} Magic=0x{magic1:02x}{magic2:02x} "
                  f"Flags=0x{b1:02x}{b2:02x}")
            print(f"  Full message ({len(full_msg)} bytes):")
            print(hexdump(full_msg))
            if payload:
                print(f"  Payload ({len(payload)} bytes):")
                print(hexdump(payload, prefix="    "))
            sys.stdout.flush()

    except socket.timeout:
        print(f"[ZONE] Timeout waiting for data (last msg #{msg_count})")
    except ConnectionResetError:
        print(f"[ZONE] Connection reset by client")
    except Exception as e:
        print(f"[ZONE] Error: {type(e).__name__}: {e}")
    finally:
        conn.close()
        print(f"[ZONE] Disconnected from {addr} (received {msg_count} messages)")
        sys.stdout.flush()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND_ADDR, BIND_PORT))
    s.listen(5)
    print(f"Crowfall zone sniffer listening on {BIND_ADDR}:{BIND_PORT}")
    print(f"Waiting for client connection...")
    sys.stdout.flush()

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
