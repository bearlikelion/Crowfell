import socket, struct, threading, sys, time, io

"""
Crowfall zone server - minimal TCP responder.

Protocol (from BasicHeader in GameAssembly.dll):
  [Magic1:1=0x54][Magic2:1=0x53][messageLength:4LE][messageType:4LE][messageNumber:4LE]
  Total header: 14 bytes, followed by payload of (messageLength - 14) bytes.
  Magic bytes: 'T' 'S'

Message type IDs are computed via StringID.MakeStringID(className).

Handshake flow (SERVER speaks first):
  Server -> Client: PhysicsConnectionRequest  (empty payload)
  Client -> Server: PhysicsConnectionResponse  (AuthToken:string, ExpectedContextId:int)
  Server -> Client: PhysicsAuthenticationConfirmation (SessionGuid:string)
  Server -> Client: PhysicsCloseLoadScreenMessage (notifications:int)
  Client -> Server: PhysicsPingMsg / Server -> Client: PhysicsPingReplyMsg
"""

BIND_ADDR = '0.0.0.0'
BIND_PORT = 8900

HEADER_LEN = 14
MAGIC1 = 0x54  # 'T'
MAGIC2 = 0x53  # 'S'

# --- Message type IDs (StringID.MakeStringID hash of class name) ---
def make_string_id(s):
    """Reproduce the Crowfall StringID.MakeStringID hash."""
    acc = 0
    bit_pos = 0
    for ch in s:
        value = ord(ch.upper()) - 0x20
        acc ^= (value << (bit_pos & 31)) & 0xFFFFFFFF
        if bit_pos > 24:
            shift_right = (32 - bit_pos) & 31
            if shift_right > 0:
                acc ^= (value >> shift_right) & 0xFFFFFFFF
        if bit_pos >= 27:
            bit_pos -= 32
        bit_pos += 5
    if acc >= 0x80000000:
        acc -= 0x100000000
    return acc

MSG_PhysicsConnectionRequest           = make_string_id('PhysicsConnectionRequest')
MSG_PhysicsConnectionResponse          = make_string_id('PhysicsConnectionResponse')
MSG_PhysicsAuthenticationConfirmation   = make_string_id('PhysicsAuthenticationConfirmation')
MSG_PhysicsPingMsg                     = make_string_id('PhysicsPingMsg')
MSG_PhysicsPingReplyMsg                = make_string_id('PhysicsPingReplyMsg')
MSG_PhysicsCloseLoadScreenMessage      = make_string_id('PhysicsCloseLoadScreenMessage')
MSG_PhysicsServerTimeMessage           = make_string_id('PhysicsServerTimeMessage')

# Print computed IDs at startup
MSG_NAMES = {
    MSG_PhysicsConnectionRequest: 'PhysicsConnectionRequest',
    MSG_PhysicsConnectionResponse: 'PhysicsConnectionResponse',
    MSG_PhysicsAuthenticationConfirmation: 'PhysicsAuthenticationConfirmation',
    MSG_PhysicsPingMsg: 'PhysicsPingMsg',
    MSG_PhysicsPingReplyMsg: 'PhysicsPingReplyMsg',
    MSG_PhysicsCloseLoadScreenMessage: 'PhysicsCloseLoadScreenMessage',
    MSG_PhysicsServerTimeMessage: 'PhysicsServerTimeMessage',
}


def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}: {hex_part:<48} {ascii_part}")
    return "\n".join(lines)


def build_header(msg_type, msg_num, payload_len):
    """Build a 14-byte BasicHeader."""
    msg_len = HEADER_LEN + payload_len
    return struct.pack('<bbIii', MAGIC1, MAGIC2, msg_len, msg_type, msg_num)


def build_message(msg_type, msg_num, payload=b''):
    """Build a complete message (header + payload)."""
    return build_header(msg_type, msg_num, len(payload)) + payload


def write_binarywriter_string(s):
    """Encode a string the way .NET BinaryWriter.Write(string) does:
    7-bit encoded length prefix + UTF-8 bytes."""
    encoded = s.encode('utf-8')
    length = len(encoded)
    prefix = bytearray()
    while length >= 0x80:
        prefix.append((length & 0x7F) | 0x80)
        length >>= 7
    prefix.append(length & 0x7F)
    return bytes(prefix) + encoded


def read_binaryreader_string(data, offset):
    """Read a .NET BinaryReader string (7-bit length prefix + UTF-8)."""
    length = 0
    shift = 0
    pos = offset
    while True:
        b = data[pos]
        pos += 1
        length |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    s = data[pos:pos+length].decode('utf-8')
    return s, pos + length


def parse_header(data):
    """Parse a 14-byte BasicHeader."""
    if len(data) < HEADER_LEN:
        return None
    magic1, magic2 = data[0], data[1]
    msg_len = struct.unpack_from('<I', data, 2)[0]
    msg_type = struct.unpack_from('<i', data, 6)[0]
    msg_num = struct.unpack_from('<i', data, 10)[0]
    return (magic1, magic2, msg_len, msg_type, msg_num)


def recv_exact(conn, n, timeout=10):
    conn.settimeout(timeout)
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_message(conn, timeout=30):
    """Receive one complete message. Returns (msg_type, msg_num, payload) or None."""
    header_data = recv_exact(conn, HEADER_LEN, timeout=timeout)
    if header_data is None:
        return None

    hdr = parse_header(header_data)
    if hdr is None:
        print(f"[ZONE] Bad header:")
        print(hexdump(header_data))
        return None

    magic1, magic2, msg_len, msg_type, msg_num = hdr
    if magic1 != MAGIC1 or magic2 != MAGIC2:
        print(f"[ZONE] Bad magic: 0x{magic1:02x} 0x{magic2:02x} (expected 0x{MAGIC1:02x} 0x{MAGIC2:02x})")
        print(hexdump(header_data))
        return None

    payload_len = msg_len - HEADER_LEN if msg_len > HEADER_LEN else 0
    payload = b''
    if payload_len > 0:
        payload = recv_exact(conn, payload_len, timeout=10)
        if payload is None:
            return None

    name = MSG_NAMES.get(msg_type, f'Unknown(0x{msg_type & 0xFFFFFFFF:08x})')
    print(f"  << RECV [{name}] type={msg_type} num={msg_num} payload={len(payload)}b")
    if payload:
        print(hexdump(payload, prefix="     "))
    sys.stdout.flush()
    return (msg_type, msg_num, payload)


def send_message(conn, msg_type, msg_num, payload=b''):
    """Send a complete message."""
    msg = build_message(msg_type, msg_num, payload)
    name = MSG_NAMES.get(msg_type, f'Unknown(0x{msg_type & 0xFFFFFFFF:08x})')
    print(f"  >> SEND [{name}] type={msg_type} num={msg_num} payload={len(payload)}b")
    if payload:
        print(hexdump(payload, prefix="     "))
    sys.stdout.flush()
    conn.sendall(msg)


def handle(conn, addr):
    print(f"\n{'='*60}")
    print(f"[ZONE] Connection from {addr}")
    print(f"{'='*60}")
    sys.stdout.flush()

    msg_num_counter = 0

    def next_msg_num():
        nonlocal msg_num_counter
        msg_num_counter += 1
        return msg_num_counter

    try:
        # Step 1: Server sends PhysicsConnectionRequest (empty payload)
        print("[ZONE] Sending PhysicsConnectionRequest...")
        send_message(conn, MSG_PhysicsConnectionRequest, next_msg_num())

        # Step 2: Read PhysicsConnectionResponse from client
        print("[ZONE] Waiting for PhysicsConnectionResponse...")
        result = recv_message(conn, timeout=30)
        if result is None:
            print("[ZONE] No response received")
            return

        msg_type, msg_num_recv, payload = result
        if msg_type == MSG_PhysicsConnectionResponse:
            auth_token, pos = read_binaryreader_string(payload, 0)
            expected_ctx = struct.unpack_from('<i', payload, pos)[0]
            print(f"  -> AuthToken: {auth_token}")
            print(f"  -> ExpectedContextId: {expected_ctx}")
        else:
            print(f"  -> Unexpected message type, continuing anyway")

        # Step 3: Send PhysicsAuthenticationConfirmation
        print("[ZONE] Sending PhysicsAuthenticationConfirmation...")
        session_guid = "mock-session-" + str(int(time.time()))
        auth_payload = write_binarywriter_string(session_guid)
        send_message(conn, MSG_PhysicsAuthenticationConfirmation, next_msg_num(), auth_payload)

        # Step 4: Send PhysicsCloseLoadScreenMessage to dismiss loading screen
        time.sleep(0.5)
        print("[ZONE] Sending PhysicsCloseLoadScreenMessage...")
        close_payload = struct.pack('<i', 0)  # notifications = 0
        send_message(conn, MSG_PhysicsCloseLoadScreenMessage, next_msg_num(), close_payload)

        # Step 5: Main loop - handle pings and log everything
        print("[ZONE] Entering main loop (handling pings)...")
        while True:
            result = recv_message(conn, timeout=60)
            if result is None:
                print("[ZONE] Connection closed or timeout")
                break

            msg_type, msg_num_recv, payload = result

            if msg_type == MSG_PhysicsPingMsg:
                # PhysicsPingMsg: UtcNowTicks(long) + LastPingMS(int) = 12 bytes
                if len(payload) >= 12:
                    utc_ticks = struct.unpack_from('<q', payload, 0)[0]
                    last_ping = struct.unpack_from('<i', payload, 8)[0]
                    print(f"  -> Ping: UtcNowTicks={utc_ticks} LastPingMS={last_ping}")

                    # Reply with PhysicsPingReplyMsg
                    now_ticks = int(time.time() * 10_000_000) + 621355968000000000  # .NET ticks
                    reply_payload = struct.pack('<qqd',
                        utc_ticks,       # echo back client's UtcNowTicks
                        now_ticks,       # server recv time
                        time.time()      # ServerTime as double
                    )
                    send_message(conn, MSG_PhysicsPingReplyMsg, next_msg_num(), reply_payload)
            else:
                print(f"  -> Unhandled message, logging only")

    except socket.timeout:
        print(f"[ZONE] Timeout")
    except ConnectionResetError:
        print(f"[ZONE] Connection reset")
    except BrokenPipeError:
        print(f"[ZONE] Broken pipe")
    except Exception as e:
        import traceback
        print(f"[ZONE] Error: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        conn.close()
        print(f"[ZONE] Disconnected from {addr}")
        sys.stdout.flush()


def main():
    print("Crowfall Zone Server (minimal)")
    print(f"Listening on {BIND_ADDR}:{BIND_PORT}")
    print()
    print("Message type IDs:")
    for type_id, name in sorted(MSG_NAMES.items(), key=lambda x: x[1]):
        print(f"  {name}: {type_id} (0x{type_id & 0xFFFFFFFF:08x})")
    print()
    sys.stdout.flush()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND_ADDR, BIND_PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
