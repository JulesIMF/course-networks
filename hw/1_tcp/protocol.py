import errno
import socket
import struct
import threading
import queue
import time


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPHeader:
    # payload_size, seq_num, ack_num, flags (syn,ack,...), sack_count
    FMT = '!5I'
    FMT_SACK_BLOCK = '!2I'
    F_SYN = 0
    F_ACK = 1
    MAX_SACK_COUNT = 4

    def __init__(self, seq_num, ack_num, syn, ack, sack_count=0, sack_blocks=None, payload_size=0):
        self.payload_size = payload_size
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.syn = syn
        self.ack = ack
        self.sack_count = sack_count
        assert self.sack_count < self.MAX_SACK_COUNT
        self.sack_blocks = sack_blocks

    def to_bytes(self):
        flags = (1 << self.F_SYN) * int(self.syn) + \
                (1 << self.F_ACK) * int(self.ack)
        packed_data = struct.pack(
            self.FMT,
            self.payload_size,
            self.seq_num,
            self.ack_num,
            flags,
            self.sack_count
        )
        if self.sack_blocks:
            if len(self.sack_blocks) != self.sack_count:
                raise ValueError(f"{self.sack_blocks} and {
                                 self.sack_count} do not match")
            packed_data += b''.join(map(lambda t: struct.pack(
                self.FMT_SACK_BLOCK, t[0], t[1]), self.sack_blocks))
        return packed_data

    @classmethod
    def from_tcp_segment(cls, segment, offset=0):
        unpacked_data = struct.unpack_from(cls.FMT, segment, offset)
        payload_size = unpacked_data[0]
        seq_num = unpacked_data[1]
        ack_num = unpacked_data[2]
        flags = unpacked_data[3]
        sack_count = unpacked_data[4]
        assert sack_count < cls.MAX_SACK_COUNT
        syn = bool(flags & (1 << cls.F_SYN))
        ack = bool(flags & (1 << cls.F_ACK))
        sack_blocks = [] if sack_count > 0 else None
        for block_idx in range(sack_count):
            sack_blocks.append(struct.unpack_from(
                cls.FMT_SACK_BLOCK, segment, offset + cls.size(block_idx)))
        return cls(seq_num, ack_num, syn, ack, sack_count, sack_blocks, payload_size)

    @classmethod
    def size(cls, sack_count=None):
        if sack_count is None:
            sack_count = cls.MAX_SACK_COUNT
        return struct.calcsize(cls.FMT) + sack_count * struct.calcsize(cls.FMT_SACK_BLOCK)


class Buffer:
    class PresentSegments:
        def __init__(self):
            self.segments = []

        def contains(self, left, right):
            for (l_seg, r_seg) in self.segments:
                if l_seg <= left and right <= r_seg:
                    return True

            return False

        def put(self, left, right):
            i_begin = None
            i_end = None
            i_pos = None
            for i, (l_seg, r_seg) in enumerate(self.segments):
                # [] [left right] []
                if r_seg < left:
                    # не пересекаются ЕЩЕ
                    continue

                if right < l_seg:
                    # не пересекаются УЖЕ
                    if i_begin is not None:
                        i_end = i
                    else:
                        i_pos = i
                    break
                if i_begin is None:
                    i_begin = i

            if i_begin is not None:
                if i_end is None:
                    i_end = len(self.segments)

                left = min(left, self.segments[i_begin][0])
                right = max(right, self.segments[i_end - 1][1])

                self.segments = self.segments[:i_begin] + \
                    [(left, right)] + self.segments[i_end:]
                return

            if i_pos is not None:
                self.segments.insert(i_pos, (left, right))
            else:
                self.segments.append((left, right))

        def get_missing(self, max_count: int = None, begin=0):
            ans = []
            if len(self.segments) == 0:
                return ans

            if begin < self.segments[0][0]:
                ans.append((begin, self.segments[0][0]))

            for i in range(len(self.segments) - 1):
                left, right = self.segments[i][1], self.segments[i + 1][0]
                if right <= begin:
                    continue

                left = max(left, begin)
                ans.append((left, right))
                if max_count is not None and len(ans) > max_count:
                    break

            return ans[:max_count]

        def __repr__(self):
            return str(self.segments)

    def __init__(self):
        self.buffer = b''
        self.length = 0
        self.present_segments = self.PresentSegments()
        self.lock = threading.RLock()

    def put(self, data: bytes, size: int, begin: int | None = None):
        with self.lock:
            if begin is None:
                begin = self.length

            if self.length < begin + size:
                self.buffer += b'\x00' * (begin + size - self.length)
                self.length = begin + size

            self.buffer = self.buffer[:begin] + \
                data + self.buffer[begin + size:]
            
            return begin, begin + size


class IncomingBuffer(Buffer):
    def __init__(self):
        super().__init__()
        self.enough = threading.Condition(self.lock)
        self.wait_begin = 0
        self.wait_end = None

    def put(self, data: bytes, size: int, begin: int):
        with self.lock:
            if self.present_segments.contains(begin, begin + size):
                return

        super().put(data, size, begin)
        with self.lock:
            self.present_segments.put(begin, begin + size)
            if self.wait_end is not None and self.present_segments.contains(self.wait_begin, self.wait_end):
                self.enough.notify()

    def get_missing(self, max_count: int = None, begin=0):
        with self.lock:
            return self.present_segments.get_missing(max_count, begin)

    def get_next(self, count):
        with self.enough:
            if self.wait_end is not None:
                raise Exception("Double get on IncomingBuffer")

            self.wait_end = self.wait_begin + count

            self.enough.wait_for(lambda: self.present_segments.contains(
                self.wait_begin, self.wait_end))

            data = self.buffer[self.wait_begin:self.wait_end]
            self.wait_begin = self.wait_end
            self.wait_end = None
            return data


class OutcomingBuffer(Buffer):
    def __init__(self):
        super().__init__()

    def put(self, data):
        size = len(data)
        return super().put(data, size)        

    def acknowledge(self, left, right):
        with self.lock:
            self.present_segments.put(left, right)
    
    def is_acknowledged(self, left, right):
        with self.lock:
            return self.present_segments.contains(left, right)


class MyTCPProtocol(UDPBasedProtocol):
    IP_HEADER_SIZE = 60
    MTU = 65536 - IP_HEADER_SIZE - MyTCPHeader.size()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.closed = False
        self.listen_thread = threading.Thread(target=self.listening_loop_)
        self.transmission_thread = threading.Thread(
            target=self.transmission_loop_)
        self.incoming_buffer = IncomingBuffer()
        self.outcoming_buffer = OutcomingBuffer()
        self.write_queue = queue.PriorityQueue()

        self.closed_lock = threading.RLock()
        self.queue_lock = threading.RLock()

    @classmethod
    def build_segment(cls, header: MyTCPHeader, payload: bytes | None = None) -> bytes:
        if payload is not None:
            header.size = len(payload)
        segment = header.to_bytes()
        if payload is not None:
            segment += payload

        return segment

    @classmethod
    def parse_segment(cls, segment: bytes) -> bytes:
        header = MyTCPHeader.from_tcp_segment(segment)
        if header.size() == len(segment):
            return header, None

        return header, segment[header.size():]

    def process_incoming_segment_(self, header: MyTCPHeader, data: bytes):
        if header.ack:
            self.outcoming_buffer.acknowledge(0, header.ack_num)
        if header.sack_count > 0:
            for (left, right) in header.sack_blocks:
                self.outcoming_buffer.acknowledge(left, right)
        if header.payload_size > 0:
            self.incoming_buffer.put(data, header.payload_size, header.seq_num)

    def listening_loop_(self):
        while not self.is_closed():
            try:
                segment = self.recvfrom(self.MTU)
                header, data = self.parse_segment(segment)
                self.process_incoming_segment_(header, data)
            except socket.error as e:
                if e.errno == errno.EINVAL:
                    pass
                break
            except:
                break

    def transmission_loop_(self):
        while not self.is_closed():
            if self.write_queue.empty():
                continue
            try:
                (execution_time, task) = self.write_queue.get_nowait()
                if execution_time > time.monotonic():
                    self.write_queue.put((execution_time, task))
                else:
                    task()
            except Exception:
                continue
    
    def send_part(self, data: bytes):
        pass

    def send(self, data: bytes):
        return self.sendto(data)

    def recv(self, n: int):
        return self.incoming_buffer.get_next(n)

    def is_closed(self):
        with self.closed_lock:
            return self.closed

    def close(self):
        with self.closed_lock:
            self.closed = True

        super().close()
        self.listen_thread.join()
        self.transmission_thread.join()
