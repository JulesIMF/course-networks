import errno
import random
import socket
import struct
import sys
import threading
import queue
import time
import logging
import traceback

# logging.basicConfig(format='%(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.debug("Logger created")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

next_identy = -1
def get_identy():
    global next_identy
    next_identy += 1
    return next_identy


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)
        self.udp_socket.settimeout(1.0)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPHeader:
    # seg_id, payload_size, seq_num, ack_num, flags (syn,ack,...), sack_count
    FMT = '!6I'
    FMT_SACK_BLOCK = '!2I'
    F_SYN = 0
    F_ACK = 1
    MAX_SACK_COUNT = 4

    @classmethod
    def generate_id(cls):
        return random.randint(0, 2**32 - 1)

    def __init__(self, seq_num, ack_num, syn, ack, sack_count=0, sack_blocks=None, payload_size=0, seg_id=None):
        if seg_id == None:
            seg_id = MyTCPHeader.generate_id()
        
        self.seg_id = seg_id
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
            self.seg_id,
            self.payload_size,
            self.seq_num,
            self.ack_num,
            flags,
            self.sack_count
        )
        if self.sack_blocks:
            if len(self.sack_blocks) != self.sack_count:
                raise ValueError(f"{self.sack_blocks} and {self.sack_count} do not match")
            packed_data += b''.join(map(lambda t: struct.pack(
                self.FMT_SACK_BLOCK, t[0], t[1]), self.sack_blocks))
        return packed_data

    @classmethod
    def from_tcp_segment(cls, segment, offset=0):
        unpacked_data = struct.unpack_from(cls.FMT, segment, offset)
        seg_id = unpacked_data[0]
        payload_size = unpacked_data[1]
        seq_num = unpacked_data[2]
        ack_num = unpacked_data[3]
        flags = unpacked_data[4]
        sack_count = unpacked_data[5]
        assert sack_count < cls.MAX_SACK_COUNT
        syn = bool(flags & (1 << cls.F_SYN))
        ack = bool(flags & (1 << cls.F_ACK))
        sack_blocks = [] if sack_count > 0 else None
        for block_idx in range(sack_count):
            sack_blocks.append(struct.unpack_from(
                cls.FMT_SACK_BLOCK, segment, offset + cls.size(block_idx)))
        return cls(seq_num, ack_num, syn, ack, sack_count, sack_blocks, payload_size, seg_id)

    @classmethod
    def size(cls, sack_count=None):
        if sack_count is None:
            sack_count = cls.MAX_SACK_COUNT
        return struct.calcsize(cls.FMT) + sack_count * struct.calcsize(cls.FMT_SACK_BLOCK)
    
    def header_size(self):
        return MyTCPHeader.size(sack_count=self.sack_count)
    
    def __repr__(self):
        return str(self.__dict__)

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
            
            # logging.debug(f"({self.__class__.__name__}) data = {data[:10]}..., size = {size}")

            if self.length < begin + size:
                self.buffer += b'\x00' * (begin + size - self.length)
                # logging.debug(f"Extended buf to {self.buffer}")
                self.length = begin + size

            # logging.debug(f"Buffer was {self.buffer}")
            self.buffer = self.buffer[:begin] + data + self.buffer[begin + size:]
            # logging.debug(f"Inserted into buf to {self.buffer}")
            
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
    
    def get_ack_num(self):
        missing = self.present_segments.get_missing(max_count=1)
        if len(missing):
            return missing[0][0]
        else:
            return self.length       

    def get_next(self, count):
        with self.enough:
            if self.wait_end is not None:
                raise Exception("Double get on IncomingBuffer")

            self.wait_end = self.wait_begin + count

            # logging.debug(f"Waiting: b={self.wait_begin}, e={self.wait_end}...")
            self.enough.wait_for(lambda: self.present_segments.contains(
                self.wait_begin, self.wait_end))

            # logging.debug(f"Waiting is over: len={self.length}, buf={self.buffer}")
            data = self.buffer[self.wait_begin:self.wait_end]
            self.wait_begin = self.wait_end
            self.wait_end = None
            return data
    
    def __repr__(self):
        with self.lock:
            return f"{{length = {self.length}, ps = {self.present_segments}, wb = {self.wait_begin}, we = {self.wait_end}}}"

class OutcomingBuffer(Buffer):
    def __init__(self):
        super().__init__()
        self.window_changed = threading.Condition(self.lock)

    def put(self, data):
        size = len(data)
        return super().put(data, size)

    def acknowledge(self, left, right):
        with self.lock:
            old_window_start = self.window_begin()
            self.present_segments.put(left, right)
            if old_window_start != self.window_begin():
                self.window_changed.notify()
    
    def is_acknowledged(self, left, right):
        with self.lock:
            return self.present_segments.contains(left, right)
    
    def window_begin(self):
        missing = self.present_segments.get_missing(max_count=1)
        if len(missing):
            return missing[0][0]
        else:
            return self.length
    
    def wait_window_change(self, window_begin):
        with self.window_changed:
            self.window_changed.wait_for(lambda: window_begin != self.window_begin())
            return window_begin, self.window_begin()
    
    def __repr__(self):
        with self.lock:
            return f"{{length = {self.length}, ps = {self.present_segments}}}"

class MyTCPProtocol(UDPBasedProtocol):
    IP_HEADER_SIZE = 60
    MTU = 65536 - IP_HEADER_SIZE - MyTCPHeader.size()
    WINDOW_SIZE = MTU * 16
    DELAY = 0.15

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identy = get_identy()
        self.closed = False
        self.listen_thread = threading.Thread(target=self.listening_loop_)
        self.transmission_thread = threading.Thread(
            target=self.transmission_loop_)
        self.incoming_buffer = IncomingBuffer()
        self.outcoming_buffer = OutcomingBuffer()
        self.write_queue = queue.PriorityQueue()
        self.closed_lock = threading.Lock()

        self.listen_thread.start()
        self.transmission_thread.start()
        self.debug_(f"Created")

    def debug_(self, msg):
        where = next(traceback.walk_stack(None))[0]
        t = time.time()
        ct = time.gmtime(t)
        msg = f"<{self.identy}> [{time.strftime('%H:%M:%S', ct)}+{t - int(t):.03}] {{{where.f_code.co_filename.split('/')[-1]}:{where.f_lineno} ({where.f_code.co_name})}}: {msg}"
        logger.debug(msg)
    
    def info_(self, msg):
        where = next(traceback.walk_stack(None))[0]
        t = time.time()
        ct = time.gmtime(t)
        msg = f"<{self.identy}> [{time.strftime('%H:%M:%S', ct)}+{t - int(t):.03}] {{{where.f_code.co_filename.split('/')[-1]}:{where.f_lineno} ({where.f_code.co_name})}}: {msg}"
        logger.info(msg)
    
    def critical_(self, msg):
        where = next(traceback.walk_stack(None))[0]
        t = time.time()
        ct = time.gmtime(t)
        msg = f"<{self.identy}> [{time.strftime('%H:%M:%S', ct)}+{t - int(t):.03}] {{{where.f_code.co_filename.split('/')[-1]}:{where.f_lineno} ({where.f_code.co_name})}}: {msg}"
        logger.critical(msg)

    @classmethod
    def build_segment(cls, header: MyTCPHeader, payload: bytes | None = None) -> bytes:
        if payload is not None:
            header.payload_size = len(payload)
        segment = header.to_bytes()
        if payload is not None:
            segment += payload

        return segment

    @classmethod
    def parse_segment(cls, segment: bytes) -> tuple[MyTCPHeader, bytes]:
        header = MyTCPHeader.from_tcp_segment(segment)
        if header.header_size() == len(segment):
            return header, b''       

        return header, segment[header.header_size():]

    def process_incoming_segment_(self, header: MyTCPHeader, data: bytes | None):
        if header.ack:
            self.outcoming_buffer.acknowledge(0, header.ack_num)
            self.debug_(f"Ack on {header.ack_num}")
        if header.sack_count > 0:
            for (left, right) in header.sack_blocks:
                self.outcoming_buffer.acknowledge(left, right)
                self.debug_(f"SAck on [{left}, {right}]")
        if header.payload_size > 0:
            self.incoming_buffer.put(data, header.payload_size, header.seq_num)
            self.debug_(f"Incoming data [{header.seq_num}, {header.seq_num + header.payload_size}) -- {data[:10]}...")
            self.send_acknowledgement_()

    def listening_loop_(self):
        while not self.is_closed():
            try:
                self.debug_(f"Listening...")
                segment = self.recvfrom(self.MTU)
                self.debug_(f"Received")
                header, data = self.parse_segment(segment)
                self.debug_(f"Parsed segment with len={len(segment)}, header={header} () and data={data[:10]}... (sz={len(data)})")
                self.process_incoming_segment_(header, data)
            except socket.timeout as e:
                self.critical_(f"Listening socket timeout: {e}")
                continue
            except socket.error as e:
                self.critical_(f"Listening socket exc: {e}")
                break
            except Exception as e:
                self.critical_(f"Exception: {e}")
                continue
        self.info_(f"Quit listening")

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
            except socket.error as e:
                self.critical_(f"Transmission socket exc: {e}")
                break
            except Exception as e:
                self.critical_(f"Transmission exception: {e}")
                continue
        
        self.info_(f"Quit transmission")
    
    def retransmit_(self, segment, begin, end):
        if self.outcoming_buffer.is_acknowledged(begin, end):
            self.debug_(f"Retransmission cancelled [{begin}, {end})")
            return
        
        self.debug_(f"Retransmission [{begin}, {end})")
        self.send_segment_(segment)
        self.shedule_retransmission_(segment, begin, end)

    def send_acknowledgement_(self):
        ack_num = self.incoming_buffer.get_ack_num()
        # TODO: selective ack
        self.debug_(f"Send ack {ack_num}")
        self.send_segment_(self.build_segment(MyTCPHeader(0, ack_num, False, True)))
    
    def send_segment_(self, segment: bytes):
        super().sendto(segment)
    
    def send_part_(self, data: bytes):
        begin, end = self.outcoming_buffer.put(data)
        header = MyTCPHeader(begin, 0, False, False, payload_size=end-begin)
        segment = self.build_segment(header, data)
        self.debug_(f"Built segment with len={len(segment)}, header={header} () and data={data[:10]}... (sz={len(data)})")
        self.send_segment_(segment)
        self.shedule_retransmission_(segment, begin, end)
        self.debug_(f"Send part [{begin}, {end})")
        return len(data)
    
    def shedule_task_(self, task, delay):
        self.write_queue.put((time.monotonic() + delay, task))
    
    def shedule_retransmission_(self, segment, begin, end, delay=None):
        if delay is None:
            delay = self.DELAY

        self.shedule_task_(lambda: self.retransmit_(segment, begin, end), delay)

    def send(self, data: bytes):
        old_data = data
        self.debug_(f"Send {len(data)} bytes ({data[:10]}...)")
        window_begin = self.outcoming_buffer.window_begin()
        window_final = window_begin + len(data)
        total = 0
        window_end = window_begin
        while window_begin != window_final:
            # Насыщение окна
            while window_end != window_final and window_end - window_begin < self.WINDOW_SIZE:
                piece = data[:self.MTU]
                piece_size = self.send_part_(piece)
                total += piece_size
                window_end += piece_size
                data = data[self.MTU:]
            
            # Сдвиг левой части
            _, new_window_begin = self.outcoming_buffer.wait_window_change(window_begin)
            self.debug_(f"new_window_begin = {new_window_begin}, window_begin = {window_begin}")
            assert new_window_begin - window_begin > 0
            window_begin = new_window_begin
        
        # window_begin == window_final --- все дошли
        self.info_(f"Sent all {total} bytes {old_data[:10]}...")
        return total

    def recv(self, n: int):
        self.debug_(f"Receiving {n} bytes")
        data = self.incoming_buffer.get_next(n)
        self.info_(f"Received all {n} bytes ({data[:10]}...)")
        return data

    def is_closed(self):
        with self.closed_lock:
            return self.closed

    def close(self):
        self.info_("Closing...")
        # logger.setLevel(logging.DEBUG)
        super().close()
        with self.closed_lock:
            self.closed = True
        self.listen_thread.join()
        self.transmission_thread.join()
        self.info_("Closed")
