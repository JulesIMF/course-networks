# from protocol import MyTCPProtocol, Buffer

# ps = Buffer.PresentSegments()

import threading

class Lol:
    def __init__(self):
        self.thread = threading.Thread(target=self.lol)
        self.thread.start()

    def lol(self):
        print(id(self))

    def stop(self):
        self.thread.join()

lol = Lol()
lol.stop()
exit()

# while True:
#     l, r = tuple(map(int, (input().split(' '))))
#     ps.put(l, r)
#     print(ps)
#     print(ps.get_missing())

