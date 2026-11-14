"""Bounded worker server shared by protocol implementations."""
import socketserver
import threading


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = False
    block_on_close = True

    def setup_limits(self, limit):
        self.slots = threading.BoundedSemaphore(limit)
        self.stopping = threading.Event()
        self.active = set()
        self.active_lock = threading.Lock()

    def process_request(self, request, client_address):
        if self.stopping.is_set() or not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.active_lock:
            self.active.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()

    def stop(self):
        self.stopping.set()
        self.shutdown()
        with self.active_lock:
            for connection in self.active:
                try:
                    connection.shutdown(2)
                except OSError:
                    pass
                connection.close()
        self.server_close()
