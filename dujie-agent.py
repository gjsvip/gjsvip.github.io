#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
渡劫code 执行代理（dujie-agent.py，架构文档 §3.4 #43 / §8.1）。

在你自己的 Linux 服务器上运行，通过 WSS 主动外连 Cloudflare Worker 的
Durable Object（TerminalRoom），收发 JSON 行协议（§5.4）：

    hello / exec / spawn / data / resize / kill / exit / error / ping / pong

设计要点（§8.1）：
  - 零依赖：不依赖 websockets 库，自实现 RFC6455 最小客户端
    （socket + ssl + 帧编解码，客户端帧必须掩码）；
  - exec：subprocess shell=True，stdout/stderr 合并，按 64KB 分块
    base64 经 data 帧回传，结束发 exit{code}；默认超时 60s；
  - spawn：pty.openpty + /bin/bash，读线程分块回传，resize 用
    fcntl.ioctl(TIOCSWINSZ)，kill 杀进程组；
  - 心跳：每 30s 发 ping，90s 未收到 pong 判定断线；
  - 重连：指数退避 1s → 2s → … → 30s 封顶；重连成功后 DO 房间不变，
    已 spawn 的 shell 进程在服务器侧保留，浏览器重连即可恢复；
  - --print-systemd：输出 Restart=always 的 unit 文本；
  - SIGTERM / SIGINT：优雅退出（终止全部 spawn 会话并关闭连接）。

用法：
    python3 dujie-agent.py --server wss://dujiecode.dujie-nb.workers.dev \
        --backend-id bk_xxx --token djt_xxx
    python3 dujie-agent.py --print-systemd ...   # 打印 systemd unit
"""

import argparse
import base64
import fcntl
import json
import os
import platform as platform_mod
import pty
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.parse

# ---- 常量（§8.1） ----
VERSION = '1.0.0'
CHUNK_SIZE = 64 * 1024          # exec / spawn 输出分块大小（字节）
PING_INTERVAL = 30              # 心跳间隔（秒）
PONG_TIMEOUT = 90               # 多久未收 pong 判定断线（秒）
EXEC_DEFAULT_TIMEOUT = 60       # exec 默认超时（秒）
RECONNECT_MIN = 1.0             # 重连退避下限（秒）
RECONNECT_MAX = 30.0            # 重连退避上限（秒）
SOCKET_TIMEOUT = 10             # 握手阶段 socket 超时（秒）
RECV_POLL_SEC = 1.0             # 接收循环轮询粒度（秒）


def log(*parts):
    """带时间戳的日志输出（行缓冲，便于 systemd  journal 采集）"""
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *parts, flush=True)


class WsError(Exception):
    """WebSocket 协议或连接错误"""


class MiniWebSocket:
    """RFC6455 最小 WebSocket 客户端（仅客户端角色，stdlib 实现）

    只实现本代理所需子集：文本帧收发、分片重组、ping/pong、close；
    客户端发送的帧必须带掩码（RFC6455 §5.3），接收帧不校验掩码。
    """

    def __init__(self, url, timeout=SOCKET_TIMEOUT):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'wss':
            raise WsError('仅支持 wss:// 安全连接：%s' % url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or '/'
        if parsed.query:
            self.path += '?' + parsed.query
        self.timeout = timeout
        self.sock = None
        self._recv_buffer = b''

    def connect(self):
        """TCP + TLS + HTTP Upgrade 握手（101 后即就绪）"""
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock.settimeout(self.timeout)

        # 握手请求：16 字节随机数 base64 作为 Sec-WebSocket-Key
        key = base64.b64encode(os.urandom(16)).decode('ascii')
        handshake = (
            'GET %s HTTP/1.1\r\n'
            'Host: %s:%d\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\n'
            'Sec-WebSocket-Version: 13\r\n'
            '\r\n'
        ) % (self.path, self.host, self.port, key)
        self.sock.sendall(handshake.encode('ascii'))

        # 读取响应头（以空行结束）；最小客户端不校验 Accept，仅校验 101
        header = b''
        while b'\r\n\r\n' not in header:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WsError('握手阶段连接被关闭')
            header += chunk
        status_line = header.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        if ' 101 ' not in status_line:
            raise WsError('WebSocket 握手失败：%s' % status_line)
        # 响应头之后可能紧跟帧数据，缓存多余字节
        extra = header.split(b'\r\n\r\n', 1)[1]
        if extra:
            self._recv_buffer = extra

    def send_text(self, text):
        """发送一条文本消息（单帧，FIN=1）"""
        self._send_frame(0x1, text.encode('utf-8'))

    def _send_frame(self, opcode, payload):
        """发送单帧：FIN + opcode，长度三档编码，客户端掩码"""
        header = bytearray()
        header.append(0x80 | opcode)
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack('>H', length)
        else:
            header.append(0x80 | 127)
            header += struct.pack('>Q', length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _recv_exact(self, n):
        """精确读取 n 字节（含已缓存数据）"""
        while len(self._recv_buffer) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WsError('连接已关闭')
            self._recv_buffer += chunk
        data = self._recv_buffer[:n]
        self._recv_buffer = self._recv_buffer[n:]
        return data

    def _recv_frame(self):
        """读取一个 WebSocket 帧，返回 (fin, opcode, payload)"""
        head = self._recv_exact(2)
        fin = (head[0] & 0x80) != 0
        opcode = head[0] & 0x0F
        masked = (head[1] & 0x80) != 0
        length = head[1] & 0x7F
        if length == 126:
            length = struct.unpack('>H', self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack('>Q', self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b''
        if mask is not None:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    def recv_message(self):
        """接收一条完整消息：自动重组分片，处理 ping/pong/close 控制帧"""
        parts = []
        while True:
            fin, opcode, payload = self._recv_frame()
            if opcode == 0x8:  # close：对端关闭
                raise WsError('服务器关闭了连接')
            if opcode == 0x9:  # ping → 回 pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong：由 pump 记录心跳
                return b'__pong__'
            if opcode in (0x1, 0x2):  # text / binary：消息首帧
                parts = [payload]
            elif opcode == 0x0:  # continuation：分片后续
                parts.append(payload)
            else:
                continue
            if fin:
                return b''.join(parts)

    def close(self):
        """发送 close 帧并关闭 socket（尽力而为）"""
        if self.sock is not None:
            try:
                self._send_frame(0x8, struct.pack('>H', 1000))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class DujieAgent:
    """执行代理主体：连接 / 收发 / exec / spawn / 心跳 / 重连"""

    def __init__(self, server, backend_id, token):
        self.server = server.rstrip('/')
        self.backend_id = backend_id
        self.token = token
        self.ws = None
        self.stop_event = threading.Event()
        self.last_pong = time.monotonic()
        # spawn 会话表：id -> {'proc': Popen, 'master': fd}
        self.spawns = {}
        self.spawn_lock = threading.Lock()
        self.hostname = socket.gethostname()

    # ---------------- 连接与主循环 ----------------

    def connect_url(self):
        """代理连接地址（token 经查询参数传递，DO 内做哈希校验）"""
        query = urllib.parse.urlencode(
            {'backendId': self.backend_id, 'token': self.token}
        )
        return '%s/api/agent/connect?%s' % (self.server, query)

    def run(self):
        """主循环：连接 → 收发 → 断线指数退避重连（1s → 30s 封顶）

        心跳线程按连接绑定：每轮结束（重连前）先 stop.set() 并 join()
        旧线程，避免每次重连泄漏一个常驻心跳线程（旧线程还会经新 ws 发 ping）。
        """
        backoff = RECONNECT_MIN
        heartbeat = None
        heartbeat_stop = None
        while not self.stop_event.is_set():
            try:
                self.ws = MiniWebSocket(self.connect_url(), timeout=SOCKET_TIMEOUT)
                self.ws.connect()
                log('已连接 %s（backend %s）' % (self.server, self.backend_id))
                self.last_pong = time.monotonic()
                backoff = RECONNECT_MIN
                # 连接首帧：hello 自述
                self.send_json({
                    'type': 'hello',
                    'version': VERSION,
                    'hostname': self.hostname,
                    'platform': platform_mod.platform(),
                })
                # 心跳线程绑定本连接的停止事件，重连时旧线程先退出
                heartbeat_stop = threading.Event()
                heartbeat = threading.Thread(
                    target=self.heartbeat_loop,
                    args=(heartbeat_stop,),
                    daemon=True,
                )
                heartbeat.start()
                self.pump()
            except (WsError, OSError) as exc:
                log('连接中断：', exc)
            finally:
                # 先停心跳并回收旧线程，再关 socket，防止线程泄漏
                if heartbeat_stop is not None:
                    heartbeat_stop.set()
                if heartbeat is not None:
                    heartbeat.join()
                    heartbeat = None
                self.cleanup_socket()
            if self.stop_event.is_set():
                break
            log('%.0f 秒后重连…' % backoff)
            if self.stop_event.wait(backoff):
                break
            backoff = min(backoff * 2, RECONNECT_MAX)
        self.shutdown()

    def pump(self):
        """接收循环：解析 JSON 行协议帧并分发；pong 超时判定断线"""
        self.ws.sock.settimeout(RECV_POLL_SEC)
        while not self.stop_event.is_set():
            try:
                raw = self.ws.recv_message()
            except socket.timeout:
                # 轮询粒度内无数据：检查心跳超时
                if time.monotonic() - self.last_pong > PONG_TIMEOUT:
                    raise WsError('%d 秒未收到心跳响应，判定断线' % PONG_TIMEOUT)
                continue
            if raw == b'__pong__':
                self.last_pong = time.monotonic()
                continue
            if not raw:
                continue
            try:
                msg = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                continue
            if not isinstance(msg, dict):
                continue
            self.handle_message(msg)

    def heartbeat_loop(self, stop_event):
        """心跳线程：每 30s 发 ping；发送失败即连接已断。

        stop_event 为本次连接专属的停止事件：重连时由 run() 置位，
        旧线程据此退出，不会继续经新连接发 ping。
        """
        while not stop_event.is_set():
            if stop_event.wait(PING_INTERVAL):
                break
            if not self.send_json({'type': 'ping'}):
                return

    def cleanup_socket(self):
        """关闭当前 WebSocket（重连前调用）"""
        if self.ws is not None:
            self.ws.close()
            self.ws = None

    def send_json(self, obj):
        """发送一帧 JSON 行协议消息；连接断开时返回 False"""
        if self.ws is None:
            return False
        try:
            self.ws.send_text(json.dumps(obj, ensure_ascii=False))
            return True
        except (WsError, OSError):
            return False

    def send_data(self, session_id, payload):
        """输出按 64KB 分块 base64 经 data 帧回传；断开返回 False"""
        for i in range(0, len(payload), CHUNK_SIZE):
            chunk = payload[i:i + CHUNK_SIZE]
            ok = self.send_json({
                'type': 'data',
                'id': session_id,
                'data': base64.b64encode(chunk).decode('ascii'),
            })
            if not ok:
                return False
        return True

    # ---------------- 消息分发 ----------------

    def handle_message(self, msg):
        """按 type 分发（§5.4 协议表）"""
        mtype = msg.get('type')
        if mtype == 'exec':
            # exec 放独立线程，避免长命令阻塞接收循环
            threading.Thread(target=self.handle_exec, args=(msg,), daemon=True).start()
        elif mtype == 'spawn':
            self.handle_spawn(msg)
        elif mtype == 'data':
            self.handle_data(msg)
        elif mtype == 'resize':
            self.handle_resize(msg)
        elif mtype == 'kill':
            self.handle_kill(msg)
        elif mtype == 'pong':
            self.last_pong = time.monotonic()
        elif mtype == 'ping':
            self.send_json({'type': 'pong'})

    # ---------------- exec：一次性命令 ----------------

    def handle_exec(self, msg):
        """执行一次性命令：shell=True，输出分块回传，结束发 exit"""
        exec_id = msg.get('id', '')
        command = msg.get('command', '')
        timeout = msg.get('timeoutSec')
        try:
            timeout = float(timeout) if timeout else EXEC_DEFAULT_TIMEOUT
        except (TypeError, ValueError):
            timeout = EXEC_DEFAULT_TIMEOUT
        if timeout <= 0:
            timeout = EXEC_DEFAULT_TIMEOUT

        try:
            proc = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            self.send_json({'type': 'error', 'id': exec_id, 'message': '命令启动失败：%s' % exc})
            self.send_json({'type': 'exit', 'id': exec_id, 'code': 127})
            return

        deadline = time.monotonic() + timeout
        fd = proc.stdout.fileno()
        timed_out = False
        while True:
            if proc.poll() is not None:
                # 进程已结束：读净管道剩余输出
                while True:
                    try:
                        chunk = os.read(fd, CHUNK_SIZE)
                    except OSError:
                        chunk = b''
                    if not chunk:
                        break
                    if not self.send_data(exec_id, chunk):
                        return
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                ready, _, _ = select.select([fd], [], [], min(1.0, remaining))
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                chunk = os.read(fd, CHUNK_SIZE)
            except OSError:
                chunk = b''
            if not chunk:
                proc.wait()
                continue
            if not self.send_data(exec_id, chunk):
                return

        if timed_out:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
            self.send_json({
                'type': 'error', 'id': exec_id,
                'message': '命令超时（%d 秒），已强制终止' % int(timeout),
            })

        code = proc.returncode if proc.returncode is not None else -1
        self.send_json({'type': 'exit', 'id': exec_id, 'code': code})

    # ---------------- spawn：交互式 shell（PTY） ----------------

    def handle_spawn(self, msg):
        """启动交互式 shell：pty.openpty + /bin/bash，独立进程组"""
        spawn_id = msg.get('id', '')
        cols = int(msg.get('cols') or 80)
        rows = int(msg.get('rows') or 24)
        cmd = msg.get('cmd') or '/bin/bash'

        with self.spawn_lock:
            old = self.spawns.get(spawn_id)
        if old is not None:
            # 同 id 重入（浏览器重连后重发 spawn）：终止旧 shell，
            # 旧读线程负责清理与 exit 通知，避免输出重复
            self._kill_process_group(old['proc'])

        master, slave = pty.openpty()
        # 初始窗口大小（TIOCSWINSZ）
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass
        env = dict(os.environ, TERM='xterm-256color', COLUMNS=str(cols), LINES=str(rows))
        try:
            proc = subprocess.Popen(
                [cmd], stdin=slave, stdout=slave, stderr=slave,
                env=env, start_new_session=True,
            )
        except OSError as exc:
            os.close(master)
            os.close(slave)
            self.send_json({'type': 'error', 'id': spawn_id, 'message': '启动 shell 失败：%s' % exc})
            return
        os.close(slave)

        with self.spawn_lock:
            self.spawns[spawn_id] = {'proc': proc, 'master': master}
        threading.Thread(
            target=self._pump_spawn, args=(spawn_id, master, proc), daemon=True
        ).start()

    def _pump_spawn(self, spawn_id, master, proc):
        """读线程：PTY 输出分块 base64 回传；进程退出发 exit"""
        try:
            while True:
                try:
                    chunk = os.read(master, CHUNK_SIZE)
                except OSError:
                    break  # PTY 关闭（子进程退出）
                if not chunk:
                    break
                if not self.send_data(spawn_id, chunk):
                    return
        finally:
            code = proc.wait()
            try:
                os.close(master)
            except OSError:
                pass
            with self.spawn_lock:
                self.spawns.pop(spawn_id, None)
            self.send_json({'type': 'exit', 'id': spawn_id, 'code': code})

    def handle_data(self, msg):
        """stdin 写入（base64 解码后写入 PTY master）"""
        spawn_id = msg.get('id', '')
        with self.spawn_lock:
            entry = self.spawns.get(spawn_id)
        if entry is None:
            return
        try:
            payload = base64.b64decode(msg.get('data', ''))
            os.write(entry['master'], payload)
        except (OSError, ValueError):
            pass

    def handle_resize(self, msg):
        """调整 PTY 窗口大小（fcntl.ioctl TIOCSWINSZ）"""
        spawn_id = msg.get('id', '')
        cols = int(msg.get('cols') or 80)
        rows = int(msg.get('rows') or 24)
        with self.spawn_lock:
            entry = self.spawns.get(spawn_id)
        if entry is None:
            return
        try:
            fcntl.ioctl(entry['master'], termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass

    def handle_kill(self, msg):
        """终止会话：杀进程组（读线程负责 exit 通知与清理）"""
        spawn_id = msg.get('id', '')
        with self.spawn_lock:
            entry = self.spawns.get(spawn_id)
        if entry is None:
            return
        self._kill_process_group(entry['proc'])

    def _kill_process_group(self, proc):
        """杀进程组：SIGTERM 优雅退出，3 秒后 SIGKILL 强杀"""
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
                return
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                proc.wait(timeout=3)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass

    # ---------------- 退出 ----------------

    def stop(self, *_args):
        """SIGTERM / SIGINT：置位停止标志（主循环负责清理）"""
        log('收到退出信号')
        self.stop_event.set()

    def shutdown(self):
        """优雅退出：终止全部 spawn 会话并关闭连接"""
        log('正在退出…')
        with self.spawn_lock:
            entries = list(self.spawns.values())
        for entry in entries:
            self._kill_process_group(entry['proc'])
        self.cleanup_socket()
        log('已退出')


def systemd_unit(server, backend_id, token):
    """输出 Restart=always 的 systemd unit（用户自行 systemctl enable）"""
    script = os.path.abspath(__file__)
    user = os.environ.get('USER') or os.environ.get('LOGNAME') or 'root'
    return '''[Unit]
Description=渡劫code 执行代理（backend %s）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 注意：token 以明文写入 unit 文件，请限制文件权限（chmod 600）
ExecStart=/usr/bin/env python3 %s --server %s --backend-id %s --token %s
Restart=always
RestartSec=5
User=%s
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
''' % (backend_id, script, server, backend_id, token, user)


def main():
    parser = argparse.ArgumentParser(
        description='渡劫code 执行代理（Python3 单文件，stdlib 零依赖）'
    )
    parser.add_argument('--server', required=True,
                        help='Worker 地址，如 wss://dujiecode.dujie-nb.workers.dev')
    parser.add_argument('--backend-id', required=True,
                        help='执行后端 ID（bk_ 开头，设置页创建）')
    parser.add_argument('--token', required=True,
                        help='agent token（djt_ 开头，创建时仅展示一次）')
    parser.add_argument('--print-systemd', action='store_true',
                        help='打印 systemd unit 文本后退出')
    args = parser.parse_args()

    if args.print_systemd:
        print(systemd_unit(args.server, args.backend_id, args.token))
        return 0

    agent = DujieAgent(args.server, args.backend_id, args.token)
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
