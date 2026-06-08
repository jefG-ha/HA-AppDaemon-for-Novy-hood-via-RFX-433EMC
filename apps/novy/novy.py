"""
Novy hood control via RFXtrx (WiFi) for AppDaemon.

Exposes two HA entities:
  - fan.novy           : on/off + speed (Low / Medium / High / Boost)
  - light.novy_light   : on/off (toggle)

Talks to an RFXtrx over plain TCP using the FAN protocol, subtype Novy.
Commands (byte 8):
    0x01 = Power (toggle fan on/off, keeps speed)
    0x02 = Speed up   (+)
    0x03 = Speed down (-)
    0x04 = Light toggle
"""

import appdaemon.plugins.hass.hassapi as hass
import socket
import threading
import time


# Fixed packet skeleton: [len, type=0x17, subtype=0x0B, seq, id1, id2, id3, cmd, filler]
# id1..id3 are the hood ID (default Novy code = 0x00 0x00 0x00)
def _pkt(cmd: int, hood_id: bytes = b"\x00\x00\x00", seq: int = 1) -> bytes:
    assert len(hood_id) == 3
    return bytes([0x08, 0x17, 0x0B, seq & 0xFF]) + hood_id + bytes([cmd, 0x00])


CMD_POWER = 0x01
CMD_UP    = 0x02
CMD_DOWN  = 0x03
CMD_LIGHT = 0x04
HOOD_ID = "000000"  # default Novy code, override with your hood's ID if different

# Set Mode command (Interface Control, type 0x00, subtype 0x00).
# RFXCOM support confirmed this exact byte sequence enables undec ON
# and HomeConfort/Fan, and that undec MUST be re-sent after every RFX
# restart since it always reverts to OFF on power-up.
#   length=0x0D, type=0x00, sub=0x00, seq=??, cmd=0x03 (Set Mode),
#   transceiver=0x53, freq=0x1C (433.92), msg3=0x80 (undec on),
#   msg4=0x00, msg5=0x00, msg6=0x02 (HomeConfort/Fan),
#   msg7=0x00, msg8=0x00, reserved=0x00, 0x00.
# The sequence byte (index 3) is filled in at send time.
SET_MODE_TEMPLATE = bytes([
    0x0D, 0x00, 0x00, 0x00, 0x03, 0x53, 0x1C,
    0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
])

# A single remote press emits multiple identical bursts ~150-300ms apart.
# 500ms catches all repeats of one press while still allowing a deliberate
# second press ~1 second later to register as a new event.
REMOTE_DEDUP_WINDOW = 0.5  # seconds

# Keepalive tuning
KEEPALIVE_INTERVAL = 60.0    # send a status request every N seconds
RX_SILENCE_TIMEOUT = 180.0   # if no RX for this long, force a reconnect

# RFXtrx interface-control packet: get status
# Layout: [len=0x0D, type=0x00, subtype=0x00, seq, cmd=0x02, msg1..msg9]
def _status_pkt(seq: int = 1) -> bytes:
    return bytes([0x0D, 0x00, 0x00, seq & 0xFF, 0x02]) + bytes(9)


class NovyHoodControl(hass.Hass):

    def initialize(self):
        # Hood / entity settings
        self.hood_name      = self.args["hood"]["name"]                # e.g. fan.novy
        self.hood_pretty    = self.args["hood"]["friendly_name"]
        self.light_name     = self.args["hood"].get("light_name", "light.novy_light")
        self.light_pretty   = self.args["hood"].get("light_friendly_name", "Novy Light")
        # 3-byte hood ID. Defaults to 000000 which matches a factory-default
        # Novy 840029 remote. Override in apps.yaml with `id: AABBCC`.
        self.hood_id        = bytes.fromhex(self.args["hood"].get("id", HOOD_ID))
        # If True, watch the periodic status replies from the RFX. If undec
        # is disabled (e.g. after a firmware reset or self-clear), send a
        # Set Mode command to turn it back on while preserving the other
        # protocol enables. This is needed for our particular Novy hood
        # because some bursts decode only when undec is on.
        self.keep_undec_on = bool(self.args["hood"].get("keep_undec_on", True))

        # HA Fan entity model (modern, post-2021):
        #   bit 0 (SET_SPEED, value 1) = legacy speed support, deprecated
        #   bit 3 (PRESET_MODE, value 8) = preset modes (what we use)
        # We expose the four hood speeds as preset modes so HA's automations
        # and UI work natively. We also report a percentage so cards that
        # only know about percentage can still drive the fan.
        self.supported_features = 8  # SUPPORT_PRESET_MODE
        self.icon = "mdi:pot-steam"
        self.hood_speed_list = ["Low", "Medium", "High", "Boost"]
        self.hood_boost_time = 300  # seconds, lower than the hood's own boost timeout

        # Fan state
        self.hood_state  = "off"                        # 'on' / 'off'
        self.hood_speed  = self.hood_speed_list[0]      # current desired speed
        # 'real_speed' tracks where we believe the hood's internal counter is.
        # 0 = off; otherwise an internal index >= 2 used by control_hood().
        self.real_speed  = 0
        self.in_step     = False                        # True while control_hood is stepping

        # Light state (toggle-only, so we track it ourselves)
        self.light_on = False

        # RFXtrx connection
        self.rfx_host    = self.args["hood"]["host"]
        self.rfx_port    = self.args["hood"].get("port", 10001)
        self.sock        = None
        self.sock_lock   = threading.Lock()
        self.tx_seq      = 0
        self.reader_stop = threading.Event()
        self.reader_thread = None
        self.watchdog_thread = None
        # Last time we received any byte from the RFX. Used by the watchdog
        # to detect silent (half-open) connections.
        self.last_rx = time.monotonic()
        # Track our own transmissions so we don't react to their RX echo
        # as if they came from the physical remote. We stash the next
        # expected (cmd, deadline) tuples here.
        self.self_echo_lock = threading.Lock()
        self.self_echoes: list[tuple[int, float]] = []

        # Dedup repeats from the physical remote: each press emits multiple
        # bursts; we only want to act on the first one.
        self.last_remote_cmd: int = -1
        self.last_remote_at: float = 0.0
        self.remote_lock = threading.Lock()

        self._connect()
        self._start_reader()
        self._start_watchdog()

        self.update_fan_state()
        self.update_light_state()

        self.listen_event(self.on_call_service, event="call_service")
        self.listen_state(
            self.stop_boost,
            self.hood_name,
            attribute="speed",
            new=self.hood_speed_list[-1],
            duration=self.hood_boost_time,
        )

    def terminate(self):
        self.reader_stop.set()
        with self.sock_lock:
            if self.sock is not None:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None

    # ---------- Connection management ----------

    def _connect(self):
        with self.sock_lock:
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            try:
                s = socket.create_connection((self.rfx_host, self.rfx_port), timeout=5)
                s.settimeout(None)
                self.sock = s
                self.last_rx = time.monotonic()
                self.log(f"Connected to RFXtrx at {self.rfx_host}:{self.rfx_port}")
                connected = True
            except OSError as e:
                self.log(f"Failed to connect to RFXtrx: {e}", level="ERROR")
                self.sock = None
                connected = False
        # Outside the lock: send the Set Mode command. Because undec is
        # required for reliable Novy packet capture and because the RFX
        # always reverts undec to OFF on its own restart, we need to (re)
        # apply the setting after every successful connection.
        if connected and self.keep_undec_on:
            self._send_set_mode(reason="connect")

    def _send_cmd(self, cmd: int):
        """Build and send a Novy packet for the given command byte."""
        self.tx_seq = (self.tx_seq + 1) & 0xFF
        payload = _pkt(cmd, self.hood_id, self.tx_seq)
        self._mark_self_echo(cmd)
        self._send_raw(payload)

    def _send_set_mode(self, reason: str = ""):
        """
        Send the RFXCOM-recommended Set Mode command to enable 'undec on'
        and HomeConfort/Fan. Per RFXCOM support, this MUST be re-sent on
        every RFX restart because the firmware always reverts undec to OFF
        on power-up. We send it on every TCP (re)connect and again if a
        status reply shows undec has been disabled.
        """
        self.tx_seq = (self.tx_seq + 1) & 0xFF
        payload = bytearray(SET_MODE_TEMPLATE)
        payload[3] = self.tx_seq
        suffix = f" ({reason})" if reason else ""
        self.log(f"Sending Set Mode to enable undec+Fan{suffix}")
        self._set_mode_sent_at = time.monotonic()
        self._send_raw(bytes(payload))

    def _send_raw(self, payload: bytes, quiet: bool = False):
        for attempt in (1, 2):
            with self.sock_lock:
                sock = self.sock
            if sock is None:
                self._connect()
                with self.sock_lock:
                    sock = self.sock
                if sock is None:
                    return
            try:
                sock.sendall(payload)
                if not quiet:
                    self.log(f"TX: {payload.hex()}")
                return
            except OSError as e:
                self.log(f"Send failed ({e}), reconnecting (attempt {attempt})", level="WARNING")
                with self.sock_lock:
                    if self.sock is sock:
                        try:
                            self.sock.close()
                        except OSError:
                            pass
                        self.sock = None
        if not quiet:
            self.log("Send failed after retry", level="ERROR")

    # ---------- Self-echo bookkeeping ----------
    # When we transmit, the RFXtrx also echoes the received command back
    # over the TCP socket (because it actually goes out over the air and
    # we hear our own transmission). With undec on, we receive *all* the
    # repeat bursts of our own transmission. We don't want to interpret
    # any of those as "the user pressed the physical remote", so we drop
    # them all within a window after our send.

    def _mark_self_echo(self, cmd: int):
        # The RFXtrx echoes back the bursts of our own TX. The full burst
        # cluster from a single TX completes within ~200ms (5 burst repeats
        # at ~30-40ms intervals). We use 300ms as a safe upper bound.
        #
        # Critically, this window must NOT be too long — if a user presses
        # the remote shortly after our own TX (e.g. wanting to nudge the
        # speed up further from what we just commanded), we must not mistake
        # their press for an echo of our TX. 300ms is well below the typical
        # human reaction time + inter-burst gap, so real presses survive.
        with self.self_echo_lock:
            self.self_echoes.append((cmd, time.monotonic() + 0.3))

    def _is_self_echo(self, cmd: int) -> bool:
        """Check if this RX is an echo of our own recent TX. Does NOT consume
        the entry — multiple repeats of the same command should all be matched."""
        now = time.monotonic()
        with self.self_echo_lock:
            # Drop expired entries.
            self.self_echoes = [(c, t) for (c, t) in self.self_echoes if t > now]
            for c, _t in self.self_echoes:
                if c == cmd:
                    return True
        return False

    # ---------- Interface message handling (status replies) ----------

    # Bit 7 of msg3 in the status reply indicates undec on/off.
    # In a status reply (length 0x14 = 20+1), msg3 lives at index 7.
    UNDEC_BIT = 0x80

    # Don't re-issue Set Mode more often than this. Avoids flapping if
    # something else is fighting us, and gives the RFX time to apply the
    # previous Set Mode before we observe its result.
    SET_MODE_MIN_INTERVAL = 30.0  # seconds

    def _handle_interface_message(self, packet: bytes):
        """
        Inspect periodic status replies. If undec is off and we want it on,
        send a Set Mode command to turn it back on. Per RFXCOM support, the
        RFX always reverts undec to OFF on its own restart, so we need to
        keep re-applying the setting whenever we see it has been disabled.

        Also logs a status summary on connect and whenever the protocol-
        enable bytes change, so you can see at a glance what the RFX is
        configured for without spamming the log every keepalive.
        """
        if len(packet) < 14:
            return

        msg3 = packet[7]
        msg4 = packet[8]
        msg5 = packet[9]
        msg6 = packet[10]
        msg7 = packet[11]
        msg8 = packet[12]
        undec_currently_on = bool(msg3 & self.UNDEC_BIT)

        # Status digest: log on first observation and whenever it changes.
        digest = (msg3, msg4, msg5, msg6, msg7, msg8)
        prev_digest = getattr(self, "_status_digest", None)
        if digest != prev_digest:
            self._status_digest = digest
            self.log(
                f"RFX status: undec={'ON' if undec_currently_on else 'off'}, "
                f"msg3-8={msg3:02X} {msg4:02X} {msg5:02X} "
                f"{msg6:02X} {msg7:02X} {msg8:02X}"
            )

        if not self.keep_undec_on:
            return

        # Track transitions for clearer logging
        prev = getattr(self, "_undec_was_on", None)
        self._undec_was_on = undec_currently_on

        if undec_currently_on:
            if prev is False:
                self.log("Undec is now ON in RFX (Set Mode took effect).")
            return

        # Undec is off. Decide whether to re-issue Set Mode now.
        last_sent = getattr(self, "_set_mode_sent_at", 0.0)
        elapsed = time.monotonic() - last_sent
        if elapsed < self.SET_MODE_MIN_INTERVAL:
            # We sent Set Mode recently; the RFX may not have applied it
            # yet, or the previous Set Mode did not take. Wait before
            # retrying to avoid spamming.
            return

        if prev is True:
            reason = "undec turned OFF, restoring"
            level = "WARNING"
        else:
            reason = "undec is OFF, enabling"
            level = "INFO"
        self.log(f"Status: {reason} (msg3=0x{msg3:02X})", level=level)
        self._send_set_mode(reason=reason)


    def _start_reader(self):
        self.reader_stop.clear()
        self.reader_thread = threading.Thread(
            target=self._reader_loop, name="novy-rfxtrx-reader", daemon=True
        )
        self.reader_thread.start()

    def _start_watchdog(self):
        self.watchdog_thread = threading.Thread(
            target=self._watchdog_loop, name="novy-rfxtrx-watchdog", daemon=True
        )
        self.watchdog_thread.start()

    def _watchdog_loop(self):
        """
        Periodically sends a status request to the RFXtrx and watches the
        last_rx timestamp. If the device has been silent for too long, we
        force-close the socket; the reader thread then reconnects.

        Why: TCP doesn't always notice a peer that's gone away (WiFi flap,
        device reboot, half-open connection). Without an active probe we
        could sit on a dead socket indefinitely.
        """
        # Stagger the first probe so we don't fight startup.
        if self.reader_stop.wait(KEEPALIVE_INTERVAL):
            return

        while not self.reader_stop.is_set():
            now = time.monotonic()
            silent_for = now - self.last_rx

            with self.sock_lock:
                have_sock = self.sock is not None

            if have_sock and silent_for > RX_SILENCE_TIMEOUT:
                self.log(
                    f"Watchdog: no RX for {silent_for:.0f}s, forcing reconnect",
                    level="WARNING",
                )
                with self.sock_lock:
                    if self.sock is not None:
                        try:
                            self.sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        try:
                            self.sock.close()
                        except OSError:
                            pass
                        self.sock = None
                # Give the reader a chance to reconnect before checking again.
                if self.reader_stop.wait(KEEPALIVE_INTERVAL):
                    return
                continue

            # Send a status request as a keepalive. The RFX replies with an
            # interface message, which updates last_rx in the reader thread.
            if have_sock:
                self._send_status_probe()

            if self.reader_stop.wait(KEEPALIVE_INTERVAL):
                return

    def _send_status_probe(self):
        """Send a get-status interface command. Used as a TCP keepalive."""
        self.tx_seq = (self.tx_seq + 1) & 0xFF
        payload = _status_pkt(self.tx_seq)
        # Don't log this; it's noisy. The reply will show up in RX as type 0x01.
        self._send_raw(payload, quiet=True)

    def _reader_loop(self):
        while not self.reader_stop.is_set():
            with self.sock_lock:
                sock = self.sock
            if sock is None:
                if self.reader_stop.wait(2.0):
                    return
                self._connect()
                continue
            try:
                length_byte = self._recv_exact(sock, 1)
                if length_byte is None:
                    raise ConnectionError("connection closed by RFXtrx")
                self.last_rx = time.monotonic()
                length = length_byte[0]
                if length == 0:
                    continue
                rest = self._recv_exact(sock, length)
                if rest is None:
                    raise ConnectionError("short read")
                self.last_rx = time.monotonic()
                packet = length_byte + rest
                self._handle_packet(packet)
            except OSError as e:
                if self.reader_stop.is_set():
                    return
                self.log(f"Reader error ({e}); reconnecting...", level="WARNING")
                with self.sock_lock:
                    if self.sock is sock:
                        try:
                            self.sock.close()
                        except OSError:
                            pass
                        self.sock = None
                if self.reader_stop.wait(1.0):
                    return
            except Exception as e:
                # Belt-and-braces: don't let an unexpected error kill the reader.
                if self.reader_stop.is_set():
                    return
                self.log(f"Reader unexpected error ({type(e).__name__}: {e})", level="ERROR")
                if self.reader_stop.wait(1.0):
                    return

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _handle_packet(self, packet: bytes):
        if len(packet) < 2:
            return
        ptype = packet[1]

        # Type 0x01 = Interface Message. Replies to our keepalive Get Status
        # probes contain the current configuration; we use that to detect if
        # undec has been disabled (e.g. after a firmware reset) and re-enable
        # it. We don't log these by default, they are noisy.
        if ptype == 0x01:
            self._handle_interface_message(packet)
            return

        # Type 0x7F = Undecoded RF Message (only seen when 'undec on' is set).
        # These are bursts the firmware decoder rejected — typically RF noise
        # from neighbouring 433 MHz devices that don't match any protocol we
        # have enabled. Not actionable for us; drop silently.
        if ptype == 0x7F:
            return

        self.log(f"RX: {packet.hex()} (type=0x{ptype:02X})")

        # FAN protocol (0x17), Novy subtype (0x0B), correct hood ID
        if (
            ptype == 0x17
            and len(packet) >= 9
            and packet[2] == 0x0B
            and packet[4:7] == self.hood_id
        ):
            cmd = packet[7]
            # Skip echoes of our own transmissions (and their burst repeats)
            if self._is_self_echo(cmd):
                self.log(f"  (ignored self-echo of cmd 0x{cmd:02X})")
                return
            self._handle_remote_press(cmd)

    def _handle_remote_press(self, cmd: int):
        """Called when we observe a packet that didn't originate from us."""
        # A single remote press emits a tight burst of 3-5 packets within
        # ~150-200ms. Subsequent legitimate presses come at least ~500-800ms
        # later (limited by the remote's repeat behaviour). We dedupe by
        # treating any matching command within BURST_WINDOW of the FIRST
        # observed burst as a repeat — without refreshing the timestamp,
        # which would otherwise extend the window indefinitely and suppress
        # rapid legit re-presses.
        now = time.monotonic()
        BURST_WINDOW = 0.35  # seconds, covers ~5 bursts at ~40ms each + jitter
        with self.remote_lock:
            if cmd == self.last_remote_cmd and (now - self.last_remote_at) < BURST_WINDOW:
                self.log(f"  (suppressed repeat of cmd 0x{cmd:02X})")
                return
            self.last_remote_cmd = cmd
            self.last_remote_at = now  # only set on the FIRST burst

        self.log(f"  remote pressed command 0x{cmd:02X}")

        button = None
        if cmd == CMD_POWER:
            button = "power"
            new_state = "off" if self.hood_state == "on" else "on"
            self.hood_state = new_state
            if new_state == "off":
                self.real_speed = 0
            else:
                self.real_speed = self.hood_speed_list.index(self.hood_speed) + 2
            self.update_fan_state(send=False)
            self.log(
                f"  -> fan.novy now state={self.hood_state} speed={self.hood_speed}"
            )
        elif cmd == CMD_UP:
            button = "up"
            prev = (self.hood_state, self.hood_speed)
            self._step_real(+1)
            self.update_fan_state(send=False)
            if (self.hood_state, self.hood_speed) != prev:
                self.log(
                    f"  -> fan.novy now state={self.hood_state} speed={self.hood_speed}"
                )
            else:
                self.log(
                    f"  -> fan.novy already at max (state={self.hood_state} speed={self.hood_speed})"
                )
        elif cmd == CMD_DOWN:
            button = "down"
            prev = (self.hood_state, self.hood_speed)
            self._step_real(-1)
            self.update_fan_state(send=False)
            if (self.hood_state, self.hood_speed) != prev:
                self.log(
                    f"  -> fan.novy now state={self.hood_state} speed={self.hood_speed}"
                )
            else:
                self.log(
                    f"  -> fan.novy already at min (state={self.hood_state} speed={self.hood_speed})"
                )
        elif cmd == CMD_LIGHT:
            button = "light"
            self.light_on = not self.light_on
            self.update_light_state(send=False)
            self.log(
                f"  -> light.novy_light now {'on' if self.light_on else 'off'}"
            )

        # Fire an HA event so automations can react to specific button presses.
        if button is not None:
            self.fire_event(
                "novy_remote",
                button=button,
                cmd=cmd,
                entity_id=self.hood_name,
            )

    def _step_real(self, direction: int):
        """
        Apply a remote UP/DOWN press to our internal state.

        Mapping between real_speed (the rolling counter representing the
        hood's physical state) and the speed list:
            real_speed = 0       → off
            real_speed = 2..N+1  → speed_list[0..N-1]   (Low, Medium, High, Boost)

        The hood has NO intermediate state between off and Low (real_speed=1
        is a phantom). Physically, pressing DOWN at Low turns the hood off
        directly, and pressing UP at off jumps straight to Low. We need to
        mirror that here, otherwise remote presses desync from HA state.
        """
        max_real = len(self.hood_speed_list) + 1   # 5 for 4 speeds: off, _, Low, Med, High, Boost

        if direction > 0:
            # UP: off → Low jumps over the phantom slot
            if self.real_speed == 0:
                new_real = 2
            else:
                new_real = min(self.real_speed + 1, max_real)
        else:
            # DOWN: Low → off jumps over the phantom slot
            if self.real_speed <= 2:
                new_real = 0
            else:
                new_real = self.real_speed - 1

        self.real_speed = new_real
        if new_real == 0:
            self.hood_state = "off"
        else:
            self.hood_state = "on"
            idx = new_real - 2
            self.hood_speed = self.hood_speed_list[idx]

    # ---------- HA service handling ----------

    def on_call_service(self, event_name, data, kwargs):
        domain = data.get("domain")
        service = data.get("service")
        service_data = data.get("service_data", {}) or {}

        target = service_data.get("entity_id")
        if isinstance(target, list):
            targets = set(target)
        elif target is None:
            return
        else:
            targets = {target}

        if domain == "fan" and self.hood_name in targets:
            self.log(f"fan service: {service} data={service_data}")
            self._on_fan_service(service, service_data)
        elif domain == "light" and self.light_name in targets:
            self.log(f"light service: {service} data={service_data}")
            self._on_light_service(service)

    # ---------- Fan service handlers ----------

    def _on_fan_service(self, service: str, service_data: dict):
        """
        Handle modern HA fan services. The fan platform supports:
          turn_on              (with optional percentage / preset_mode)
          turn_off
          toggle
          set_percentage       (percentage: 0..100)
          set_preset_mode      (preset_mode: "Low"/"Medium"/"High"/"Boost")
          increase_speed       (with optional percentage_step)
          decrease_speed       (with optional percentage_step)
        Plus the legacy:
          set_speed            (speed: "Low"/...)  -- deprecated but still seen
        """
        # Pull every speed-ish parameter the call might carry
        requested_preset = (
            service_data.get("preset_mode")
            or service_data.get("speed")  # legacy
        )
        requested_pct = service_data.get("percentage")
        if requested_pct is not None:
            try:
                requested_pct = int(requested_pct)
            except (TypeError, ValueError):
                requested_pct = None

        # Normalize a percentage into a preset name when both are absent
        def desired_speed_from_call():
            if requested_preset in self.hood_speed_list:
                return requested_preset
            if requested_pct is not None and requested_pct > 0:
                return self._percentage_to_speed(requested_pct)
            return None

        if service == "turn_off":
            if self.hood_state == "on":
                self._fan_off()
            return

        if service == "turn_on":
            target = desired_speed_from_call()
            if target is not None:
                self.hood_speed = target
            if self.hood_state == "off":
                self.hood_state = "on"
            self.update_fan_state(send=True)
            return

        if service == "toggle":
            if self.hood_state == "on":
                self._fan_off()
            else:
                target = desired_speed_from_call()
                if target is not None:
                    self.hood_speed = target
                self.hood_state = "on"
                self.update_fan_state(send=True)
            return

        if service == "set_percentage":
            if requested_pct is None:
                return
            if requested_pct <= 0:
                if self.hood_state == "on":
                    self._fan_off()
                return
            self.hood_speed = self._percentage_to_speed(requested_pct)
            if self.hood_state == "off":
                self.hood_state = "on"
            self.update_fan_state(send=True)
            return

        if service in ("set_preset_mode", "set_speed"):
            target = desired_speed_from_call()
            if target is None:
                return
            self.hood_speed = target
            if self.hood_state == "off":
                self.hood_state = "on"
            self.update_fan_state(send=True)
            return

        if service == "increase_speed":
            self._step_speed(+1)
            return

        if service == "decrease_speed":
            self._step_speed(-1)
            return

    def _fan_off(self):
        self.hood_state = "off"
        if self.hood_speed == self.hood_speed_list[-1]:
            # Don't strand the speed on Boost across off/on cycles.
            self.hood_speed = self.hood_speed_list[-2]
        self.update_fan_state(send=True)

    def _step_speed(self, delta: int):
        """Move one preset step up or down. Turning on if needed."""
        if self.hood_state == "off":
            if delta > 0:
                self.hood_speed = self.hood_speed_list[0]
                self.hood_state = "on"
                self.update_fan_state(send=True)
            return
        try:
            idx = self.hood_speed_list.index(self.hood_speed)
        except ValueError:
            idx = 0
        new_idx = idx + delta
        if new_idx < 0:
            self._fan_off()
            return
        if new_idx >= len(self.hood_speed_list):
            new_idx = len(self.hood_speed_list) - 1
        self.hood_speed = self.hood_speed_list[new_idx]
        self.update_fan_state(send=True)

    # ---------- Light service handlers ----------

    def _on_light_service(self, service: str):
        if service == "turn_on" and not self.light_on:
            self._send_cmd(CMD_LIGHT)
            self.light_on = True
            self.update_light_state(send=False)
        elif service == "turn_off" and self.light_on:
            self._send_cmd(CMD_LIGHT)
            self.light_on = False
            self.update_light_state(send=False)
        elif service == "toggle":
            self._send_cmd(CMD_LIGHT)
            self.light_on = not self.light_on
            self.update_light_state(send=False)

    # ---------- State publication ----------

    def _speed_to_percentage(self, speed: str) -> int:
        """Map preset name to a 0..100 percentage for HA cards that use it."""
        try:
            idx = self.hood_speed_list.index(speed)
        except ValueError:
            return 0
        # 4 speeds -> 25, 50, 75, 100
        return int(round((idx + 1) * 100 / len(self.hood_speed_list)))

    def _percentage_to_speed(self, pct: int) -> str:
        """Map 1..100 percentage to the closest preset speed."""
        pct = max(0, min(100, int(pct)))
        if pct <= 0:
            return self.hood_speed_list[0]
        # bucket into len(speed_list) bands
        n = len(self.hood_speed_list)
        idx = min(n - 1, max(0, (pct - 1) * n // 100))
        return self.hood_speed_list[idx]

    def update_fan_state(self, send: bool = True):
        pct = self._speed_to_percentage(self.hood_speed) if self.hood_state == "on" else 0
        self.set_state(
            self.hood_name,
            state=self.hood_state,
            attributes={
                # Modern HA fan attributes
                "preset_modes": self.hood_speed_list,
                "preset_mode": self.hood_speed if self.hood_state == "on" else None,
                "percentage": pct,
                "percentage_step": int(round(100 / len(self.hood_speed_list))),
                "supported_features": self.supported_features,
                # Legacy attributes kept for backward compatibility with old
                # cards / automations that still read them
                "speed_list": self.hood_speed_list,
                "speed": self.hood_speed,
                "friendly_name": self.hood_pretty,
                "icon": self.icon,
            },
        )
        if send and not self.in_step:
            self.control_hood()

    def update_light_state(self, send: bool = True):
        self.set_state(
            self.light_name,
            state="on" if self.light_on else "off",
            attributes={
                "friendly_name": self.light_pretty,
                "icon": "mdi:lightbulb",
            },
        )
        # Light TX is handled directly by _on_light_service; nothing to do here.

    # ---------- Stepping logic for fan speed ----------

    def control_hood(self, *args, **kwargs):
        """
        Walk the real hood up or down one step at a time, one second apart,
        until our 'real_speed' counter matches the desired target.
        Accepts both positional and kwargs to be compatible with AppDaemon
        run_in callbacks across versions.
        """
        try:
            self._control_hood_step()
        except Exception as e:
            self.log(f"control_hood error: {e!r}", level="ERROR")
            # Don't leave in_step stuck; recover and retry one more time.
            self.in_step = False
            self.run_in(self.control_hood, 2)

    def _control_hood_step(self):
        self.in_step = True

        if self.hood_state == "off":
            target = 0
        else:
            target = self.hood_speed_list.index(self.hood_speed) + 2

        self.log(f"control_hood: real={self.real_speed} target={target}")

        if self.real_speed == target:
            self.in_step = False
            return

        if self.real_speed > target:
            self.real_speed -= 1
            self.log(f"Sending DOWN; real_speed now {self.real_speed}")
            self._send_cmd(CMD_DOWN)
        else:
            if self.real_speed == 0:
                # First step from off: counter jumps to 2, then continues
                self.real_speed += 1
            self.real_speed += 1
            self.log(f"Sending UP; real_speed now {self.real_speed}")
            self._send_cmd(CMD_UP)

        self.run_in(self.control_hood, 1)

    def stop_boost(self, *args, **kwargs):
        self.hood_speed = self.hood_speed_list[-2]
        self.update_fan_state(send=True)
