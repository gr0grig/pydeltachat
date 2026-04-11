"""IMAP and SMTP transport layer for Delta Chat."""

import email
import imaplib
import logging
import smtplib
import ssl
import time
from email.message import Message

log = logging.getLogger(__name__)


class IMAPConnection:
    """IMAP connection for receiving Delta Chat messages."""

    def __init__(self, host: str, port: int = 993):
        self.host = host
        self.port = port
        self._conn: imaplib.IMAP4_SSL | None = None
        self._last_uid: str | None = None

    def connect(self, user: str, password: str) -> None:
        """Connect and authenticate to IMAP server."""
        ctx = ssl.create_default_context()
        self._conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
        self._conn.login(user, password)
        log.info("IMAP connected: %s", user)

    def select_inbox(self) -> int:
        """Select INBOX and return message count."""
        assert self._conn is not None
        status, data = self._conn.select("INBOX")
        if status != "OK":
            raise RuntimeError(f"IMAP SELECT failed: {data}")
        count = int(data[0])
        # Remember the highest UID so we can fetch only new messages later
        if count > 0:
            status, data = self._conn.uid("search", None, "ALL")
            if status == "OK" and data[0]:
                uids = data[0].split()
                self._last_uid = uids[-1].decode()
        return count

    def fetch_new_messages(self) -> list[Message]:
        """Fetch messages that arrived after the last check.

        Returns list of email.message.Message objects.
        """
        assert self._conn is not None
        # Search for UIDs greater than last seen
        if self._last_uid:
            criteria = f"(UID {int(self._last_uid) + 1}:*)"
        else:
            criteria = "ALL"

        status, data = self._conn.uid("search", None, criteria)
        if status != "OK" or not data[0]:
            return []

        uids = data[0].split()
        # Filter out already-seen UID (IMAP UID range is inclusive)
        if self._last_uid:
            uids = [u for u in uids if int(u) > int(self._last_uid)]

        if not uids:
            return []

        messages = []
        for uid in uids:
            status, msg_data = self._conn.uid("fetch", uid, "(RFC822)")
            if status != "OK":
                continue
            raw = None
            for item in msg_data:
                if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
                    raw = bytes(item[1])
                    break
            if raw is None:
                continue
            msg = email.message_from_bytes(raw)
            messages.append(msg)
            self._last_uid = uid.decode() if isinstance(uid, bytes) else uid

        return messages

    def poll_wait(self, timeout: float = 60.0, interval: float = 3.0) -> bool:
        """Poll for new messages by issuing NOOP and checking for new UIDs.

        Returns True if new messages are likely available.
        """
        assert self._conn is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._conn.noop()
            # Check for new UIDs
            search_from = int(self._last_uid) + 1 if self._last_uid else 1
            status, data = self._conn.uid("search", None, f"(UID {search_from}:*)")
            if status == "OK" and data[0]:
                uids = data[0].split()
                if self._last_uid:
                    uids = [u for u in uids if int(u) > int(self._last_uid)]
                if uids:
                    return True
            time.sleep(interval)
        return False

    def close(self) -> None:
        """Close the IMAP connection."""
        if self._conn:
            try:
                self._conn.close()
                self._conn.logout()
            except Exception:
                pass
            self._conn = None


class SMTPConnection:
    """SMTP connection for sending Delta Chat messages."""

    def __init__(self, host: str, port: int = 465):
        self.host = host
        self.port = port
        self._conn: smtplib.SMTP_SSL | None = None
        self._user: str | None = None
        self._password: str | None = None

    def connect(self, user: str, password: str) -> None:
        """Connect and authenticate to SMTP server."""
        self._user = user
        self._password = password
        self._do_connect()

    def _do_connect(self) -> None:
        ctx = ssl.create_default_context()
        self._conn = smtplib.SMTP_SSL(self.host, self.port, context=ctx)
        self._conn.login(self._user, self._password)
        log.info("SMTP connected: %s", self._user)

    def _reconnect(self) -> None:
        try:
            if self._conn:
                self._conn.quit()
        except Exception:
            pass
        self._conn = None
        self._do_connect()

    def send(self, from_addr: str, to_addr: str, raw_message: bytes) -> None:
        """Send a raw email message. Auto-reconnects on timeout."""
        for attempt in range(2):
            try:
                assert self._conn is not None
                self._conn.sendmail(from_addr, [to_addr], raw_message)
                break
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPSenderRefused,
                    smtplib.SMTPResponseException, OSError) as e:
                if attempt == 0:
                    log.warning("SMTP send failed (%s), reconnecting...", e)
                    self._reconnect()
                else:
                    raise
        log.info("Message sent: %s -> %s", from_addr, to_addr)

    def close(self) -> None:
        """Close the SMTP connection."""
        if self._conn:
            try:
                self._conn.quit()
            except Exception:
                pass
            self._conn = None
