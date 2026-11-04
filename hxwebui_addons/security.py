import re
import hmac
import secrets
import os
from flask import session, request, abort, current_app
from hxtool_util import format_activity_log

ADDON_MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_LINES = 10000
MAX_LINE_LEN = 1024
RE_NUMERIC_ID = re.compile(r'[0-9]{1,10}')
RE_POLICY_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')
_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def get_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.modified = True
    return session['csrf_token']


def install_guards(bp):
    @bp.before_request
    def _addon_guards():
        if request.method == 'POST':
            if request.content_length is None:
                abort(411)
            if request.content_length > ADDON_MAX_UPLOAD_BYTES + 65536:
                abort(413)
            if 'ht_user' in session:
                sent = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
                expected = session.get('csrf_token', '')
                if not expected or not hmac.compare_digest(sent.encode('utf-8', 'ignore'), expected.encode('utf-8', 'ignore')):
                    current_app.logger.warning(
                        format_activity_log(
                            msg="csrf rejected",
                            path=clean_log(request.path),
                            user=session.get('ht_user'),
                            controller=session.get('hx_ip'),
                        )
                    )
                    abort(400, "CSRF token missing or invalid")


def valid_numeric_id(s) -> bool:
    return bool(s is not None and RE_NUMERIC_ID.fullmatch(str(s)))


def valid_policy_id(s) -> bool:
    return bool(s is not None and RE_POLICY_ID.fullmatch(str(s)))


def parse_lines(text) -> list[str]:
    if not text:
        return []
    lines = [ln.strip() for ln in str(text).splitlines() if ln.strip()]
    if len(lines) > MAX_LINES:
        raise ValueError("Too many lines (max 10000)")
    for line in lines:
        if len(line) > MAX_LINE_LEN or _CTRL.search(line):
            raise ValueError("Line exceeds maximum length or contains invalid characters")
    return lines


def read_upload_lines(file_storage, allowed_exts) -> list[str]:
    if not file_storage or not getattr(file_storage, 'filename', ''):
        return []
    ext = os.path.splitext((file_storage.filename or '').lower())[1]
    if ext not in allowed_exts:
        raise ValueError("Unsupported file type")
    raw = file_storage.stream.read(ADDON_MAX_UPLOAD_BYTES + 1)
    if len(raw) > ADDON_MAX_UPLOAD_BYTES:
        raise ValueError("Upload too large (max 2 MiB)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("File is not valid UTF-8")
    return parse_lines(text)


def clean_log(v, maxlen=200) -> str:
    s = str(v).replace('\r', '').replace('\n', '').replace("'", '')
    return s[:maxlen]


def audit(action, **kw):
    current_app.logger.info(
        format_activity_log(
            msg=kw.pop('msg', 'addon action'),
            action=action,
            user=session.get('ht_user'),
            controller=session.get('hx_ip'),
            **{k: clean_log(v) for k, v in kw.items()},
        )
    )


def safe_error(prefix, code, resp) -> str:
    current_app.logger.warning(
        format_activity_log(
            msg="addon api error",
            prefix=clean_log(prefix),
            code=clean_log(code),
            detail=clean_log(resp, 500),
            user=session.get('ht_user'),
            controller=session.get('hx_ip'),
        )
    )
    return f"{prefix} (HTTP {code}). See server log for details."


def csv_safe(v) -> str:
    s = str(v)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s
