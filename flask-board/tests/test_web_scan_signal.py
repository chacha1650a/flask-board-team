"""공격② 웹 스캐너(nikto·gobuster) 탐지용 신호 — 404 를 GELF(rule='web-scan')로 신고한다.

스캐너는 사전의 없는 경로를 대량 요청해 404 를 폭주시킨다. 앱이 404 마다 GELF 를 보내면
Graylog 가 src_ip 별로 집계(예: 30초 내 30회↑)해 스캔을 탐지하고 n8n 이 차단한다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

ADMIN = {'X-API-Key': 'test-admin-key'}


@pytest.fixture
def sent(monkeypatch):
  """send_gelf 호출을 가로채 기록한다(실제 UDP 전송 없이 검증)."""
  calls = []

  def fake(short_message, rule, **fields):
    calls.append({'msg': short_message, 'rule': rule, **fields})

  import app as app_mod
  monkeypatch.setattr(app_mod, 'send_gelf', fake)
  return calls


@pytest.fixture
def client(tmp_path):
  class TestConfig:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'test-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECURITY_API_KEY = 'test-security-key'
    ADMIN_API_KEY = 'test-admin-key'
    ADMIN_ALLOWLIST = []
    AUTO_POST_ON_DENY = False
    PUBLIC_API_KEY = None
    PUBLIC_API_URL = 'http://example.invalid/'

  application = create_app(TestConfig)
  yield application.test_client()
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def web_scan(calls):
  return [c for c in calls if c['rule'] == 'web-scan']


def test_404_is_reported_as_web_scan(client, sent):
  """없는 경로 → 404 → rule='web-scan' 신고(src_ip·path·code 포함)."""
  assert client.get('/no-such-page-xyz').status_code == 404
  ev = web_scan(sent)
  assert len(ev) == 1, sent
  assert ev[0]['src_ip'] == '127.0.0.1'
  assert ev[0]['path'] == '/no-such-page-xyz'
  assert ev[0]['code'] == 404


def test_scan_burst_reports_every_404(client, sent):
  """gobuster 처럼 연속 404 를 만들면 요청 수만큼 신고된다(집계의 재료)."""
  for i in range(35):
    client.get(f'/wordlist-{i}')
  assert len(web_scan(sent)) == 35


def test_long_path_is_truncated(client, sent):
  """로그 인젝션·과대 로그 방지 — 경로는 120자로 자른다."""
  client.get('/' + 'a' * 500)
  ev = web_scan(sent)
  assert len(ev) == 1
  assert len(ev[0]['path']) <= 120


def test_admin_api_404_is_not_reported(client, sent):
  """운영·n8n 트래픽 오탐 방지 — /api/admin 의 404 는 신고하지 않는다."""
  client.get('/api/admin/no-such-endpoint', headers=ADMIN)
  assert web_scan(sent) == []


def test_normal_200_is_not_reported(client, sent):
  """정상 응답은 신고하지 않는다."""
  assert client.get('/').status_code == 200
  assert web_scan(sent) == []


def test_send_failure_does_not_break_response(client, monkeypatch):
  """SIEM 신고가 예외를 내도 응답(404)은 그대로 나간다."""
  import app as app_mod

  def boom(*a, **k):
    raise RuntimeError('graylog down')

  monkeypatch.setattr(app_mod, 'send_gelf', boom)
  assert client.get('/still-404').status_code == 404
