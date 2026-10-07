import pytest

from sieve.pipeline import mask

# fake keys, split so secret scanners don't flag them
SHOULD_MASK = [
    ("OPENAI_API_KEY=sk-" + "proj-abcDEF1234567890ghijKLMNOP", "sk-proj"),
    ("anahtarım sk-" + "ant-api03-Xy7Kq2mN9pL4vR8tW1zB6cD3fG5hJ0 bu", "sk-ant"),
    ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("token: gh" + "p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "ghp_"),
    ("slack xo" + "xb-123456789012-abcdefghijkl", "xoxb-"),
    ("key=AI" + "zaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "AIzaSy"),
    ("stripe sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc", "sk_live"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r", "eyJhbGci"),
    ("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA " + "PRIVATE KEY-----", "MIIEpAIBAAKCAQEA7"),
    ("DATABASE_URL=postgres://admin:S3cretPass!@db.example.com:5432/app", "S3cretPass!"),
    ("password: Ankara2026!", "Ankara2026!"),
    ("şifre=Gizli.123", "Gizli.123"),
    ("şifrem: Kedi2026!", "Kedi2026!"),  # Turkish puts the owner on the word
    ("Parolanız=Ankara06*", "Ankara06*"),
    ("Şifrem 123456 ama giremiyorum", "123456"),
    ("parolam de Kedi*99", "Kedi*99"),
    ("config: Zk8Qp2Lm7Vx4Rt9Nw3Bj6Hy1Cf5Gd0Ks8Ea", "Zk8Qp2Lm7Vx4Rt9Nw3Bj6Hy1Cf5Gd0Ks8Ea"),
]

SHOULD_NOT_CHANGE = [
    "Şifremi unuttum, nasıl sıfırlarım?",
    "Şifrem nasıl değiştirilir?",
    "Parolam en az kaç karakter olmalı?",
    "API anahtarımı nereden alırım?",
    "Token süresi ne zaman doluyor?",
    "Git commit 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a3f geri alınabilir mi?",
    "internationalization_and_localization_settings_panel",
    "https://www.example.com/docs/getting-started",
    "Kullanıcı adım ali.veli, şifre politikası nedir?",
]


@pytest.mark.parametrize("text, secret", SHOULD_MASK)
def test_masks(text, secret):
    assert secret not in mask(text)


@pytest.mark.parametrize("text", SHOULD_NOT_CHANGE)
def test_leaves_alone(text):
    assert mask(text) == text
