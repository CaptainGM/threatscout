from threatscout.cli import _file_stem
from threatscout.pdf import _safe


def test_file_name_has_no_bad_characters():
    name = _file_stem("https://evil.example/a?b=1:8080")
    assert not any(ch in name for ch in ":?/")


def test_pdf_text_turkish_letters():
    assert _safe("İstanbul Şişli") == "Istanbul Sisli"
