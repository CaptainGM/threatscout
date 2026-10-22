from pathlib import Path

from threatscout.config import Settings


def test_database_path_does_not_depend_on_current_folder():
    # Yol mutlak olmali, yoksa baska klasordan calistirinca yeni bos bir veritabani olusur
    assert Path(Settings().sqlite_path).is_absolute()
