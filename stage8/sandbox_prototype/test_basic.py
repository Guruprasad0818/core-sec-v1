import os
from data_seeder import seed_demo
from report_uploader import upload_report


def test_seeder_and_uploader(tmp_path):
    db, email = seed_demo()
    assert os.path.exists(db)
    # create fake zap report
    zap = tmp_path / "zap-report.json"
    zap.write_text('{"site": [{"alerts": [{"risk": "High"}]}]}')
    ok = upload_report(str(zap), threshold=0.5)
    assert ok


if __name__ == '__main__':
    test_seeder_and_uploader(__import__('pathlib').Path('.').resolve())
    print('ok')
