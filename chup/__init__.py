import hashlib
from datetime import datetime
import os
import shutil
import click as clk
from typing import Any
import tomllib as tl
import logging
import sigvault
from tempfile import TemporaryFile, TemporaryDirectory
from dirtools import Dir, DirState, compute_diff
import tarfile
import gnupg
import zstd

logging.basicConfig(level=logging.INFO)
log = logging


class Config:
    def __init__(self, dir_to_backup: str, password: str):
        self.__dir_to_backup = dir_to_backup
        self.__password = password

    def dir_to_backup(self):
        return self.__dir_to_backup

    def password(self):
        return self.__password

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Config':
        return cls(data['backup']['dir_to_backup'], data['backup']['password'])


@clk.command('chup', help="Chuyang Chen's incremental backup tool.")
@clk.option('--config', '-c', 'config_path', help='The config file in TOML format.', default='/etc/chup.toml')
def chup(config_path: str):
    with open(config_path) as f:
        config = Config.from_dict(tl.loads(f.read()))
    full_cloud_backup(config)


def full_local_backup(config: Config, target_dir: str) -> tuple[str, str]:
    with TemporaryDirectory() as tmpdir:
        backup_datetime = datetime.utcnow()
        timestamp = backup_datetime.isoformat()
        working_dir = os.path.join(tmpdir, f'{timestamp}-full')
        os.mkdir(working_dir)
        password = config.password()
        backup_dir = Dir(config.dir_to_backup())
        backup_dir_state = DirState(backup_dir)
        backup_dir_state.to_json(working_dir, dt=backup_datetime, fmt='{0}.state.{1}.json')
        with tarfile.open(os.path.join(working_dir, 'data.tar'), mode='w') as tarball:
            tarball.add(backup_dir.path)
        with sigvault.open_vault(os.path.join(working_dir, 'data.tar'), 'w', backup_dir.path) as sv:
            for f in backup_dir.iterfiles():
                sv.add(f)

        with tarfile.open(os.path.join(tmpdir, f'{timestamp}-full.tar'), mode='w') as tarball:
            tarball.add(working_dir)

        zstd.compress(os.path.join(tmpdir, f'{timestamp}-full.tar'), os.path.join(tmpdir, f'{timestamp}-full.tar.zst'))
        gnupg.GPG().encrypt_file(os.path.join(tmpdir, f'{timestamp}-full.tar.zst'), symmetric='CAST5',
                                 passphrase=password, recipients=None,
                                 output=os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'))
        with open(os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'), 'rb') as f:
            hash_value = hashlib.md5(f.read()).hexdigest()
        shutil.move(os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'), target_dir)
        return os.path.join(target_dir, f'{timestamp}-full.tar.zst.gpg'), hash_value


def full_cloud_backup(config: Config):
    filename, hash_value = full_local_backup(config, os.getcwd())
    with open('./md5.txt', 'w') as f:
        f.write(os.path.basename(filename) + ' ' + hash_value)
