import hashlib
from datetime import datetime
import os
import shutil
import click as clk
from typing import Any
import tomllib as tl
import logging
import pyrsync
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
@clk.option('--debug', 'debug', default = None)
@clk.option('--full', '-f', 'full', is_flag=True, help='Perform a full backup.')
def chup(config_path: str, full: bool, debug: str):
    with open(config_path) as f:
        config = Config.from_dict(tl.loads(f.read()))
    if full:
        full_cloud_backup(config)
    else:
        incremental_cloud_backup(config, debug)


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
        with tarfile.open(os.path.join(working_dir, 'base.tar'), mode='w') as tarball:
            tarball.add(backup_dir.path, arcname='data')
        with sigvault.open_vault(os.path.join(working_dir, 'base.tar'), 'w', backup_dir.path) as sv:
            for f in backup_dir.iterfiles():
                sv.add(f)

        with tarfile.open(os.path.join(tmpdir, f'{timestamp}-full.tar'), mode='w') as tarball:
            tarball.add(working_dir, arcname=working_dir.split('/')[-1])

        zstd.compress(os.path.join(tmpdir, f'{timestamp}-full.tar'), os.path.join(tmpdir, f'{timestamp}-full.tar.zst'))
        gnupg.GPG().encrypt_file(os.path.join(tmpdir, f'{timestamp}-full.tar.zst'), symmetric='CAST5',
                                 passphrase=password, recipients=None,
                                 output=os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'))
        with open(os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'), 'rb') as f:
            hash_value = hashlib.md5(f.read()).hexdigest()
        shutil.move(os.path.join(tmpdir, f'{timestamp}-full.tar.zst.gpg'), target_dir)
        return os.path.join(target_dir, f'{timestamp}-full.tar.zst.gpg'), hash_value


def incremental_local_backup(config: Config, target_dir: str, base_backup: str) -> tuple[str, str]:
    with TemporaryDirectory() as tmpdir:
        backup_datetime = datetime.utcnow()
        timestamp = backup_datetime.isoformat()
        working_dir = os.path.join(tmpdir, f'{timestamp}-incr')
        os.mkdir(working_dir)
        password = config.password()
        backup_dir = Dir(config.dir_to_backup())
        backup_key = backup_dir.path.strip('/').split('/')[-1]

        last_state = DirState.from_json(Dir(base_backup).get('{0}.state.*'.format(backup_key),
                                                             sort_reverse=True, abspath=True))
        current_state = DirState(backup_dir)

        diff = current_state - last_state

        current_state.to_json(working_dir, dt=backup_datetime, fmt='{0}.state.{1}.json')

        __process_created(working_dir, backup_dir.path, diff['created'])

        last_sigs = {}
        if os.path.exists(os.path.join(base_backup, 'base.tar')):
            with sigvault.open_vault(os.path.join(base_backup, 'base.tar'), 'r') as last_base_sv:
                last_sigs |= last_base_sv.sigs
        if os.path.exists(os.path.join(base_backup, 'updated.tar')):
            with sigvault.open_vault(os.path.join(base_backup, 'updated.tar'), 'r') as last_updated_sv:
                last_sigs |= last_updated_sv.sigs
        if os.path.exists(os.path.join(base_backup, 'created.tar')):
            with sigvault.open_vault(os.path.join(base_backup, 'created.tar'), 'r') as last_created_sv:
                last_sigs |= last_created_sv.sigs

        __process_updated(working_dir, backup_dir.path, diff['updated'], last_sigs)

        with tarfile.open(os.path.join(tmpdir, f'{timestamp}-incr.tar'), mode='w') as tarball:
            tarball.add(working_dir, arcname=working_dir.split('/')[-1])

        zstd.compress(os.path.join(tmpdir, f'{timestamp}-incr.tar'), os.path.join(tmpdir, f'{timestamp}-incr.tar.zst'))
        gnupg.GPG().encrypt_file(os.path.join(tmpdir, f'{timestamp}-incr.tar.zst'), symmetric='CAST5',
                                 passphrase=password, recipients=None,
                                 output=os.path.join(tmpdir, f'{timestamp}-incr.tar.zst.gpg'))
        with open(os.path.join(tmpdir, f'{timestamp}-incr.tar.zst.gpg'), 'rb') as f:
            hash_value = hashlib.md5(f.read()).hexdigest()
        shutil.move(os.path.join(tmpdir, f'{timestamp}-incr.tar.zst.gpg'), target_dir)
        return os.path.join(target_dir, f'{timestamp}-incr.tar.zst.gpg'), hash_value


def full_cloud_backup(config: Config):
    filename, hash_value = full_local_backup(config, os.getcwd())
    with open('./md5.txt', 'w') as f:
        f.write(os.path.basename(filename) + ' ' + hash_value)


def incremental_cloud_backup(config: Config, debug: str = None):
    if debug is not None:
        filename, hash_value = incremental_local_backup(config, os.getcwd(), debug)
        with open('./md5.txt', 'w') as f:
            f.write(os.path.basename(filename) + ' ' + hash_value)


def __process_created(working_dir: str, backup_dir: str, created_files: list[str]):
    # with tarfile.open(os.path.join(working_dir, 'data.tar'), mode='w') as tarball:
    #     for f in created_files:
    #         tarball.add(os.path.join(backup_dir, f), arcname=os.path.join('created', f))
    with sigvault.open_vault(os.path.join(working_dir, 'created.tar'), 'w', backup_dir) as sv:
        for f in created_files:
            sv.add(f)


def __process_updated(working_dir: str, backup_dir: str, updated_files: list[str], last_sigs: dict[str, bytes]):
    with tarfile.open(os.path.join(working_dir, 'updated.tar'), mode='w') as tarball:
        for f in updated_files:
            # tarball.add(os.path.join(backup_dir, f), arcname=os.path.join('updated', f)
            f_abs = os.path.join(backup_dir, f)
            with open(f_abs, 'rb') as input_f, TemporaryFile('w+b') as tmp_sig_f, TemporaryFile('w+b') as tmp_delta_f:
                tmp_sig_f.write(last_sigs[f])
                tmp_sig_f.seek(0)
                pyrsync.delta(input_f, tmp_sig_f, tmp_delta_f)
                tmp_delta_f.seek(0)
                tarinfo = tarfile.TarInfo(os.path.join('updated', f))
                tarinfo.size = os.fstat(tmp_delta_f.fileno()).st_size
                tarball.addfile(tarinfo, tmp_delta_f)
