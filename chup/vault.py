import base64
import hashlib
import json
import os
from enum import Enum
from tarfile import TarFile
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Optional
import os.path as op
from datetime import datetime

import gnupg
import pyrsync

import zstd
from dirtools import Dir, DirState

_DEFAULT_GPG_ALG = 'CAST5'

_VAULT_ROOT_PREFIX = 'backup'
_VAULT_ADD_PREFIX = 'created'
_VAULT_UPDATE_PREFIX = 'updated'

_VAULT_SIG_FILE = 'sigs.json.gpg'
_VAULT_METADATA_FILE = 'metadata.json.gpg'
_VAULT_STATE_FILE = 'state.json.gpg'
_VAULT_DATA_PREFIX = 'data'


class VaultType(Enum):
    FULL = 'full'
    INCREMENTAL = 'incremental'


class VaultWriter:
    def __init__(self, vault_dir: str, backup_dir: str, password: str,
                 previous_vault: Optional[tuple[str, str, dict[str, bytes]]] = None):
        self.__backup_dir = backup_dir
        self.__timestamp = datetime.utcnow()
        self.__vault_path = op.join(vault_dir, f'{self.__timestamp.isoformat()}.tar')
        self.__tarball = TarFile.open(self.__vault_path, mode='w')
        self.__password = password
        self.__tmp_dir = TemporaryDirectory()
        self.__data_tarball = TarFile.open(op.join(self.__tmp_dir.name, 'data.tar'), mode='w')
        if previous_vault is None:
            self.__type = VaultType.FULL
            self.__sigs = {}
            return
        self.__type = VaultType.INCREMENTAL
        self.__previous_vault_path, self.__previous_vault_hash, self.__sigs = previous_vault

    @property
    def type(self):
        return self.__type

    def __enter__(self):
        return self

    @property
    def timestamp(self):
        return self.__timestamp.isoformat()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def result(self):
        return self.__vault_path

    def create(self, file: str):
        self.__data_tarball.add(op.join(self.__backup_dir, file),
                                arcname=op.join(_VAULT_DATA_PREFIX, _VAULT_ADD_PREFIX, file))
        with open(op.join(self.__backup_dir, file), 'rb') as original_file, NamedTemporaryFile(mode='w+b') as sig_file:
            pyrsync.signature(original_file, sig_file, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
            sig_file.seek(0)
            self.__sigs[file] = sig_file.read()

    def update(self, file: str):
        with (open(op.join(self.__backup_dir, file), 'rb') as original_file,
              NamedTemporaryFile(mode='w+b') as delta_file,
              NamedTemporaryFile(mode='w+b') as new_sig_file,
              NamedTemporaryFile(mode='w+b') as old_sig_file):
            old_sig = self.__sigs[file]
            old_sig_file.write(old_sig)
            old_sig_file.seek(0)
            pyrsync.delta(original_file, old_sig_file, delta_file)
            delta_file.seek(0)
            self.__data_tarball.add(delta_file.name, arcname=op.join(_VAULT_DATA_PREFIX, _VAULT_UPDATE_PREFIX, file))
            pyrsync.signature(original_file, new_sig_file, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
            new_sig_file.seek(0)
            self.__sigs[file] = new_sig_file.read()

    def delete(self, file: str):
        self.__sigs.pop(file)

    def close(self):
        metadata = {'timestamp': self.timestamp, 'type': self.__type.value,
                    'dir_name': self.__backup_dir.strip('/').split('/')[-1]}
        if self.__type == VaultType.INCREMENTAL:
            metadata['previous_vault'] = {'name': op.basename(self.__previous_vault_path),
                                          'hash': self.__previous_vault_hash}
        with NamedTemporaryFile(mode='w+t') as metadata_file:
            json.dump(metadata, metadata_file, indent=2)
            metadata_file.seek(0)
            with NamedTemporaryFile(mode='w+b') as tmp:
                gnupg.GPG().encrypt(metadata_file.read(), recipients=None, passphrase=self.__password, output=tmp.name,
                                    symmetric=_DEFAULT_GPG_ALG)
                tmp.seek(0)
                self.__tarball.add(tmp.name, arcname=op.join(_VAULT_ROOT_PREFIX, _VAULT_METADATA_FILE))

        sigs_list = [{'file': k, 'sig': base64.encodebytes(v).decode('ascii')} for k, v in self.__sigs.items()]
        with NamedTemporaryFile(mode='w+t') as sigs_file:
            json.dump(sigs_list, sigs_file, indent=2)
            sigs_file.seek(0)
            with NamedTemporaryFile(mode='w+b') as tmp:
                gnupg.GPG().encrypt(sigs_file.read(), recipients=None, passphrase=self.__password, output=tmp.name,
                                    symmetric=_DEFAULT_GPG_ALG)
                tmp.seek(0)
                self.__tarball.add(tmp.name, arcname=op.join(_VAULT_ROOT_PREFIX, _VAULT_SIG_FILE))

        dir_state = DirState(Dir(self.__backup_dir))
        with TemporaryDirectory() as tmp_dir:
            dir_state.to_json(tmp_dir, self.__timestamp, fmt='state.json')
            with NamedTemporaryFile(mode='w+b') as tmp:
                gnupg.GPG().encrypt_file(op.join(tmp_dir, 'state.json'), recipients=None, passphrase=self.__password,
                                         output=tmp.name, symmetric=_DEFAULT_GPG_ALG)
                tmp.seek(0)
                self.__tarball.add(tmp.name, arcname=op.join(_VAULT_ROOT_PREFIX, _VAULT_STATE_FILE))

        self.__data_tarball.close()
        zstd.compress(self.__data_tarball.name, op.join(self.__tmp_dir.name, f'{_VAULT_DATA_PREFIX}.tar.zst'))
        gnupg.GPG().encrypt_file(op.join(self.__tmp_dir.name, f'{_VAULT_DATA_PREFIX}.tar.zst'), recipients=None,
                                 passphrase=self.__password,
                                 output=op.join(self.__tmp_dir.name, f'{_VAULT_DATA_PREFIX}.tar.zst.gpg'),
                                 symmetric=_DEFAULT_GPG_ALG)
        self.__tarball.add(op.join(self.__tmp_dir.name, f'{_VAULT_DATA_PREFIX}.tar.zst.gpg'),
                           arcname=op.join(_VAULT_ROOT_PREFIX, f'{_VAULT_DATA_PREFIX}.tar.zst.gpg'))
        self.__tarball.close()
        self.__tmp_dir.cleanup()


class VaultReader:
    def __init__(self, vault_file: str, password: str):
        with open(vault_file, 'rb') as f:
            self.__hash_value = hashlib.md5(f.read()).hexdigest()
        self.__tarball = TarFile(vault_file, mode='r')
        self.__password = password
        self.__tmp_dir = TemporaryDirectory()
        self.__tmp_dir_with_root = op.join(self.__tmp_dir.name, _VAULT_ROOT_PREFIX)

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, _VAULT_METADATA_FILE), path=self.__tmp_dir.name)
        t = gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_METADATA_FILE), passphrase=password)
        metadata = json.loads(str(gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_METADATA_FILE),
                                                           passphrase=password)))
        self.__type = VaultType(metadata['type'])
        self.__timestamp = datetime.fromisoformat(metadata['timestamp'])
        self.__dir_name = metadata['dir_name']

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, _VAULT_SIG_FILE), path=self.__tmp_dir.name)
        sigs = json.loads(str(gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_SIG_FILE),
                                                       passphrase=password)))
        self.__sigs = {x['file']: base64.decodebytes(x['sig'].encode('ascii')) for x in sigs}

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, _VAULT_STATE_FILE), path=self.__tmp_dir.name)
        gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_STATE_FILE),
                                 output=op.join(self.__tmp_dir_with_root, 'state.json'), passphrase=password)
        self.__dir_state = DirState.from_json(op.join(self.__tmp_dir_with_root, 'state.json'))

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, f'{_VAULT_DATA_PREFIX}.tar.zst.gpg'),
                               path=self.__tmp_dir.name)
        gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, f'{_VAULT_DATA_PREFIX}.tar.zst.gpg'),
                                 output=op.join(self.__tmp_dir_with_root, f'{_VAULT_DATA_PREFIX}.tar.zst'),
                                 passphrase=password)
        zstd.decompress(op.join(self.__tmp_dir_with_root, f'{_VAULT_DATA_PREFIX}.tar.zst'),
                        op.join(self.__tmp_dir_with_root, f'{_VAULT_DATA_PREFIX}.tar'))
        self.__data_tarball = TarFile(op.join(self.__tmp_dir_with_root, f'{_VAULT_DATA_PREFIX}.tar'), mode='r')

    @property
    def type(self) -> VaultType:
        return self.__type

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def dir_name(self) -> str:
        return self.__dir_name

    @property
    def hash_value(self) -> str:
        return self.__hash_value

    @property
    def dir_state(self) -> DirState:
        return self.__dir_state

    @property
    def sigs(self) -> dict[str, bytes]:
        return self.__sigs

    def __enter__(self):
        return self

    def close(self):
        self.__data_tarball.close()
        self.__tmp_dir.cleanup()
        self.__tarball.close()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_vault(vault_dir: str, backup_dir: str, password: str) -> VaultWriter:
    result = VaultWriter(vault_dir, backup_dir, password)
    for file in os.listdir(backup_dir):
        result.create(file)
    return result


def open_vault(vault_file: str, password: str) -> VaultReader:
    return VaultReader(vault_file, password)


def increment_vault(vault_dir: str, last_vault_file: str, password: str, backup_dir: str) -> VaultWriter:
    with open_vault(op.join(vault_dir, last_vault_file), password) as last_vault:
        current_vault = VaultWriter(vault_dir, backup_dir, password,
                                    (last_vault_file, last_vault.hash_value, last_vault.sigs))
        backup_dir = Dir(backup_dir)
        current_state = DirState(backup_dir)
        diff = current_state - last_vault.dir_state
        for file in diff['created']:
            current_vault.create(file)
        for file in diff['updated']:
            current_vault.update(file)
        for file in diff['deleted']:
            current_vault.delete(file)
    return current_vault
