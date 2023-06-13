import base64
import hashlib
import json
import os
import shutil
from enum import Enum
from io import BytesIO
from tarfile import TarFile
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Optional, IO
import os.path as op
from datetime import datetime
import log
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
_VAULT_FILE_LIST_FILE = 'list.json.gpg'
_VAULT_DATA_PREFIX = 'data'


class VaultType(Enum):
    FULL = 'full'
    INCREMENTAL = 'incremental'


class VaultWriter:
    def __init__(self, vault_dir: str, backup_dir: str, password: str,
                 previous_vault: Optional[tuple[str, str, dict[str, bytes], set[str]]] = None, id: str = None):
        self.__backup_dir = backup_dir
        self.__timestamp = datetime.utcnow()
        if id is None:
            self.__id = self.__timestamp.isoformat()
        else:
            self.__id = id
        self.__vault_path = op.join(vault_dir, f'{self.__timestamp.isoformat()}.tar')
        self.__tarball = TarFile.open(self.__vault_path, mode='w')
        self.__password = password
        self.__tmp_dir = TemporaryDirectory()
        self.__data_tarball = TarFile.open(op.join(self.__tmp_dir.name, 'data.tar'), mode='w')
        if previous_vault is None:
            self.__type = VaultType.FULL
            self.__sigs = {}
            self.__file_list = set()
            return
        self.__type = VaultType.INCREMENTAL
        self.__previous_vault_path, self.__previous_vault_hash, self.__sigs, self.__file_list = previous_vault

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
        log.info(f'Adding file {file} to vault {self.id}')
        self.__data_tarball.add(op.join(self.__backup_dir, file),
                                arcname=op.join(_VAULT_DATA_PREFIX, _VAULT_ADD_PREFIX, file))
        with open(op.join(self.__backup_dir, file), 'rb') as original_file, BytesIO() as sig_file:
            pyrsync.signature(original_file, sig_file, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
            sig_file.seek(0)
            self.__sigs[file] = sig_file.read()
            self.__file_list.add(file)

    @property
    def id(self):
        return self.__id

    def update(self, file: str):
        log.info(f'Updating file {file} in vault {self.id}')
        with (open(op.join(self.__backup_dir, file), 'rb') as original_file,
              NamedTemporaryFile(mode='w+b') as delta_file,
              BytesIO() as new_sig_file,
              BytesIO() as old_sig_file):
            old_sig = self.__sigs[file]
            old_sig_file.write(old_sig)
            old_sig_file.seek(0)
            pyrsync.delta(original_file, old_sig_file, delta_file)
            delta_file.seek(0)
            original_file.seek(0)
            self.__data_tarball.add(delta_file.name, arcname=op.join(_VAULT_DATA_PREFIX, _VAULT_UPDATE_PREFIX, file))
            pyrsync.signature(original_file, new_sig_file, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
            new_sig_file.seek(0)
            self.__sigs[file] = new_sig_file.read()

    def delete(self, file: str):
        log.info(f'Deleting file {file} from vault {self.id}')
        self.__sigs.pop(file)
        self.__file_list.remove(file)

    def close(self):
        log.info(f'Saving vault {self.id}')
        metadata = {'id': self.id, 'timestamp': self.timestamp, 'type': self.__type.value,
                    'dir_name': self.__backup_dir.strip('/').split('/')[-1]}
        if self.__type == VaultType.INCREMENTAL:
            metadata['previous_vault'] = {'file_name': op.basename(self.__previous_vault_path),
                                          'hash': self.__previous_vault_hash}
        with NamedTemporaryFile(mode='w+t') as metadata_file:
            json.dump(metadata, metadata_file, indent=2)
            metadata_file.seek(0)
            with NamedTemporaryFile(mode='w+b') as tmp:
                gnupg.GPG().encrypt(metadata_file.read(), recipients=None, passphrase=self.__password, output=tmp.name,
                                    symmetric=_DEFAULT_GPG_ALG)
                tmp.seek(0)
                self.__tarball.add(tmp.name, arcname=op.join(_VAULT_ROOT_PREFIX, _VAULT_METADATA_FILE))

        with NamedTemporaryFile(mode='w+t') as file_list_file:
            json.dump(list(self.__file_list), file_list_file, indent=2)
            file_list_file.seek(0)
            with NamedTemporaryFile(mode='w+b') as tmp:
                gnupg.GPG().encrypt(file_list_file.read(), recipients=None, passphrase=self.__password, output=tmp.name,
                                    symmetric=_DEFAULT_GPG_ALG)
                tmp.seek(0)
                self.__tarball.add(tmp.name, arcname=op.join(_VAULT_ROOT_PREFIX, _VAULT_FILE_LIST_FILE))

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
        metadata = json.loads(str(gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_METADATA_FILE),
                                                           passphrase=password)))
        self.__type = VaultType(metadata['type'])
        self.__timestamp = datetime.fromisoformat(metadata['timestamp'])
        self.__dir_name = metadata['dir_name']
        self.__id = metadata['id']
        self.__file_name = vault_file
        if self.__type == VaultType.FULL:
            self.__previous_vault: Optional[tuple[str, str]] = None
        else:
            self.__previous_vault = (metadata['previous_vault']['file_name'], metadata['previous_vault']['hash'])

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, _VAULT_SIG_FILE), path=self.__tmp_dir.name)
        sigs = json.loads(str(gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_SIG_FILE),
                                                       passphrase=password)))
        self.__sigs = {x['file']: base64.decodebytes(x['sig'].encode('ascii')) for x in sigs}

        self.__tarball.extract(op.join(_VAULT_ROOT_PREFIX, _VAULT_FILE_LIST_FILE), path=self.__tmp_dir.name)
        file_list = json.loads(str(gnupg.GPG().decrypt_file(op.join(self.__tmp_dir_with_root, _VAULT_FILE_LIST_FILE),
                                                            passphrase=password)))
        self.__file_list = set(file_list)

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

        self.__data_unfold: Optional[TemporaryDirectory] = None

    @property
    def type(self) -> VaultType:
        return self.__type

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def id(self) -> str:
        return self.__id

    @property
    def data_files(self) -> set[str]:
        return self.__file_list

    @property
    def dir_name(self) -> str:
        return self.__dir_name

    @property
    def hash_value(self) -> str:
        return self.__hash_value

    @property
    def file_name(self) -> str:
        return self.__file_name

    @property
    def dir_state(self) -> DirState:
        return self.__dir_state

    @property
    def sigs(self) -> dict[str, bytes]:
        return self.__sigs

    @property
    def previous(self) -> Optional[tuple[str, str]]:
        return self.__previous_vault

    def __enter__(self):
        return self

    def close(self):
        self.__data_tarball.close()
        self.__tmp_dir.cleanup()
        self.__tarball.close()
        if self.__data_unfold is not None:
            self.__data_unfold.cleanup()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def unfold(self):
        if self.__data_unfold is not None:
            return
        self.__data_unfold = TemporaryDirectory()
        self.__data_tarball.extractall(path=self.__data_unfold.name)

    def get(self, prefix: str, file: str) -> BytesIO | IO[bytes] | None:
        if prefix != _VAULT_ADD_PREFIX and prefix != _VAULT_UPDATE_PREFIX:
            raise ValueError(f'Invalid prefix {prefix}')
        if self.__data_unfold is not None:
            return open(op.join(self.__data_unfold.name, _VAULT_DATA_PREFIX, prefix, file), 'rb')
        else:
            return self.__data_tarball.extractfile(op.join(_VAULT_DATA_PREFIX, prefix, file))


def create_vault(vault_dir: str, backup_dir: str, password: str) -> VaultWriter:
    result = VaultWriter(vault_dir, backup_dir, password)
    log.info(f'Creating vault {result.id} in {vault_dir}')
    for file in os.listdir(backup_dir):
        result.create(file)
    return result


def open_vault(vault_file: str, password: str) -> VaultReader:
    log.info(f'Opening vault file {vault_file}')
    return VaultReader(vault_file, password)


def increment_vault(vault_dir: str, last_vault_file: str, password: str, backup_dir: str) -> VaultWriter:
    with open_vault(op.join(vault_dir, last_vault_file), password) as last_vault:
        current_vault = VaultWriter(vault_dir, backup_dir, password,
                                    (last_vault_file, last_vault.hash_value, last_vault.sigs, last_vault.data_files))
        log.info(f'Creating updated vault {current_vault.id} from {last_vault.id} in {vault_dir}')
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


class _WorkingDir:
    def __init__(self, base_backup: VaultReader, output_dir: str):
        if base_backup.type != VaultType.FULL:
            raise ValueError('Base backup must be a full backup')
        self.__base_backup = base_backup
        self.__working_dir = TemporaryDirectory()

        log.info(f'Unpacking base backup {base_backup.file_name}')
        self.__base_backup.unfold()
        self.__current_backup = self.__base_backup

        for f in self.current_data_files:
            log.info(f'Copying data file {f} from {self.__base_backup.file_name}')
            with open(op.join(self.__working_dir.name, f), 'wb') as file:
                with self.__current_backup.get(_VAULT_ADD_PREFIX, f) as created_file:
                    file.write(created_file.read())

        self.__output_dir = output_dir

    @property
    def output_dir(self) -> str:
        return self.__output_dir

    def patch(self, new_vault: VaultReader):
        if new_vault.type != VaultType.INCREMENTAL:
            raise ValueError('New vault must be an incremental vault')

        log.info(f'Unpacking incremental backup {new_vault.file_name}')
        new_vault.unfold()

        new_state = new_vault.dir_state

        diff = new_state - self.__current_backup.dir_state

        for file in diff['deleted']:
            log.info(f'Deleting file {file}')
            os.remove(op.join(self.__working_dir.name, file))

        for file in diff['created']:
            log.info(f'Copying file {file} from {new_vault.file_name}')
            with open(op.join(self.__working_dir.name, file), 'wb') as f:
                with new_vault.get(_VAULT_ADD_PREFIX, file) as created_file:
                    f.write(created_file.read())

        for file in diff['updated']:
            log.info(f'Updating file {file} from {new_vault.file_name}')
            with open(op.join(self.__working_dir.name, file), 'r+b') as f:
                with BytesIO() as tmp:
                    with new_vault.get(_VAULT_UPDATE_PREFIX, file) as update_patch:
                        pyrsync.patch(f, update_patch, tmp)
                        tmp.seek(0)
                        f.truncate(0)
                        f.seek(0)
                        f.write(tmp.read())

        self.__current_backup = new_vault

    @property
    def current_dir_state(self) -> DirState:
        return self.__current_backup.dir_state

    @property
    def current_hash_value(self) -> str:
        return self.__current_backup.hash_value

    @property
    def current_data_files(self) -> set[str]:
        return self.__current_backup.data_files

    @property
    def current_sigs(self) -> dict[str, bytes]:
        return self.__current_backup.sigs

    def __enter__(self):
        return self

    def dump(self):
        log.info(f'Dump expanded data to {self.__output_dir}')
        for sub in os.listdir(self.__working_dir.name):
            shutil.copy2(op.join(self.__working_dir.name, sub), self.__output_dir)

    def close(self):
        self.dump()
        self.__working_dir.cleanup()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def expand_vault(vault_dir: str, vault_file: str, password: str, target_dir: str):
    if len(os.listdir(target_dir)) != 0:
        raise ValueError(f'Target directory {target_dir} is not empty.')
    with open_vault(op.join(vault_dir, vault_file), password) as target_vault:
        working_list = [target_vault]
        tail = working_list[-1]
        while tail.type != VaultType.FULL:
            previous_vault, previous_hash = tail.previous
            to_add = open_vault(op.join(vault_dir, previous_vault), password)
            if to_add.hash_value != previous_hash:
                raise ValueError(f'Hash mismatch for {previous_vault} as previous vault of {tail.file_name}')
            working_list.append(to_add)
            tail = working_list[-1]
        if tail.type != VaultType.FULL:
            raise ValueError(f'Vault chain with no end.')
        working_list = list(reversed(working_list))
        base = working_list.pop(0)
        with _WorkingDir(base, target_dir) as working_dir:
            for vault in working_list:
                working_dir.patch(vault)
