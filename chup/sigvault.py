from typing import TextIO, Optional
import base64
import pyrsync
import tarfile
from tempfile import TemporaryFile, NamedTemporaryFile, TemporaryDirectory
import os


class SigVaultWriter(object):
    def __init__(self, tar_ball_path, base_path):
        self.base_path = base_path
        self.tar: Optional[tarfile.TarFile] = None
        self.__sig_file: Optional[TextIO] = None
        self.__tar_ball_path = tar_ball_path

    def add(self, file_to_sig: str):
        with open(os.path.join(self.base_path, file_to_sig), 'rb') as file_to_sig:
            with TemporaryFile('w+b') as f:
                pyrsync.signature(file_to_sig, f, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
                f.seek(0)
                self.__sig_file.write(f'{os.path.relpath(file_to_sig.name, self.base_path)} {base64.encodebytes(f.read()).decode("ascii")}')

    def close(self):
        self.__sig_file.seek(0)
        sig_size = os.fstat(self.__sig_file.fileno()).st_size
        # self.tar.addfile(tarinfo=sig_info, fileobj=self.__sig_file)
        self.tar.add(self.__sig_file.name, arcname='.sig')
        self.tar.close()
        self.__sig_file.close()

    def __enter__(self):
        self.__sig_file = NamedTemporaryFile(mode='w+t')
        self.tar = tarfile.open(name=self.__tar_ball_path, mode='a')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SigVaultReader(object):
    def __init__(self, tarball_path: str):
        self.__tarball_path = tarball_path
        self.tar: Optional[tarfile.TarFile] = None

    def extract(self, path):
        self.tar.extract(os.path.join('data', path))

    @property
    def sigs(self) -> dict[str, bytes]:
        sigs = {}
        with TemporaryDirectory('w+') as p:
            self.tar.extract('.sig', p)
            with open(os.path.join(p, '.sig'), 'r') as sig_file:
                for line in sig_file:
                    sigs[line.split(' ')[0]] = base64.decodebytes(line.split(' ')[1].encode('ascii'))
        return sigs

    def __enter__(self):
        self.tar = tarfile.open(name=self.__tarball_path, mode='r')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tar.close()


class SigVault(object):
    @classmethod
    def open(cls, path, mode='r', base_path=None):
        if len(mode) > 1 or mode not in 'rw':
            raise ValueError("mode must be 'r' or 'w'")
        if mode == 'r':
            return SigVaultReader(path)
        else:
            return SigVaultWriter(path, base_path)


open_vault = SigVault.open
