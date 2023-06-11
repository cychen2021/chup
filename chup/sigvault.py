from typing import TextIO, Optional
import base64
import pyrsync
from dirtools import Dir
import tarfile
from tempfile import NamedTemporaryFile
import os


class SigVaultWriter(object):
    def __init__(self, tar_ball_path, base_path):
        self.base_path = base_path
        self.tar: Optional[tarfile.TarFile] = None
        self.__sig_file: Optional[TextIO] = None
        self.__tar_ball_path = tar_ball_path

    def add(self, file_to_sig: str):
        with open(os.path.join(self.base_path, file_to_sig), 'rb') as file_to_sig:
            with NamedTemporaryFile(delete=False) as f:
                pyrsync.signature(file_to_sig, f, 4, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)
                tmp_sig_file_path = f.name
            with open(tmp_sig_file_path, 'rb') as tmp_sig_file:
                self.__sig_file.write(f'{file_to_sig.name} {base64.encodebytes(tmp_sig_file.read()).decode("ascii")}')
            os.remove(tmp_sig_file_path)

    def close(self):
        self.__sig_file.close()
        with open(self.__sig_file.name, 'rb') as sig_file:
            sig_size = os.fstat(sig_file.fileno()).st_size
            sig_info = tarfile.TarInfo(f'{self.base_path.strip("/")}/.sig')
            sig_info.size = sig_size
            self.tar.addfile(tarinfo=sig_info, fileobj=sig_file)
        self.tar.close()
        os.remove(self.__sig_file.name)

    def __enter__(self):
        self.__sig_file = NamedTemporaryFile(delete=False, mode='wt')
        self.tar = tarfile.open(name=self.__tar_ball_path, mode='a')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SigVaultReader(object):
    def __init__(self, base_path='.', key=None):
        self.tars = []
        _dir = Dir(base_path)
        for sv_file in _dir.files('{0}.sigvault.*.tgz'.format(key),
                                  sort_reverse=True):
            archive = open(os.path.join(_dir.path, sv_file), 'rb')
            tar = tarfile.open(fileobj=archive, mode='r:gz')
            self.tars.append(tar)

    def extract(self, path):
        for tar in self.tars:
            try:
                m = tar.getmember(path)
                return tar.extractfile(m)
            except:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


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
