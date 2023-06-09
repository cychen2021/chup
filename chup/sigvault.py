import pyrsync
from dirtools import Dir
import tarfile
from tempfile import NamedTemporaryFile
import os


class SigVaultWriter(object):
    def __init__(self, path, base_path):
        self.base_path = base_path
        self.archive = open(path, 'wb')
        self.tar = tarfile.open(fileobj=self.archive, mode='w:gz')
        self.__file_obj = None

    def add(self, path=None, file_obj=None):
        if path is not None:
            file_obj = open(os.path.join(self.base_path, path), 'rb')
            self.__file_obj = file_obj
        # sig = librsync.signature(file_obj)
        # Copy the sig to a file in open mode
        with NamedTemporaryFile() as f:
            pyrsync.signature(file_obj, f, 32, pyrsync.RS_RK_BLAKE2_SIG_MAGIC)

            sig_size = os.fstat(f.fileno()).st_size
            sig_info = tarfile.TarInfo(path)
            sig_info.size = sig_size
            self.tar.addfile(tarinfo=sig_info, fileobj=f)

    def close(self):
        self.tar.close()
        if self.__file_obj is not None:
            self.__file_obj.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SigVaultReader(object):
    def __init__(self, base_path='.', key=None):
        self.tars = []
        _dir = Dir(base_path)
        for sv_file in _dir.files('{0}.sigvault.*.tgz'.format(key),
                                  sort_reverse=True):
            archive = bltn_open(os.path.join(_dir.path, sv_file), 'rb')
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
    """ Helper for choosing SigVault{Reader/Writer}. """
    @classmethod
    def open(cls, path, mode='r', base_path=None):
        if len(mode) > 1 or mode not in 'rw':
            raise ValueError("mode must be 'r' or 'w'")
        if mode == 'r':
            return SigVaultReader(path)
        else:
            return SigVaultWriter(path, base_path)


open_vault = SigVault.open
