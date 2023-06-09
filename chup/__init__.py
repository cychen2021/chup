import os
import click as clk
from typing import Any
import tomllib as tl
import os.path as op
import log
import utils

from vault import create_vault, increment_vault, expand_vault
from dirtools import Dir, DirState, compute_diff


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


@clk.group('chup', help="Chuyang Chen's incremental backup tool.")
def chup():
    pass


@chup.command('expand', help='Expand a vault.')
@clk.option('--vault-dir', '-d', 'vault_dir', help='The directory to store the vault.', default='.')
@clk.password_option(confirmation_prompt=False)
@clk.argument('vault_to_expand', required=True)
@clk.option('--output-dir', '-o', 'output_dir', help='The directory to dump the expanded files.', default='./output')
def expand(vault_dir: str, vault_to_expand: str, password: str, output_dir: str):
    expand_vault(vault_dir, vault_to_expand, password, output_dir)


@chup.command('backup', help='Conduct cloud backup.')
@clk.option('--config', '-c', 'config_path', help='The config file in TOML format.', default='/etc/chup.toml')
@clk.option('--debug', 'debug', default=None)
@clk.option('--full', '-f', 'full', is_flag=True, help='Perform a full backup.')
def backup(config_path: str, full: bool, debug: str):
    with open(config_path) as f:
        config = Config.from_dict(tl.loads(f.read()))
    if full:
        full_cloud_backup(config)
    else:
        incremental_cloud_backup(config, debug)


def full_local_backup(config: Config, target_dir: str) -> tuple[str, str]:
    log.info("Starting full backup.")
    with create_vault(target_dir, config.dir_to_backup(), config.password()) as new_vault:
        result = new_vault.result

    with open(result, 'rb') as f:
        hash_value = utils.hash_file_sha256(f)
    return result, hash_value


def incremental_local_backup(config: Config, target_dir: str, base_backup: str) -> tuple[str, str]:
    log.info(f'Starting incremental backup from base vault file {base_backup}.')
    with increment_vault(target_dir, base_backup, config.password(), config.dir_to_backup()) as new_vault:
        result = new_vault.result

    with open(result, 'rb') as f:
        hash_value = utils.hash_file_sha256(f)
    return result, hash_value


def full_cloud_backup(config: Config):
    filename, hash_value = full_local_backup(config, op.join(os.getcwd(), 'test'))


def incremental_cloud_backup(config: Config, debug: str = None):
    if debug is not None:
        filename, hash_value = incremental_local_backup(config, os.path.join(os.getcwd(), 'test'), debug)
