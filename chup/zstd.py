import subprocess

DEFAULT_COMPRESS_LEVEL = 7


def compress(src: str, dst: str, compress_level: int = DEFAULT_COMPRESS_LEVEL):
    subprocess.run(['zstd', f'-{compress_level}', src, '-o', dst], check=True)


def decompress(src: str, dst: str):
    subprocess.run(['zstd', '-d', src, '-o', dst], check=True)
