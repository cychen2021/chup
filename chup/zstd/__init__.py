import subprocess


def compress(src: str, dst: str, compress_level: int = 3):
    subprocess.run(['zstd', f'-{compress_level}', src, '-o', dst], check=True)


def decompress(src: str, dst: str):
    subprocess.run(['zstd', '-d', src, '-o', dst], check=True)
