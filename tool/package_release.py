"""Package a native CI build and record its exact public source identity."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.0.3'
FLUTTER_VERSION = '3.47.9'
FLUTTER_REVISION = 'c197ca5199'


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def package(target, output):
    if target not in ('windows-x64', 'macos-x64', 'macos-arm64'):
        raise ValueError('Unknown native target.')
    if target.startswith('windows') != (platform.system() == 'Windows'):
        raise ValueError('Build on the matching native operating system.')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT, text=True).strip():
        raise ValueError('Release packaging requires a clean source checkout.')
    sdk = json.loads(subprocess.check_output(
        ['flutter.bat' if os.name == 'nt' else 'flutter', '--version', '--machine'], text=True))
    if sdk['frameworkVersion'] != FLUTTER_VERSION or not sdk['frameworkRevision'].startswith(FLUTTER_REVISION):
        raise ValueError('The build must use the pinned Flutter SDK.')
    output.mkdir(parents=True, exist_ok=True)
    stem = f'Ashapp-v{VERSION}-{target}'
    archive = output / f'{stem}.zip'
    if target == 'windows-x64':
        bundle = ROOT / 'flutter/build/windows/x64/runner/Release'
        if not (bundle / 'ashapp.exe').is_file():
            raise ValueError('Windows release bundle is missing.')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as result:
            for item in sorted(bundle.rglob('*')):
                if item.is_file():
                    result.write(item, item.relative_to(bundle))
            result.write(ROOT / 'LICENSE', 'LICENSE')
            result.write(ROOT / 'vendor/LICENSE.Varckin', 'LICENSE.Varckin')
    else:
        bundle = ROOT / 'flutter/build/macos/Build/Products/Release/Ashapp.app'
        binary = bundle / 'Contents/MacOS/Ashapp'
        required = 'arm64' if target.endswith('arm64') else 'x86_64'
        actual = subprocess.check_output(['lipo', '-archs', str(binary)], text=True).split()
        if actual != [required]:
            raise ValueError(f'Expected only {required}, got {actual}.')
        # Cross-compiling on an Intel Mac is supported. Every embedded Mach-O
        # dependency must also contain the requested slice, including code assets.
        for item in bundle.rglob('*'):
            if item.is_file() and not item.is_symlink():
                inspected = subprocess.run(['lipo', '-archs', str(item)],
                                           capture_output=True, text=True)
                if inspected.returncode == 0 and required not in inspected.stdout.split():
                    raise ValueError(f'An embedded native dependency lacks {required}: {item.name}')
        # Keep the ad-hoc signature's default code-hash requirement. An
        # identifier-only requirement would let unrelated code impersonate us.
        subprocess.run(['codesign', '--force', '--deep', '--sign', '-',
                        '--identifier', 'io.github.andreybrsv.ashapp',
                        '--entitlements', str(ROOT / 'flutter/macos/Runner/Release.entitlements'),
                        str(bundle)], check=True)
        subprocess.run(['codesign', '--verify', '--deep', '--strict', str(bundle)], check=True)
        with tempfile.TemporaryDirectory(prefix='ashapp-package-') as directory:
            payload = Path(directory) / stem
            payload.mkdir()
            shutil.copytree(bundle, payload / 'Ashapp.app', symlinks=True)
            shutil.copy2(ROOT / 'LICENSE', payload / 'LICENSE')
            shutil.copy2(ROOT / 'vendor/LICENSE.Varckin', payload / 'LICENSE.Varckin')
            subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent',
                            str(payload), str(archive)], check=True)
    manifest = {'version': VERSION, 'source_commit': revision, 'target': target,
                'build_host_arch': platform.machine(), 'test_host_arch': platform.machine(),
                'flutter': sdk['frameworkVersion'], 'flutter_revision': sdk['frameworkRevision'],
                'dart': sdk['dartSdkVersion'], 'pubspec_lock_sha256': sha256(ROOT / 'flutter/pubspec.lock'),
                'vendor_sha256': sha256(ROOT / 'vendor/amneziawg-install.sh'),
                'archive': archive.name, 'sha256': sha256(archive),
                'run_url': (f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                            f"{os.environ['GITHUB_RUN_ID']}" if 'GITHUB_RUN_ID' in os.environ else None)}
    (output / f'{stem}.build.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'Packaged {archive.name}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('--output', type=Path, default=ROOT / 'release-output')
    args = parser.parse_args()
    package(args.target, args.output.resolve())
