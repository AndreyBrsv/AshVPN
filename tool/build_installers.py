"""Build system installers from the complete, already verified native bundle."""
import os
import hashlib
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path


def build_macos_helper(root, target, version, app):
    """Compile a small independently launched Cocoa maintenance bundle."""
    arch = {'macos-x64': 'x86_64', 'macos-arm64': 'arm64'}[target]
    contents = app / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    (contents / 'Resources').mkdir()
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'io.github.andreybrsv.ashapp.maintenance',
        'CFBundleName': 'Ashapp Maintenance', 'CFBundleExecutable': 'Maintenance',
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': version,
        'CFBundleVersion': version, 'LSMinimumSystemVersion': '12.0',
        'NSHighResolutionCapable': True, 'CFBundleIconFile': 'AppIcon.icns'}))
    icon = root / 'flutter/build/macos/Build/Products/Release/Ashapp.app/Contents/Resources/AppIcon.icns'
    if icon.is_file():
        shutil.copy2(icon, contents / 'Resources/AppIcon.icns')
    subprocess.run(['xcrun', 'swiftc', '-O', '-target', f'{arch}-apple-macos12.0',
                    str(root / 'tool/macos_maintenance.swift'), '-o', str(contents / 'MacOS/Maintenance')], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True)


def build_macos_maintenance_disk(root, target, version, output, installer):
    disk = output / f'Ashapp-v{version}-{target}-maintenance.dmg'
    with tempfile.TemporaryDirectory(prefix='ashapp-maintenance-') as folder:
        payload = Path(folder) / 'payload'
        app = payload / 'Ashapp Setup.app'
        build_macos_helper(root, target, version, app)
        resources = app / 'Contents/Resources'
        shutil.copy2(installer, resources / 'Installation.pkg')
        info = app / 'Contents/Info.plist'
        properties = plistlib.loads(info.read_bytes())
        with installer.open('rb') as source:
            properties['AshappPackageSHA256'] = hashlib.file_digest(source, 'sha256').hexdigest()
        info.write_bytes(plistlib.dumps(properties))
        shutil.copy2(root / 'LICENSE', resources / 'LICENSE')
        subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True)
        subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True)
        subprocess.run(['hdiutil', 'create', '-volname', 'Ashapp Setup', '-srcfolder',
                        str(payload), '-format', 'UDZO', str(disk)], check=True)
    if not disk.is_file() or disk.stat().st_size == 0:
        raise ValueError('Maintenance disk output is missing.')
    return disk


def build_installer(root, target, version, output):
    stem = f'Ashapp-v{version}-{target}-setup'
    if target == 'windows-x64':
        candidates = [os.environ.get('INNO_ISCC', ''), shutil.which('ISCC.exe') or '']
        for variable in ('ProgramFiles(x86)', 'ProgramFiles'):
            if os.environ.get(variable):
                candidates.append(str(Path(os.environ[variable]) / 'Inno Setup 6/ISCC.exe'))
        compiler = next((Path(item) for item in candidates if item and Path(item).is_file()), None)
        if compiler is None:
            raise ValueError('Inno Setup 6 is required to package the Windows installer; set INNO_ISCC.')
        subprocess.run([str(compiler), f'/DAppVersion={version}', f'/DSourceRoot={root}',
                        f'/DOutputDirectory={output}', f'/DOutputName={stem}',
                        str(root / 'tool/windows_setup.iss')], check=True)
        installer = output / f'{stem}.exe'
    elif target in ('macos-x64', 'macos-arm64'):
        installer = output / f'{stem}.pkg'
        with tempfile.TemporaryDirectory(prefix='ashapp-installer-') as folder:
            directory = Path(folder)
            payload = directory / 'payload'
            payload.mkdir()
            shutil.copytree(root / 'flutter/build/macos/Build/Products/Release/Ashapp.app',
                            payload / 'Ashapp.app', symlinks=True)
            components = directory / 'components.plist'
            # Replace one complete bundle in /Applications, never search for or
            # overwrite unrelated copies, and do not run privileged scripts.
            components.write_bytes(plistlib.dumps([{
                'RootRelativeBundlePath': 'Ashapp.app', 'BundleIsRelocatable': False,
                'BundleIsVersionChecked': True, 'BundleHasStrictIdentifier': True,
                'BundleOverwriteAction': 'upgrade'}]))
            subprocess.run(['pkgbuild', '--root', str(payload), '--component-plist', str(components),
                            '--identifier', 'io.github.andreybrsv.ashapp.installer',
                            '--version', version, '--install-location', '/Applications',
                            '--ownership', 'recommended', str(installer)], check=True)
    else:
        raise ValueError('Unknown installer target.')
    if not installer.is_file() or installer.stat().st_size == 0:
        raise ValueError('Native installer output is missing.')
    return installer
