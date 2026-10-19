"""Extract one independently pinned public keyring; never install the package."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile

PACKAGE_BYTES = 11124
PACKAGE_SHA256 = "36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8"
KEYRING_BYTES = 3607
KEYRING_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
PACKAGE_NAME = "ubuntu-keyring_2023.11.28.1_all.deb"
KEYRING_NAME = "ubuntu-archive-keyring.gpg"
MEMBER = "usr/share/keyrings/ubuntu-archive-keyring.gpg"
MAX_TAR_BYTES = 256 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_package(blob):
    require(len(blob) == PACKAGE_BYTES and hashlib.sha256(blob).hexdigest() == PACKAGE_SHA256, "Pinned Ubuntu keyring package integrity failed")


def read_unique_member(blob):
    require(0 < len(blob) <= MAX_TAR_BYTES, "Unbounded Ubuntu keyring payload")
    result = None; seen = set()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as archive:
        for item in archive:
            require(len(seen) < 64, "Too many Ubuntu keyring payload members")
            name = item.name[2:] if item.name.startswith("./") else item.name
            if name == "": name = "."
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and ":" not in name and "\\" not in name and "\0" not in name and len(name) <= 160, "Unsafe Ubuntu keyring member path")
            require(str(path) == name and name not in seen and not item.pax_headers, "Aliased, repeated or extended Ubuntu keyring member")
            require(item.isfile() or item.isdir(), "Ubuntu keyring links/special files refused")
            require(0 <= item.size <= 65536, "Oversized Ubuntu keyring member")
            seen.add(name)
            if name == MEMBER:
                require(result is None and item.isfile() and 0 < item.size <= 65536 and item.uid == 0 and item.gid == 0 and not item.mode & 0o022, "Untrusted Ubuntu archive-keyring member")
                with archive.extractfile(item) as stream:
                    result = stream.read(65537)
                require(len(result) == item.size and len(result) <= 65536, "Truncated Ubuntu archive-keyring member")
        require(not any(blob[archive.offset:]), "Unexpected trailing Ubuntu keyring payload")
    require(result is not None, "Unique regular Ubuntu archive-keyring member absent")
    return result


def verify_keyring(blob):
    # Offline inspected primary-key fingerprints are tied to this exact byte pin.
    # No key import, network lookup, local trust metadata or new OpenPGP runtime.
    require(len(blob) == KEYRING_BYTES and hashlib.sha256(blob).hexdigest() == KEYRING_SHA256, "Pinned Ubuntu archive-keyring integrity failed")


def owned_paths(package, destination):
    parent = package.parent
    require(re.fullmatch(r"/var/tmp/spaceapp-native-apt-[1-9][0-9]{0,19}-[1-9][0-9]{0,3}-[A-Za-z0-9]{6}", str(parent)) is not None, "Unreviewed owned APT parent")
    require(package.name == PACKAGE_NAME and destination == parent / KEYRING_NAME, "Unreviewed owned keyring filenames")
    info = parent.lstat()
    require(parent.resolve() == parent and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022 and stat.S_IMODE(info.st_mode) == 0o755, "Untrusted owned APT parent")


def main():
    require(sys.platform == "linux" and os.getuid() != 0 and len(sys.argv) == 3, "Native keyring extraction requires an unprivileged Linux caller")
    package, destination = Path(sys.argv[1]), Path(sys.argv[2]); owned_paths(package, destination)
    before = package.lstat()
    require(package.resolve() == package and stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o444 and before.st_size == PACKAGE_BYTES, "Untrusted owned keyring package")
    descriptor = os.open(package, os.O_RDONLY | os.O_NOFOLLOW)
    process = None
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size) == (before.st_dev, before.st_ino, before.st_size), "Owned keyring package changed before verification")
        verify_package(os.read(descriptor, PACKAGE_BYTES + 1)); os.lseek(descriptor, 0, os.SEEK_SET)
        # Passing the same verified descriptor avoids reopening a substituted path.
        # dpkg-deb only decodes the payload; maintainer scripts are never invoked.
        # The native JS supervisor bounds this whole owned process group to30s.
        process = subprocess.Popen(["/usr/bin/dpkg-deb", "--fsys-tarfile", f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        payload = process.stdout.read(MAX_TAR_BYTES + 1)
        require(len(payload) <= MAX_TAR_BYTES, "Decoded Ubuntu keyring payload exceeds limit")
        code = process.wait(timeout=1)
        detail = process.stderr.read(4097)
        require(code == 0 and len(detail) <= 4096, "Read-only Ubuntu keyring package decoder failed")
        keyring = read_unique_member(payload); verify_keyring(keyring)
        os.lseek(descriptor, 0, os.SEEK_SET); verify_package(os.read(descriptor, PACKAGE_BYTES + 1))
        owned_paths(package, destination)
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(output, "wb") as stream: stream.write(keyring)
        os.chmod(destination, 0o444)
        value = destination.lstat()
        require(destination.resolve() == destination and stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o444, "Owned archive-keyring permissions changed")
        verify_keyring(destination.read_bytes())
        print(json.dumps({"packageBytes": PACKAGE_BYTES, "packageSha256": PACKAGE_SHA256, "keyringBytes": KEYRING_BYTES, "keyringSha256": KEYRING_SHA256, "path": str(destination), "hostKeyringUsed": False, "packageInstalled": False, "maintainerScriptsExecuted": False}))
    finally:
        os.close(descriptor)
        if process is not None:
            if process.poll() is None: process.kill()
            process.stdout.close(); process.stderr.close(); process.wait(timeout=1)


if __name__ == "__main__":
    main()
