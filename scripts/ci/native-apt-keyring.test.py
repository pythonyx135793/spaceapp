"""Pure archive/pin rejection controls: no package download or native provisioning."""
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

spec = importlib.util.spec_from_file_location("native_apt_keyring", Path(__file__).with_name("native-apt-keyring.py"))
keyring = importlib.util.module_from_spec(spec); spec.loader.exec_module(keyring)


def payload(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind, mode, uid in entries:
            value = tarfile.TarInfo(name); value.size = len(data); value.type = kind; value.mode = mode; value.uid = uid; value.gid = 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): value.linkname = "outside"
            archive.addfile(value, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return stream.getvalue()


def regular(name=keyring.MEMBER, data=b"synthetic public fixture", mode=0o644, uid=0):
    return (name, data, tarfile.REGTYPE, mode, uid)


class ArchiveKeyringControls(unittest.TestCase):
    def test_unique_regular_member_is_read_without_extracting_other_files(self):
        self.assertEqual(keyring.read_unique_member(payload([regular("usr/share/doc/public.txt", b"unused"), regular()])), b"synthetic public fixture")

    def test_duplicate_target_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(), regular()]))

    def test_equivalent_dot_prefix_cannot_hide_duplicate(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(), regular("./" + keyring.MEMBER)]))

    def test_absent_target_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular("other.gpg")]))

    def test_links_and_special_files_refused(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE]:
            with self.subTest(kind=kind), self.assertRaises(ValueError): keyring.read_unique_member(payload([(keyring.MEMBER, b"", kind, 0o644, 0)]))

    def test_directory_cannot_impersonate_keyring(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([(keyring.MEMBER, b"", tarfile.DIRTYPE, 0o755, 0)]))

    def test_unsafe_paths_refused(self):
        for path in ["../outside", "/absolute", "C:drive", "usr/../outside", "usr\\outside", "usr//outside"]:
            with self.subTest(path=path), self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(path), regular()]))

    def test_writable_or_nonroot_package_member_refused(self):
        for mode, uid in [(0o666, 0), (0o664, 0), (0o644, 1000)]:
            with self.subTest(mode=mode, uid=uid), self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(mode=mode, uid=uid)]))

    def test_oversized_member_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(data=b"a" * 65537)]))

    def test_excessive_member_count_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular(f"other-{i}", b"a") for i in range(64)] + [regular()]))

    def test_nonzero_trailing_payload_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(payload([regular()]) + b"hidden payload")

    def test_payload_bound_refused(self):
        with self.assertRaises(ValueError): keyring.read_unique_member(b"a" * (keyring.MAX_TAR_BYTES + 1))

    def test_truncated_tar_refused(self):
        with self.assertRaises((ValueError, tarfile.TarError)): keyring.read_unique_member(payload([regular()])[:513])

    def test_package_size_and_digest_required(self):
        for value in [b"", b"a" * (keyring.PACKAGE_BYTES - 1), b"a" * keyring.PACKAGE_BYTES]:
            with self.subTest(size=len(value)), self.assertRaises(ValueError): keyring.verify_package(value)

    def test_keyring_size_and_digest_required(self):
        for value in [b"", b"a" * (keyring.KEYRING_BYTES - 1), b"a" * keyring.KEYRING_BYTES]:
            with self.subTest(size=len(value)), self.assertRaises(ValueError): keyring.verify_keyring(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
