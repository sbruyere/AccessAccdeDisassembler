import io
import argparse
import pathlib
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import access_project
import config
import disassemble
import vba_disassembler


ROOT = pathlib.Path(__file__).resolve().parents[1]


class IdentifierEncodingTests(unittest.TestCase):
    def test_ascii_and_windows_1252_identifiers(self):
        with patch.object(config, 'PROJECT_ENCODING', 'cp1252'):
            self.assertEqual(access_project.try_decode_identifier(b'Example'), 'Example')
            self.assertEqual(access_project.try_decode_identifier(b'Ausf\xfchren'), 'Ausf\u00fchren')
            self.assertEqual(access_project.try_decode_identifier(b''), '')
            self.assertEqual(access_project.try_decode_identifier(b'\x81'), '')

    def test_other_windows_code_page_can_be_selected(self):
        name = '\u041f\u0440\u0438\u043c\u0435\u0440'
        with patch.object(config, 'PROJECT_ENCODING', 'cp1251'):
            self.assertEqual(access_project.try_decode_identifier(name.encode('cp1251')), name)

    def test_project_inventory_retains_non_ascii_module_and_function_names(self):
        module = SimpleNamespace(name='module_fixup', functions=['function_fixup'])
        project_resource = SimpleNamespace(modules=[module])
        srp = SimpleNamespace(srp=SimpleNamespace(resources=[
            SimpleNamespace(module_flag=0, resource=SimpleNamespace(resource=project_resource))
        ]))
        values = {'module_fixup': b'Mod_Pr\xfcfung', 'function_fixup': b'Ausf\xfchren'}
        storage = SimpleNamespace(get_node_content=lambda path: io.BytesIO())
        with patch.object(config, 'PROJECT_ENCODING', 'cp1252'), \
                patch.object(access_project.vba_structs.SRP0, 'parse_stream', return_value=srp), \
                patch.object(access_project.VBAProject, '_load_vba_project'), \
                patch.object(access_project.VBAProject, '_resolve_fixup',
                             side_effect=lambda fixup, **kwargs: values[fixup]):
            project = access_project.VBAProject(storage)
        inventory = list(project.modules)
        self.assertEqual(inventory[0].name, 'Mod_Pr\u00fcfung')
        self.assertEqual(inventory[0].function_names, ['Ausf\u00fchren'])

    def test_cli_rejects_unknown_encoding_before_opening_a_database(self):
        result = subprocess.run([
            sys.executable, str(ROOT / 'disassemble.py'),
            '--accde-file-path', 'unused.accde', '--output-folder-path', 'unused-output',
            '--encoding', 'not-a-real-codec',
        ], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unknown project encoding', result.stderr)

    def test_codec_alias_is_normalized(self):
        self.assertEqual(disassemble.project_encoding('windows-1252'), 'cp1252')
        for encoding in ('utf-8', 'utf-16', 'utf-32', 'cp1251'):
            with self.subTest(encoding=encoding):
                self.assertEqual(disassemble.project_encoding(encoding), encoding)

    def test_non_text_codecs_are_rejected(self):
        for encoding in ('base64', 'base64_codec', 'hex', 'rot_13', 'zlib_codec'):
            with self.subTest(encoding=encoding):
                with self.assertRaises(argparse.ArgumentTypeError):
                    disassemble.project_encoding(encoding)

    def test_cli_rejects_non_text_codecs_before_opening_a_database(self):
        for encoding in ('base64', 'hex', 'rot_13'):
            with self.subTest(encoding=encoding):
                result = subprocess.run([
                    sys.executable, str(ROOT / 'disassemble.py'),
                    '--accde-file-path', 'unused.accde', '--output-folder-path', 'unused-output',
                    '--encoding', encoding,
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('Project encoding must decode bytes to text', result.stderr)

    def test_listings_are_written_as_utf8(self):
        module_name = 'Mod_\u041f\u0440\u0438\u043c\u0435\u0440'
        function_name = '\u041f\u0440\u0438\u043c\u0435\u0440'
        module = SimpleNamespace(function_name_to_function={
            function_name: SimpleNamespace(name=function_name)
        })
        project = SimpleNamespace(modules=[SimpleNamespace(name=module_name)],
                                  get_vba_module=lambda name: module)
        with tempfile.TemporaryDirectory() as temporary, \
                patch('access_file.AccessDBFile'), \
                patch.object(access_project, 'VBAProject', return_value=project), \
                patch.object(vba_disassembler, 'Disassembler') as decoder, \
                patch('sys.stdout', new_callable=io.StringIO):
            decoder.return_value.disassemble.return_value = 'synthetic listing'
            destination = pathlib.Path(temporary) / 'output'
            disassemble.disassemble_all(pathlib.Path('unused.accde'), destination)
            listing = (destination / module_name).read_bytes().decode('utf-8')
        self.assertIn(function_name, listing)


class OptionalDependencyTests(unittest.TestCase):
    def test_bundled_opcode_tables_load_when_angr_imports_are_blocked(self):
        script = textwrap.dedent('''
            import importlib.abc
            import pathlib
            import sys
            class BlockAngr(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == 'angr' or fullname.startswith('angr.'):
                        raise ImportError('angr deliberately unavailable')
            sys.meta_path.insert(0, BlockAngr())
            import config
            import vba_disassembler
            for mode in (True, False):
                config.IS_32_BIT_VBA6 = mode
                name = 'opcodes_vba6.json' if mode else 'opcodes_vba7.json'
                decoder = vba_disassembler.Disassembler(pathlib.Path('generated') / name)
                assert decoder._code_to_opcode
            assert 'angr' not in sys.modules
        ''')
        result = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class CleanupInstructionTests(unittest.TestCase):
    def test_cleanup_does_not_consume_the_following_instruction(self):
        for mode in (True, False):
            with patch.object(config, 'IS_32_BIT_VBA6', mode):
                mapping = ROOT / 'generated' / ('opcodes_vba6.json' if mode else 'opcodes_vba7.json')
                decoder = vba_disassembler.Disassembler(mapping)
                for name in ('FFreeVar', 'FFreeStr', 'FFreeAd'):
                    with self.subTest(vba6=mode, instruction=name):
                        cleanup = next(op for op in decoder._opcodes if op.name == name)
                        mnemonic = next(code for code in cleanup.mnemonics if code <= 250) if mode else cleanup.mnemonics[0]
                        header = struct.pack('<B' if mode else '<H', mnemonic)
                        addresses = (-0x38, -0x58, -0x78, -0x98) if mode else (-0x10038, -0x10058, -0x10078, -0x10098)
                        operands = struct.pack('<H', 8) + struct.pack('<hhhh' if mode else '<iiii', *addresses)
                        # Encode a separate, argument-free instruction as a sentinel.
                        sentinel = next(op for op in decoder._opcodes if not op.args and
                                        any(code <= 250 for code in op.mnemonics))
                        sentinel_code = next(code for code in sentinel.mnemonics if code <= 250)
                        trailer = struct.pack('<B' if mode else '<H', sentinel_code)
                        stream = io.BytesIO(header + operands + trailer)
                        instruction = decoder._read_next_opcode(stream)
                        self.assertEqual(instruction.opcode.name, name)
                        self.assertEqual(instruction.args_raw, [8, *addresses])
                        self.assertEqual(stream.tell(), len(header + operands))
                        following = decoder._read_next_opcode(stream)
                        self.assertEqual(following.mnemonic, sentinel_code)
                        self.assertEqual(stream.tell(), len(header + operands + trailer))


if __name__ == '__main__':
    unittest.main()
