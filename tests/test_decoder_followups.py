import io
import pathlib
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import access_project
import config
import vba_disassembler

ROOT = pathlib.Path(__file__).resolve().parents[1]


def decoder_for(mode):
    name = 'opcodes_vba6.json' if mode else 'opcodes_vba7.json'
    return vba_disassembler.Disassembler(ROOT / 'generated' / name)


def encode_mnemonic(code, mode):
    if not mode:
        return struct.pack('<H', code)
    if code <= 250:
        return bytes([code])
    table, slot = divmod(code - 251, 256)
    return bytes([251 + table, slot])


def encode_instruction(decoder, name, values, mode):
    opcode = next(op for op in decoder._opcodes if op.name == name)
    assert len(opcode.args) == len(values), 'Fixture does not match the operand count'
    raw = encode_mnemonic(opcode.mnemonics[0], mode)
    for arg, value in zip(opcode.args, values):
        raw += value.to_bytes(arg.size, 'little', signed=True)
    return raw


def listing(decoder, bytecode, symbols=None, imports=None):
    function = SimpleNamespace(bytecode=bytecode, function_symbols=[])
    module = SimpleNamespace(function_name_to_function={'Test': function},
                             module_symbols=[SimpleNamespace(address=k, name=v)
                                             for k, v in (symbols or {}).items()],
                             imports=imports or [])
    return decoder.disassemble(module, 'Test')


class ExtendedOpcodeTests(unittest.TestCase):
    def test_all_primary_and_secondary_slots_are_contiguous_and_distinct(self):
        read = vba_disassembler.Disassembler._read_next_opcode_vba6
        for value in range(251):
            self.assertEqual(read(io.BytesIO(bytes([value]))), value)
        decoded = [read(io.BytesIO(bytes([prefix, slot])))
                   for prefix in range(251, 256) for slot in range(256)]
        self.assertEqual(decoded, list(range(251, 1531)))

    def test_missing_secondary_byte_raises_eof(self):
        for prefix in range(251, 256):
            with self.subTest(prefix=prefix), self.assertRaises(EOFError):
                vba_disassembler.Disassembler._read_next_opcode_vba6(io.BytesIO(bytes([prefix])))

    def test_known_extended_instructions_leave_the_next_instruction_intact(self):
        with patch.object(config, 'IS_32_BIT_VBA6', True):
            decoder = decoder_for(True)
            # Fixed byte fixtures, including a return and a two-word member store.
            stream = io.BytesIO(b'\xfc\xc9\xfd\xe7\xf8\xff\x10\x00\xf4\x14')
            returned = decoder._read_next_opcode(stream)
            self.assertEqual((returned.opcode.name, returned.args_raw, stream.tell()), ('Return', [], 2))
            stored = decoder._read_next_opcode(stream)
            self.assertEqual((stored.opcode.name, stored.args_raw, stream.tell()), ('FMemStStr', [-8, 16], 8))
            sentinel = decoder._read_next_opcode(stream)
            self.assertEqual((sentinel.opcode.name, sentinel.args_raw, stream.tell()), ('LitI2_Byte', [20], 10))


class OperandWidthTests(unittest.TestCase):
    def test_32bit_handler_operands_do_not_consume_the_following_instruction(self):
        fixtures = {
            'NextI4': (b'\xf8\xff\x10\x00', [-8, 16]),
            'FMemStStr': (b'\xf8\xff\x10\x00', [-8, 16]),
            'Return': (b'', []),
            'ExitProcHresult': (b'', []),
            'ExitProcCb': (b'\x08\x00', [8]),
        }
        with patch.object(config, 'IS_32_BIT_VBA6', True):
            decoder = decoder_for(True)
            for name, (operands, values) in fixtures.items():
                opcode = next(op for op in decoder._opcodes if op.name == name)
                for code in opcode.mnemonics:
                    with self.subTest(instruction=name, mnemonic=code):
                        header = encode_mnemonic(code, True)
                        stream = io.BytesIO(header + operands + b'\xf4\x14')
                        actual = decoder._read_next_opcode(stream)
                        self.assertEqual((actual.opcode.name, actual.args_raw), (name, values))
                        self.assertEqual(stream.tell(), len(header + operands))
                        following = decoder._read_next_opcode(stream)
                        self.assertEqual((following.opcode.name, following.args_raw), ('LitI2_Byte', [20]))
                        self.assertEqual(stream.tell(), len(header + operands) + 2)

    def test_64bit_word_widths_are_not_replaced_by_32bit_overrides(self):
        with patch.object(config, 'IS_32_BIT_VBA6', False):
            decoder = decoder_for(False)
            for name in ('NextI4', 'FMemStStr'):
                with self.subTest(instruction=name):
                    opcode = next(op for op in decoder._opcodes if op.name == name)
                    raw = encode_mnemonic(opcode.mnemonics[0], False) + struct.pack('<ii', -0x10008, 0x10010)
                    stream = io.BytesIO(raw)
                    self.assertEqual(decoder._read_next_opcode(stream).args_raw, [-0x10008, 0x10010])
                    self.assertEqual(stream.tell(), len(raw))


class LocalImportTests(unittest.TestCase):
    def project(self):
        project = access_project.VBAProject.__new__(access_project.VBAProject)
        project._all_functions = ['WrongGlobal0', 'WrongGlobal1']
        project._module_index_to_module_info = {
            0: access_project.VBAModuleInfo('First', 0, ['First0', 'First1']),
            1: access_project.VBAModuleInfo('Second', 1, ['Second0', 'Second1']),
        }
        return project

    def resolve(self, mode):
        project = self.project()
        fixup = SimpleNamespace(srp_index=9)
        resource = SimpleNamespace(module_flag=0, resource=SimpleNamespace(resource=SimpleNamespace(
            unk1=1, pointer=SimpleNamespace(srp_index=123))))
        srp_to_module = {9: 1, 123: 0}
        with patch.object(config, 'IS_32_BIT_VBA6', mode), \
                patch.object(project, '_resolve_fixup', return_value=resource), \
                patch.object(access_project.vba_structs, 'get_module_prop_a', return_value=18), \
                patch.object(project, '_get_srp_type_and_module_index',
                             side_effect=lambda index: (None, srp_to_module[index])):
            partial = project._partial_resolve_import(fixup)
            name = project._fully_resolve_import(partial)
        return partial, name

    def test_32bit_import_uses_fixup_srp_module_then_function_index(self):
        partial, name = self.resolve(True)
        self.assertIsInstance(partial, access_project.LocalFunctionImport32Bit)
        self.assertEqual(partial.srp_index, 9)
        self.assertEqual(name, 'Second1')

    def test_64bit_import_still_uses_pointer_srp_module(self):
        partial, name = self.resolve(False)
        self.assertIsInstance(partial, access_project.LocalFunctionImport64Bit)
        self.assertEqual(partial.srp_index, 123)
        self.assertEqual(name, 'First1')


class OperandRenderingTests(unittest.TestCase):
    def assert_first_frame_operand_resolves(self, names):
        for mode in (True, False):
            with patch.object(config, 'IS_32_BIT_VBA6', mode):
                decoder = decoder_for(mode)
                for name in names:
                    with self.subTest(vba6=mode, instruction=name):
                        opcode = next(op for op in decoder._opcodes if op.name == name)
                        values = [-8] + [20] * (len(opcode.args) - 1)
                        raw = encode_instruction(decoder, name, values, mode)
                        text = listing(decoder, raw, {-8: 'NamedFrameValue', 20: 'NotAnAddress'})
                        self.assertIn(name + '(NamedFrameValue', text)

    def test_single_value_cleanup_offsets_keep_variable_names(self):
        self.assert_first_frame_operand_resolves(('FFree1Var', 'FFree1Str', 'FFree1Ad'))

    def test_variant_conversion_destinations_keep_variable_names(self):
        self.assert_first_frame_operand_resolves((
            'CVarI2', 'CVarStr', 'CVarCy', 'CVarI4', 'CVarR4', 'CVarR8',
            'CVarAd', 'CVarUI1', 'CVarUnk', 'CVarDate', 'CVarVec', 'CVarUdt',
        ))

    def test_other_known_frame_operand_families_keep_variable_names(self):
        self.assert_first_frame_operand_resolves((
            'AddVar', 'EqTextVar', 'ConcatVar', 'FnInStr4Var', 'ForVar',
            'ForEachCollVar', 'FDupVar', 'LateMemLdVar', 'FMemStStr',
        ))

    def test_numeric_operands_do_not_resolve_to_coincidentally_matching_symbols(self):
        for mode in (True, False):
            with self.subTest(vba6=mode), patch.object(config, 'IS_32_BIT_VBA6', mode):
                decoder = decoder_for(mode)
                raw = encode_instruction(decoder, 'LitI2', [20], mode)
                raw += encode_instruction(decoder, 'BranchFVar', [20], mode)
                text = listing(decoder, raw, {20: 'NotAnAddress'})
                self.assertIn('LitI2(0x14)', text)
                self.assertIn('BranchFVar(0x14)', text)
                self.assertNotIn('NotAnAddress', text)

    def test_known_variable_offsets_and_string_imports_still_resolve(self):
        for mode in (True, False):
            with self.subTest(vba6=mode), patch.object(config, 'IS_32_BIT_VBA6', mode):
                decoder = decoder_for(mode)
                raw = encode_instruction(decoder, 'LitVarI2', [-8, 20], mode)
                raw += encode_instruction(decoder, 'LitVarStr', [-8, 0], mode)
                raw += encode_instruction(decoder, 'CVarRef', [-8, 20], mode)
                text = listing(decoder, raw, {-8: 'Temporary', 20: 'NotAnAddress'}, ['Synthetic text'])
                self.assertIn('LitVarI2(Temporary,0x14)', text)
                self.assertIn('LitVarStr(Temporary,Synthetic text<0x0>)', text)
                self.assertIn('CVarRef(Temporary,0x14)', text)
                self.assertNotIn('NotAnAddress', text)

    def test_cleanup_renders_count_and_every_variable_offset(self):
        for mode in (True, False):
            with patch.object(config, 'IS_32_BIT_VBA6', mode):
                decoder = decoder_for(mode)
                for name in ('FFreeVar', 'FFreeStr', 'FFreeAd'):
                    with self.subTest(vba6=mode, instruction=name):
                        opcode = next(op for op in decoder._opcodes if op.name == name)
                        offsets = (-8, -16, -24, -32)
                        raw = encode_mnemonic(opcode.mnemonics[0], mode) + struct.pack('<H', 8)
                        raw += struct.pack('<hhhh' if mode else '<iiii', *offsets)
                        symbols = dict(zip(offsets, ['One', 'Two', 'Three', 'Four']))
                        symbols[8] = 'NotTheCount'
                        text = listing(decoder, raw, symbols)
                        self.assertIn(name + '(0x8,One,Two,Three,Four)', text)
                        self.assertNotIn('NotTheCount', text)

    def test_out_of_range_import_indexes_remain_numeric(self):
        for mode in (True, False):
            with patch.object(config, 'IS_32_BIT_VBA6', mode):
                decoder = decoder_for(mode)
                for index in (-1, 2):
                    with self.subTest(vba6=mode, index=index):
                        raw = encode_instruction(decoder, 'LitStr', [index], mode)
                        self.assertIn('LitStr(' + hex(index) + ')', listing(decoder, raw, imports=['First', 'Second']))


if __name__ == '__main__':
    unittest.main()
