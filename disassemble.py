import os
import argparse
import codecs
import pathlib
import traceback

import config

VBA6_OPCODE_FILE = pathlib.Path(__file__).parent.joinpath("generated/opcodes_vba6.json")
VBA7_OPCODE_FILE = pathlib.Path(__file__).parent.joinpath("generated/opcodes_vba7.json")


def project_encoding(value: str) -> str:
    try:
        encoding = codecs.lookup(value).name
    except LookupError:
        raise argparse.ArgumentTypeError(f"Unknown project encoding: {value}") from None
    try:
        # lookup() also accepts binary transforms and str-to-str codecs.
        # Match the bytes.decode() operation used by the project reader.
        # Empty input short-circuits codec validation in CPython.
        bytes(4).decode(encoding)
    except (LookupError, TypeError):
        raise argparse.ArgumentTypeError(f"Project encoding must decode bytes to text: {value}") from None
    except UnicodeError:
        # A text codec can reject the probe's content (e.g. a required BOM).
        pass
    return encoding


def disassemble_all(file_path: pathlib.Path, output_folder_path: pathlib.Path):
    # The imports are inside because we need config might be modified
    import access_file
    import access_project
    import vba_disassembler

    if config.IS_32_BIT_VBA6:
        opcodes_file_path = VBA6_OPCODE_FILE
    else:
        opcodes_file_path = VBA7_OPCODE_FILE

    if not output_folder_path.exists():
        output_folder_path.mkdir()
    else:
        if not output_folder_path.is_dir():
            raise RuntimeError("Output directly is not a folder!")

    with access_file.AccessDBFile(str(file_path)) as db_file:
        tree_storage = db_file.get_vba_tree_storage()
        project = access_project.VBAProject(tree_storage)
        disassembler = vba_disassembler.Disassembler(opcodes_file_path)
        for module in project.modules:
            vba_module = project.get_vba_module(module.name)
            print(f"Module: {module.name}")
            with open(output_folder_path.joinpath(module.name), "w", encoding="utf-8") as module_file:
                for function in vba_module.function_name_to_function.values():
                    try:
                        module_file.write(f"Function: {function.name}\n")
                        module_file.write(disassembler.disassemble(vba_module, function.name))
                        module_file.write("\n")
                    except Exception:
                        print(f"Failed to parse func {function.name}:")
                        print(traceback.format_exc())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--accde-file-path", type=pathlib.Path, required=True)
    parser.add_argument("--output-folder-path", type=pathlib.Path, required=True)
    parser.add_argument('--vba6', action="store_true")
    parser.add_argument('--encoding', type=project_encoding, default=config.PROJECT_ENCODING,
                        help="Project identifier encoding (default: cp1252); use the project's Windows code page")
    args = parser.parse_args()

    if args.vba6:
        config.IS_32_BIT_VBA6 = True
    config.PROJECT_ENCODING = args.encoding

    disassemble_all(args.accde_file_path, args.output_folder_path)
