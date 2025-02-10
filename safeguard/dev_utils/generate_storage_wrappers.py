import argparse
import json
import sys
from typing import Any, List, TextIO, Optional, Tuple, Dict

class CodeWriter:
    def __init__(self, output: TextIO):
        self.out_wrapper = output
        self.indent_level = 0

    def indent(self) -> "CodeWriter":
        self.indent_level+=1
        return self
    
    def dedent(self) -> "CodeWriter":
        if self.indent_level == 0:
            raise RuntimeError("Cannot dedent further")
        self.indent_level-=1
        return self
    
    def write_line(self, s: str) -> "CodeWriter":
        prefix = "\t" * self.indent_level
        self.out_wrapper.write(prefix)
        self.out_wrapper.write(s)
        self.out_wrapper.write("\n")
        return self
    
    def write_literal(self, s: str) -> "CodeWriter":
        for l in s.split("\n"):
            self.write_line(l)
        return self

def get_struct_label_or_none(ty_def: dict) -> Optional[str]:
    if not isinstance(ty_def, dict):
        return None
    enc = ty_def.get("encoding", None)
    if not isinstance(enc, str):
        return None
    if enc != "inplace":
        return None    
    if "members" not in ty_def:
        return None
    
    lbl = ty_def.get("label", None)
    if not isinstance(lbl, str):
        return None
    if not lbl.startswith("struct "):
        return None
    suffix = lbl[len("struct "):]
    return suffix.split(".")[-1]

class StructField:
    def __init__(self, name: str, offset: int, slot: int, ty: "TypeRepresentation"):
        self.name = name
        self.offset = offset
        self.slot = slot
        self.ty = ty

class TypeRepresentation:
    @staticmethod
    def from_def(data: dict, id: str) -> Optional["TypeRepresentation"]:
        ty_def = data[id]
        enc = ty_def["encoding"]
        if enc == "mapping":
            k_repr = TypeRepresentation.from_def(data, ty_def["key"])
            v_repr = TypeRepresentation.from_def(data, ty_def["value"])
            if k_repr is None or v_repr is None:
                return None
            return MappingType(k_repr, v_repr)
        elif enc == "inplace":
            label = ty_def["label"]
            struct_name = get_struct_label_or_none(ty_def)
            if struct_name is None:
                return PrimitiveType(label, int(ty_def["numberOfBytes"], 10))
            else:
                mem = []
                for m in ty_def["members"]:
                    ty_raw = m["type"]
                    field_ty = TypeRepresentation.from_def(data, ty_raw)
                    if field_ty is None:
                        continue
                    field_name = m["label"]
                    offs = m["offset"]
                    slot = int(m["slot"], 10)
                    mem.append(StructField(field_name, offs, slot, field_ty))
                if len(mem) == 0:
                    return None
                return StructType(struct_name, mem, id)

class MappingType(TypeRepresentation):
    def __init__(self, k_type: TypeRepresentation, v_type: TypeRepresentation):
        super().__init__()
        self.k_type = k_type
        self.v_type = v_type

class GenerationContext:
    def __init__(self, masks: "MaskManager"):
        self.defer_generation = [] # type:List[StructType]
        self.already_generated = set()
        self.masks = masks

    def notify_generation(self, st: "StructType"):
        self.already_generated.add(st.id)
    
    def queue_deferral(self, st: "StructType"):
        for l in self.defer_generation:
            if l.id == st.id:
                return
            elif l.name == st.name:
                raise RuntimeError(f"Conflicting definitions for plain name {l.name}, have {l.id} vs {st.id}")
        self.defer_generation.append(st)

    def finalize(self, output: CodeWriter):
        did_work = True
        while did_work:
            did_work = False
            for i in self.defer_generation:
                if i.id in self.already_generated:
                    continue
                did_work = True
                i.generate_reader(output=output,generation_context=self)

        self.masks.finalize(output)

class PrimitiveType(TypeRepresentation):
    def __init__(self, label: str, width_in_bytes: int):
        self.label = label
        self.width_in_bytes = width_in_bytes

    def get_native_repr(self):
        if self.label == "address":
            return "common.Address"
        else:
            return "*uint256.Int"
        
    def get_hash_repr(self, base: str) -> str:
        if self.label == "address":
            return f"common.BytesToHash({base}.Bytes())"
        else:
            return "common.Hash(s.Bytes32())"
        
    def from_raw_storage(self, context: GenerationContext, parent_struct: str, raw_value_var: str, output: CodeWriter, offs: int) -> str:
        output.write_line(f"{parent_struct}.acc.SetBytes({raw_value_var}[:])")
        if offs != 0:
            output.write_line(f"{parent_struct}.acc.Rsh({parent_struct}.acc, {offs * 8})")
        if self.width_in_bytes != 32:
            output.write_line(f"{parent_struct}.acc.And({parent_struct}.acc, {context.masks.get_mask_for(self.label, self.width_in_bytes)})")
        if self.label == "address":
            return f"common.BytesToAddress({parent_struct}.acc.Bytes())"
        else:
            output.write_line("nativeRepr := new(uint256.Int)")
            output.write_line(f"nativeRepr.Set({parent_struct}.acc)")
            return "nativeRepr"

class StructType(TypeRepresentation):
    def __init__(self, struct_name: str, members: List[StructField], id: str):
        super().__init__()
        self.name = struct_name
        self.members = members
        self.id = id
        self.wrapper_name = f"{self.name}Reader"

    def generate_reader(self, output: CodeWriter, generation_context: GenerationContext):
        generation_context.notify_generation(self)
        # boiler plate
        output.write_line(f"type {self.wrapper_name} struct {{").indent().write_literal("""
db *state.StateDB
basePointer, acc *uint256.Int
account common.Address
""").dedent().write_line("}")
        
        output.write_line(f"func New{self.wrapper_name}(db *state.StateDB, acc common.Address) *{self.wrapper_name} {{").indent().write_literal(f"""
return &{self.wrapper_name}{{
    db: db,
    basePointer: new(uint256.Int),
    acc: new(uint256.Int),
    account: acc,
}}
""").dedent().write_line("}")
        
        output.write_line(f"func (s *{self.wrapper_name}) Relocate(where *uint256.Int) {{").indent().write_line("s.basePointer.Set(where)").dedent().write_line("}")

        for m in self.members:
            key_accum = [] #type: List[Tuple[str, TypeRepresentation]]
            ty_it = m.ty
            key_counter = 0
            while isinstance(ty_it, MappingType):
                key_accum.append((f"k{key_counter}", ty_it.k_type))
                ty_it = ty_it.v_type
                key_counter += 1
            assert isinstance(ty_it, StructType) or isinstance(ty_it, PrimitiveType)
            accessor_name = m.name[0].capitalize() + m.name[1:]
            param_names = map(lambda it: f"{it[0]} {it[1].get_native_repr()}",key_accum)
            param_list = ", ".join(param_names)
            output.write_line(f"func (s *{self.wrapper_name}) {accessor_name}({param_list}) {ty_it.get_native_repr()} {{").indent()
            output.write_line(f"s.acc.AddUint64(s.basePointer, {m.slot})")
            temp_counter = 0
            output.write_line("storageSlot := common.Hash(s.acc.Bytes32())")
            for i in key_accum:
                key_var = f"t{temp_counter}"
                output.write_line(f"{key_var} := {i[1].get_hash_repr(i[0])}")
                temp_counter += 1
                output.write_line(f"storageSlot := crypto.keccak256({key_var}[:], storageSlot[:])")
            output.write_line("rawValue := s.db.GetState(s.account, storageSlot)")
            res = ty_it.from_raw_storage(context=generation_context, parent_struct="s", raw_value_var="rawValue", output=output, offs=m.offset)
            output.write_line(f"return {res}")
            output.dedent().write_line("}")

    def from_raw_storage(self, context: GenerationContext, parent_struct: str, raw_value_var: str, output: CodeWriter, offs: int) -> str:
        context.queue_deferral(self)
        output.write_line(f"decodedReader := New{self.wrapper_name}({parent_struct}.db, {parent_struct}.account)")
        output.write_line(f"decodedReader.basePointer.SetBytes({raw_value_var}[:])")
        return "decodedReader"


    def get_native_repr(self):
        return f"*{self.wrapper_name}"

class MaskManager:
    def __init__(self):
        self.saved_masks = {} #type: Dict[str,Tuple[str,int]]
    
    
    def get_mask_for(self, ty_name: str, width_in_bytes: int) -> str:
        mName = f"gen_{ty_name}Mask"
        self.saved_masks[ty_name] = (mName, width_in_bytes)
        return mName
    
    def finalize(self, output: CodeWriter):
        for (_, data) in self.saved_masks.items():
            hex_const = "f" * int(data[1] * 2)
            output.write_line(f"var {data[0]} = uint256.MustFromHex(\"0x{hex_const}\")")

def generate_struct_wrapper(data: dict, struct_type_name: str, output: CodeWriter, ctxt: GenerationContext) -> None:
    data_def = None
    for (id, v) in data.items():
        struct_name = get_struct_label_or_none(v)
        if struct_name != struct_type_name:
            continue
        if data_def is not None:
            raise RuntimeError(f"Ambiguous struct name {struct_type_name}, can't generate")
        data_def = TypeRepresentation.from_def(data, id)
    if data_def is None:
        raise RuntimeError(f"No struct with name {struct_type_name} found")
    assert isinstance(data_def, StructType)
    data_def.generate_reader(output, ctxt)

def generate(data: Any, struct_types: List[str], base_output: TextIO) -> None:
    if not isinstance(data, dict):
        raise ValueError("Expected dictionary, got {type(data)}")
    if "types" not in data:
        raise ValueError("Missing required 'types' key")
    if not isinstance(data["types"], dict):
        raise ValueError("'types' must be a dictionary")
    type_lookup = data["types"]
    output = CodeWriter(base_output)
    context = GenerationContext(
        masks=MaskManager()
    )
    output.write_line("package main")
    output.write_literal("""
import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/holiman/uint256"
)

""")
    for s in struct_types:
        generate_struct_wrapper(type_lookup, s, output, context)
    context.finalize(output)

def main() -> None:
    parser = argparse.ArgumentParser(description='Process JSON file with string arguments')
    parser.add_argument('input_file', help='Input JSON file path')
    parser.add_argument('struct_types', nargs='+', help='One or more strings to process')
    parser.add_argument('--out-file', help='Output file path (defaults to stdout)')
    
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Failed to parse '{args.input_file}' as JSON", file=sys.stderr)
        sys.exit(1)
    
    output = open(args.out_file, 'w') if args.out_file else sys.stdout
    try:
        generate(data, args.struct_types, output)
    finally:
        if args.out_file:
            output.close()

if __name__ == '__main__':
    main()