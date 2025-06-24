import re
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_name
import ida_typeinf
import ida_ua
import ida_xref
import ida_lines
import ida_idaapi

try:
    from .settings import SETTINGS
except ImportError:
    from settings import SETTINGS

def truncate_string(s, max_len):
    if len(s) > max_len:
        return s[:max_len-3] + '...'
    return s

def get_function_code(ea, max_len=None):
    if max_len is None:
        max_len = SETTINGS.max_prompt_tokens

    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return (truncate_string(str(cfunc), max_len), "C++")
    except ida_hexrays.DecompilationFailure:
        ida_kernwin.msg(f"AiDA: Decompilation failed at 0x{ea:X}, falling back to assembly.\n")

    func = ida_funcs.get_func(ea)
    if not func:
        return (f"// Error: Couldn't get function at 0x{ea:X}", "Error")

    lines = []
    for head in func.head_items():
        lines.append(ida_lines.generate_disasm_line(head, 0))

    assembly_code = "\n".join(lines)
    return (truncate_string(assembly_code, max_len), "Assembly")

def get_code_xrefs_to(ea):
    xrefs_to_list = []
    unique_callers = set()
    for xref in ida_xref.xrefblk_t().refs_to(ea, ida_xref.XREF_ALL):
        if len(xrefs_to_list) >= SETTINGS.xref_context_count:
            break
        if xref.iscode:
            pfn = ida_funcs.get_func(xref.frm)
            if pfn and pfn.start_ea != ea and pfn.start_ea not in unique_callers:
                unique_callers.add(pfn.start_ea)
                caller_name = ida_name.get_name(pfn.start_ea) or f"sub_{pfn.start_ea:X}"
                code, lang = get_function_code(pfn.start_ea, SETTINGS.xref_code_snippet_lines * 80)
                xrefs_to_list.append(f"// Called by: {caller_name} at 0x{pfn.start_ea:X}\n// Language: {lang}\n```cpp\n{code}\n```")
    return "\n\n".join(xrefs_to_list) if xrefs_to_list else "// No code cross-references found."

def get_code_xrefs_from(ea):
    xrefs_from_list = []
    unique_callees = set()
    func = ida_funcs.get_func(ea)
    if func:
        for head in func.head_items():
            if len(xrefs_from_list) >= SETTINGS.xref_context_count:
                break
            for xref in ida_xref.xrefblk_t().refs_from(head, ida_xref.XREF_ALL):
                if not (xref.iscode and xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]):
                    continue
                if len(xrefs_from_list) >= SETTINGS.xref_context_count:
                    break
                callee_pfn = ida_funcs.get_func(xref.to)
                if callee_pfn and callee_pfn.start_ea not in unique_callees:
                    unique_callees.add(callee_pfn.start_ea)
                    callee_name = ida_name.get_name(callee_pfn.start_ea) or f"sub_{callee_pfn.start_ea:X}"
                    code, lang = get_function_code(callee_pfn.start_ea, SETTINGS.xref_code_snippet_lines * 80)
                    entry = f"// Calls: {callee_name} at 0x{callee_pfn.start_ea:X}\n// Language: {lang}\n```cpp\n{code}\n```"
                    xrefs_from_list.append(entry)
    return "\n\n".join(xrefs_from_list) if xrefs_from_list else "// No calls to other functions found."

def get_struct_usage_context(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return "// Struct usage analysis requires a decompilable function."
    except ida_hexrays.DecompilationFailure:
        return "// Struct usage analysis requires a decompilable function."

    lvars = cfunc.get_lvars()
    if not lvars or len(lvars) == 0:
        return "// No local variables found for struct usage analysis."

    this_lvar = lvars[0]
    if not this_lvar.tif.is_ptr():
        return "// First argument is not a pointer, cannot analyze struct usage."

    struct_tif = this_lvar.tif.get_pointed_object()
    if not struct_tif.is_udt():
        return "// First argument does not point to a struct or union."

    struct_name = struct_tif.get_type_name() or f"struct_at_0x{ea:X}"

    class MemberAccessVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfunc, this_var_idx, struct_type):
            super().__init__(ida_hexrays.CV_PARENTS)
            self.cfunc = cfunc
            self.this_var_idx = this_var_idx
            self.struct_type = struct_type
            self.accesses = {}
            self.stringified_insns = {}

        def visit_expr(self, expr):
            if expr.op not in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                return 0

            base_expr = expr.x
            if base_expr.op == ida_hexrays.cot_var and base_expr.v.idx == self.this_var_idx:
                member_offset_bytes = expr.m

                parent_item = self.parents.back()
                parent_insn = parent_item.cinsn if parent_item else None

                if parent_insn:
                    insn_ea = parent_insn.ea
                    if insn_ea not in self.stringified_insns:
                        self.stringified_insns[insn_ea] = ida_lines.tag_remove(str(parent_insn)).strip()

                    usage_line = self.stringified_insns[insn_ea]

                    if member_offset_bytes not in self.accesses:
                        self.accesses[member_offset_bytes] = set()
                    self.accesses[member_offset_bytes].add(f"// 0x{expr.ea:X}: {usage_line}")
            return 0

    visitor = MemberAccessVisitor(cfunc, this_lvar.idx, struct_tif)
    visitor.apply_to(cfunc.body, None)

    if not visitor.accesses:
        return f"// No direct member accesses for struct '{struct_name}' found in this function."

    output = [f"// Member accesses for struct '{struct_name}' found in this function:"]
    for offset_bytes, usages in sorted(visitor.accesses.items()):
        offset_bits = offset_bytes * 8
        udm_tuple = struct_tif.get_udm_by_offset(offset_bits)
        if udm_tuple and udm_tuple[1]:
            member_name = udm_tuple[1].name
        else:
            member_name = f"offset_{offset_bytes:X}"

        output.append(f"// Member: {struct_name}::{member_name} (offset 0x{offset_bytes:X})")
        output.extend(sorted(list(usages)))
    return "\n".join(output)

def get_data_xrefs_for_struct(struct_tif):
    if not struct_tif or not struct_tif.is_udt():
        return "// Not a valid UDT (struct/union)."

    struct_name = struct_tif.get_type_name() or "anonymous_struct"
    output = [f"// Data cross-references to members of struct '{struct_name}':"]
    found_any = False

    try:
        for i, udm in enumerate(struct_tif.iter_udt()):
            member_tid = struct_tif.get_udm_tid(i)
            if member_tid == ida_idaapi.BADADDR:
                continue

            member_xrefs = []
            for xref in ida_xref.xrefblk_t().refs_to(member_tid, ida_xref.XREF_DATA):
                if len(member_xrefs) >= SETTINGS.xref_context_count:
                    member_xrefs.append(f"//  ... and more.")
                    break

                pfn = ida_funcs.get_func(xref.frm)
                func_name = ida_funcs.get_func_name(pfn.start_ea) if pfn else "UnknownFunction"

                xref_type_char = ida_xref.xrefchar(xref.type)
                access_type = "Write" if xref_type_char == 'w' else "Read" if xref_type_char == 'r' else "Offset"

                disasm_line = ida_lines.tag_remove(ida_lines.generate_disasm_line(xref.frm, 0))
                usage_line = f"//  - {access_type} in {func_name} at 0x{xref.frm:X}: {disasm_line.strip()}"
                member_xrefs.append(usage_line)

            if member_xrefs:
                found_any = True
                output.append(f"// Member: {struct_name}::{udm.name} (offset 0x{udm.offset//8:X})")
                output.extend(member_xrefs)

    except TypeError:
        return f"// Cannot iterate members of '{struct_name}', it might not be a struct or union."
    except Exception as e:
        return f"// Error while processing data xrefs for '{struct_name}': {e}"

    if not found_any:
        return f"// No data cross-references found for members of struct '{struct_name}'."

    return "\n".join(output)

def get_context_for_prompt(ea, include_struct_context=False):
    code, lang = get_function_code(ea)
    if lang == "Error":
        return {
            "ok": False,
            "message": code
        }

    context = {
        "ok": True,
        "code": code,
        "language": lang,
        "func_ea_hex": f"{ea:X}",
        "xrefs_to": get_code_xrefs_to(ea),
        "xrefs_from": get_code_xrefs_from(ea),
    }

    if include_struct_context:
        struct_tif = None
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc and cfunc.lvars and cfunc.lvars[0].tif.is_ptr():
                struct_tif = cfunc.lvars[0].tif.get_pointed_object()
        except ida_hexrays.DecompilationFailure:
            pass

        if struct_tif and struct_tif.is_udt():
            usage_context = get_struct_usage_context(ea)
            data_xref_context = get_data_xrefs_for_struct(struct_tif)
            context["struct_context"] = f"{usage_context}\n\n{data_xref_context}"
        else:
            context["struct_context"] = "// No struct context could be determined for this function."

    return context

def apply_struct_from_cpp(cpp_code, ea):
    try:
        struct_code = None
        match_md = re.search(r"```(?:cpp)?\s*(struct\s+.*?)\s*```", cpp_code, re.DOTALL | re.MULTILINE)
        if match_md:
            struct_code = match_md.group(1)
        elif cpp_code.strip().startswith("struct"):
            struct_code = cpp_code.strip()
        else:
            ida_kernwin.warning("AiDA: AI response did not contain a valid C++ struct definition.")
            print(f"AiDA Debug: Raw AI response:\n---\n{cpp_code}\n---")
            return

        match_name = re.search(r"struct\s+([a-zA-Z_][a-zA-Z0-9_]*)", struct_code)
        if not match_name:
            ida_kernwin.warning("AiDA: Could not find struct name in the extracted code.")
            print(f"AiDA Debug: Failed to find struct name in code:\n---\n{struct_code}\n---")
            return

        struct_name = match_name.group(1)
        idati = ida_typeinf.get_idati()

        final_struct_name = struct_name
        counter = 1
        if ida_typeinf.get_type_ordinal(idati, final_struct_name) != 0:
            choice = ida_kernwin.ask_buttons(
                "Yes", "No", "Cancel", 1,
                f"A struct named '{final_struct_name}' already exists. Overwrite it?")
            if choice == 1:
                ida_kernwin.msg(f"AiDA: Struct '{final_struct_name}' already exists, overwriting.\n")
            elif choice == 2:
                while ida_typeinf.get_type_ordinal(idati, final_struct_name) != 0:
                    final_struct_name = f"{struct_name}_{counter}"
                    counter += 1
                ida_kernwin.msg(f"AiDA: Struct '{struct_name}' already exists, creating new version: '{final_struct_name}'.\n")
            else:
                ida_kernwin.msg("AiDA: Struct creation cancelled by user.\n")
                return

        if final_struct_name != struct_name:
            struct_code = re.sub(f"struct\\s+{struct_name}", f"struct {final_struct_name}", struct_code, 1)

        err = ida_typeinf.parse_decls(idati, struct_code, None, ida_typeinf.HTI_DCL)
        if err != 0:
            ida_kernwin.warning(f"AiDA: Failed to parse the C++ struct (error code {err}).\n"
                              "Common causes are incorrect padding, member alignment, or syntax.\n\n"
                              f"Final C++ code sent to parser:\n---\n{struct_code}\n---")
            return

        ida_kernwin.msg(f"AiDA: Struct '{final_struct_name}' created/updated successfully.\n")

        ordinal = ida_typeinf.get_type_ordinal(idati, final_struct_name)
        if ordinal != 0:
            ida_kernwin.open_loctypes_window(ordinal)

        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui and vdui.cfunc:
            lvars = vdui.cfunc.lvars
            if lvars and len(lvars) > 0:
                lvar_to_set = lvars[0]
                if lvar_to_set.tif.is_ptr():
                    new_type_str = f'{final_struct_name}*'
                    tif = ida_typeinf.tinfo_t()
                    if tif.parse(new_type_str):
                        if vdui.set_lvar_type(lvar_to_set, tif):
                            ida_kernwin.msg(f"AiDA: Applied type '{new_type_str}' to the first argument '{lvar_to_set.name}'.\n")
                            vdui.refresh_view(True)
                        else:
                            ida_kernwin.warning(f"AiDA: Failed to apply type '{new_type_str}' to lvar '{lvar_to_set.name}'.")
                    else:
                        ida_kernwin.warning(f"AiDA: Failed to parse type string '{new_type_str}'.")
                else:
                    ida_kernwin.msg(f"AiDA: Did not apply type to first argument as it is not a pointer.\n")

    except Exception as e:
        import traceback
        ida_kernwin.warning(f"AiDA: Struct application failed with an exception: {e}\n{traceback.format_exc()}\nFull Response:\n{cpp_code}")