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

from .settings import SETTINGS

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
    curr_ea = func.start_ea
    while curr_ea < func.end_ea and curr_ea != ida_idaapi.BADADDR:
        lines.append(ida_lines.generate_disasm_line(curr_ea, 0))
        curr_ea = ida_bytes.next_head(curr_ea, func.end_ea)

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
                caller_name = ida_name.get_name(pfn.start_ea)
                code, lang = get_function_code(pfn.start_ea, SETTINGS.xref_code_snippet_lines * 80)
                xrefs_to_list.append(f"// Called by: {caller_name} at 0x{pfn.start_ea:X}\n// Language: {lang}\n```cpp\n{code}\n```")
    return "\n\n".join(xrefs_to_list) if xrefs_to_list else "No code cross-references found."

def get_code_xrefs_from(ea):
    xrefs_from_list = []
    unique_callees = set()
    func = ida_funcs.get_func(ea)
    if func:
        for head in func.head_items():
            if len(xrefs_from_list) >= SETTINGS.xref_context_count:
                break
            for xref in ida_xref.xrefblk_t().refs_from(head, ida_xref.XREF_ALL):
                if not xref.iscode or xref.type not in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    continue
                if len(xrefs_from_list) >= SETTINGS.xref_context_count:
                    break
                callee_pfn = ida_funcs.get_func(xref.to)
                if callee_pfn and callee_pfn.start_ea not in unique_callees:
                    unique_callees.add(callee_pfn.start_ea)
                    callee_name = ida_name.get_name(callee_pfn.start_ea)
                    code, lang = get_function_code(callee_pfn.start_ea, SETTINGS.xref_code_snippet_lines * 80)
                    entry = f"// Calls: {callee_name} at 0x{callee_pfn.start_ea:X}\n// Language: {lang}\n```cpp\n{code}\n```"
                    xrefs_from_list.append(entry)
    return "\n\n".join(xrefs_from_list) if xrefs_from_list else "No calls to other functions found."

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
                    member_xrefs.append(f"// ... and more.")
                    break

                pfn = ida_funcs.get_func(xref.frm)
                func_name = ida_name.get_name(pfn.start_ea) if pfn else "UnknownFunction"

                xref_type_char = ida_xref.xrefchar(xref.type)
                access_type = "Write" if xref_type_char == 'w' else "Read" if xref_type_char == 'r' else "Offset"

                usage_line = f"//  - {access_type} in {func_name} at 0x{xref.frm:X}: {ida_lines.generate_disasm_line(xref.frm, 0)}"
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
    this_tif = this_lvar.tif
    if not this_tif.is_ptr():
        return "// First argument is not a pointer, cannot analyze struct usage."

    struct_tif = this_tif.get_pointed_object()
    if not struct_tif.is_udt():
        return "// First argument does not point to a struct or union."

    struct_tid = struct_tif.get_tid()
    if struct_tid == ida_idaapi.BADADDR:
        return "// Could not resolve struct type ID."

    struct_name = struct_tif.get_type_name() or f"struct_at_0x{ea:X}"

    member_accesses = {}

    func = ida_funcs.get_func(ea)
    if not func:
        return "// Cannot find function boundaries."

    insn = ida_ua.insn_t()
    for head in func.head_items():
        if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
            continue
        
        if not ida_ua.decode_insn(insn, head):
            continue

        for i in range(ida_ua.UA_MAXOP):
            op = insn.ops[i]
            if op.type == ida_ua.o_displ:
                path_ids, _ = ida_bytes.get_stroff_path(head, i)
                if path_ids and path_ids[0] == struct_tid:
                    op_val = op.addr
                    udm_tuple = struct_tif.get_udm_by_offset(op_val * 8)
                    if udm_tuple and udm_tuple[1]:
                        member_name = udm_tuple[1].name
                    else:
                        member_name = f"offset_{op_val:X}"

                    if member_name not in member_accesses:
                        member_accesses[member_name] = []

                    usage_line = f"// 0x{head:X}: {ida_lines.generate_disasm_line(head, 0)}"
                    if usage_line not in member_accesses[member_name]:
                        member_accesses[member_name].append(usage_line)

    if not member_accesses:
        return f"// No direct member accesses for struct '{struct_name}' found in this function."

    output = [f"// Member accesses for struct '{struct_name}' found in this function:"]
    for member, usages in sorted(member_accesses.items()):
        output.append(f"// Member: {member}")
        output.extend(usages)
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
            if cfunc and cfunc.get_lvars() and cfunc.get_lvars()[0].tif.is_ptr():
                struct_tif = cfunc.get_lvars()[0].tif.get_pointed_object()
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
        match_md = re.search(r"```(?:cpp)?\s*(struct\s+\w+\s*\{.*?\};)```", cpp_code, re.DOTALL)
        if match_md:
            cpp_code = match_md.group(1)

        match_name = re.search(r"struct\s+(\w+)", cpp_code)
        if not match_name:
            ida_kernwin.warning("AiDA: Could not find struct name in the AI response.")
            return

        struct_name = match_name.group(1)
        final_struct_name = None
        idati = ida_typeinf.get_idati()
        while True:
            suggested_name = struct_name if final_struct_name is None else final_struct_name
            final_struct_name = ida_kernwin.ask_str(
                suggested_name,
                ida_kernwin.HIST_TYPE,
                f"Enter the final name for the struct at 0x{ea:X}:")

            if not final_struct_name:
                return

            if ida_typeinf.get_type_ordinal(idati, final_struct_name) != 0:
                ida_kernwin.warning(f"A struct named '{final_struct_name}' already exists. Please choose a different name.")
            else:
                break

        cpp_code = cpp_code.replace(struct_name, final_struct_name)

        err = ida_typeinf.parse_decls(idati, cpp_code, None, ida_typeinf.HTI_DCL)
        if err != 0:
            ida_kernwin.warning(f"AiDA: Failed to parse the C++ struct (error code {err}).\n\nResponse was:\n{cpp_code}")
            return

        ida_kernwin.msg(f"AiDA: Struct '{final_struct_name}' created successfully.\n")
        ordinal = ida_typeinf.get_type_ordinal(idati, final_struct_name)
        if ordinal != 0:
            ida_kernwin.open_loctypes_window(ordinal)

        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui and vdui.cfunc:
            lvars = vdui.cfunc.get_lvars()
            if lvars and (lvars[0].name == 'this' or 'a1' in lvars[0].name):
                new_type_str = f'{final_struct_name}*'

                tif = ida_typeinf.tinfo_t()
                if tif.parse(new_type_str):
                    if vdui.set_lvar_type(lvars[0], tif):
                        ida_kernwin.msg(f"AiDA: Applied type '{new_type_str}' to the first argument.\n")
                        vdui.refresh_view(True)
                    else:
                        ida_kernwin.warning(f"AiDA: Failed to apply type '{new_type_str}'.")
                else:
                    ida_kernwin.warning(f"AiDA: Failed to parse type string '{new_type_str}'.")

    except Exception as e:
        ida_kernwin.warning(f"AiDA: Struct application failed: {e}\nFull Response:\n{cpp_code}")