#include "aida_pro.hpp"

namespace ida_utils
{
    struct decomp_request_t : public exec_request_t
    {
        std::pair<std::string, std::string> result;
        get_code_callback_t callback;

        decomp_request_t(get_code_callback_t cb) : callback(std::move(cb)) {}

        ssize_t idaapi execute() override
        {
            if (callback)
            {
                callback(result);
            }
            delete this;
            return 0;
        }
    };

    struct match_info {
        size_t start;
        size_t len;
        qstring replacement;

        bool operator<(const match_info& other) const {
            if (start != other.start)
                return start < other.start;
            return len > other.len;
        }
    };

    static qstring create_markup_replacement(ea_t ea, const std::string& text_to_markup, int color_code)
    {
        qstring replacement;
        tag_addr(&replacement, ea);
        replacement.append(SCOLOR_ON, 1);
        replacement.append(color_code);
        replacement.append(text_to_markup.c_str());
        replacement.append(SCOLOR_OFF, 1);
        replacement.append(color_code);
        tag_addr(&replacement, ea);
        return replacement;
    }

    std::string markup_text_with_addresses(const std::string& text)
    {
        std::vector<match_info> matches;

        static const std::regex pattern(
            "\\b(sub|loc|j_sub|case|def|byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte|asc|str|stru|arr|off|seg|ptr|unk|align)_([0-9A-Fa-f]+)\\b",
            std::regex_constants::icase);

        auto words_begin = std::sregex_iterator(text.begin(), text.end(), pattern);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i)
        {
            std::smatch match = *i;
            std::string full_match_str = match.str(0);
            std::string hex_str = match.str(2);

            ea_t ea = BADADDR;
            try { ea = std::stoull(hex_str, nullptr, 16); }
            catch (...) { continue; }

            if (is_mapped(ea))
            {
                match_info mi;
                mi.start = match.position(0);
                mi.len = match.length(0);
                mi.replacement = create_markup_replacement(ea, full_match_str, COLOR_CNAME);
                matches.push_back(mi);
            }
        }

        const char* special_names[] = { "start", "WinMain", "main" };
        for (const char* name : special_names)
        {
            ea_t ea = get_name_ea(BADADDR, name);
            if (ea != BADADDR)
            {
                std::string s_name(name);
                size_t pos = text.find(s_name, 0);
                while (pos != std::string::npos)
                {
                    bool pre_ok = (pos == 0) || !is_word_char(text[pos - 1]);
                    bool post_ok = (pos + s_name.length() >= text.length()) || !is_word_char(text[pos + s_name.length()]);
                    if (pre_ok && post_ok)
                    {
                        match_info mi;
                        mi.start = pos;
                        mi.len = s_name.length();
                        mi.replacement = create_markup_replacement(ea, s_name, COLOR_CNAME);
                        matches.push_back(mi);
                    }
                    pos = text.find(s_name, pos + 1);
                }
            }
        }

        static const std::regex hex_pattern("\\b(0x[0-9A-Fa-f]{7,16})\\b", std::regex_constants::icase);
        auto hex_begin = std::sregex_iterator(text.begin(), text.end(), hex_pattern);
        auto hex_end = std::sregex_iterator();

        for (std::sregex_iterator i = hex_begin; i != hex_end; ++i)
        {
            std::smatch match = *i;
            std::string hex_str = match.str(1);

            ea_t ea = BADADDR;
            try { ea = std::stoull(hex_str, nullptr, 16); }
            catch (...) { continue; }

            if (is_mapped(ea))
            {
                match_info mi;
                mi.start = match.position(0);
                mi.len = match.length(0);
                mi.replacement = create_markup_replacement(ea, hex_str, COLOR_DREF);
                matches.push_back(mi);
            }
        }

        std::sort(matches.begin(), matches.end());
        std::vector<match_info> final_matches;
        if (!matches.empty())
        {
            final_matches.push_back(matches[0]);
            for (size_t i = 1; i < matches.size(); ++i)
            {
                if (matches[i].start >= (final_matches.back().start + final_matches.back().len))
                {
                    final_matches.push_back(matches[i]);
                }
            }
        }

        qstring result;
        size_t last_pos = 0;
        for (const auto& mi : final_matches)
        {
            result.append(text.c_str() + last_pos, mi.start - last_pos);
            result.append(mi.replacement);
            last_pos = mi.start + mi.len;
        }
        result.append(text.c_str() + last_pos);

        return result.c_str();
    }

    static std::string truncate_string(const std::string& s, size_t max_len)
    {
        if (s.length() > max_len)
        {
            return s.substr(0, max_len - 3) + "...";
        }
        return s;
    }

    std::pair<std::string, std::string> get_function_code(ea_t ea, size_t max_len, bool force_assembly)
    {
        if (max_len == 0)
        {
            max_len = g_settings.max_prompt_tokens;
        }

        if (!force_assembly && init_hexrays_plugin())
        {
            try
            {
                func_t* pfn_for_decomp = get_func(ea);
                if (pfn_for_decomp != nullptr)
                {
                    cfuncptr_t cfunc = decompile(pfn_for_decomp);
                    if (cfunc != nullptr)
                    {
                        qstring code_qstr;
                        qstring_printer_t printer(cfunc, code_qstr, false);
                        cfunc->print_func(printer);
                        return { truncate_string(code_qstr.c_str(), max_len), "C/C++" };
                    }
                }
            }
            catch (const vd_failure_t&)
            {
                msg("AiDA: Decompilation failed at 0x%a, falling back to assembly.\n", ea);
            }
        }

        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            qstring err;
            err.sprnt("// Error: Couldn't get function at 0x%a", ea);
            return { err.c_str(), "Error" };
        }

        text_t disasm_text;
        gen_disasm_text(disasm_text, pfn->start_ea, pfn->end_ea, true);

        std::stringstream ss;
        for (const twinline_t& tw_line : disasm_text)
        {
            qstring clean_line;
            tag_remove(&clean_line, tw_line.line.c_str());
            ss << clean_line.c_str() << '\n';
        }
        return { truncate_string(ss.str(), max_len), "Assembly" };
    }

    void get_function_code(ea_t ea, get_code_callback_t callback, size_t max_len, bool force_assembly)
    {
        std::thread([ea, max_len, callback, force_assembly]() {
            auto req = new decomp_request_t(callback);
            req->result = get_function_code(ea, max_len, force_assembly);
            execute_sync(*req, MFF_NOWAIT);
        }).detach();
    }

    static void recursive_get_xrefs_context(
        ea_t target_ea,
        const settings_t& settings,
        bool find_callers,
        int current_depth,
        std::set<ea_t>& visited_funcs,
        qstring& result,
        int& count)
    {
        if (current_depth >= settings.xref_analysis_depth || count >= settings.xref_context_count)
            return;

        if (visited_funcs.count(target_ea))
            return;
        visited_funcs.insert(target_ea);

        qstring name;
        get_func_name(&name, target_ea);
        if (name.empty())
            name.sprnt("sub_%a", target_ea);

        auto code_pair = get_function_code(target_ea, settings.xref_code_snippet_lines * 80);
        const char* direction = find_callers ? "Called by" : "Calls";

        result.cat_sprnt("// --- %s: %s at 0x%a (Depth: %d) ---\n",
            direction, name.c_str(), target_ea, current_depth);
        result.cat_sprnt("// Language: %s\n", code_pair.second.c_str());
        result.cat_sprnt("```cpp\n%s\n```\n\n", code_pair.first.c_str());
        count++;

        if (find_callers)
        {
            xrefblk_t xb;
            for (bool ok = xb.first_to(target_ea, XREF_ALL); ok && count < settings.xref_context_count; ok = xb.next_to())
            {
                if (xb.iscode)
                {
                    func_t* pfn = get_func(xb.from);
                    if (pfn)
                        recursive_get_xrefs_context(pfn->start_ea, settings, find_callers, current_depth + 1, visited_funcs, result, count);
                }
            }
        }
        else // find callees
        {
            func_t* pfn = get_func(target_ea);
            if (pfn)
            {
                func_item_iterator_t fii(pfn);
                for (bool ok = fii.first(); ok && count < settings.xref_context_count; ok = fii.next_addr())
                {
                    xrefblk_t xb;
                    for (bool ok_ref = xb.first_from(fii.current(), XREF_ALL); ok_ref && count < settings.xref_context_count; ok_ref = xb.next_from())
                    {
                        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
                        {
                            func_t* callee_pfn = get_func(xb.to);
                            if (callee_pfn)
                                recursive_get_xrefs_context(callee_pfn->start_ea, settings, find_callers, current_depth + 1, visited_funcs, result, count);
                        }
                    }
                }
            }
        }
    }

    std::string get_code_xrefs_to(ea_t ea, const settings_t& settings)
    {
        qstring result;
        int count = 0;
        std::set<ea_t> visited_funcs;
        recursive_get_xrefs_context(ea, settings, true, 0, visited_funcs, result, count);
        if (result.empty())
            return "// No code cross-references found.";
        return result.c_str();
    }

    std::string get_code_xrefs_from(ea_t ea, const settings_t& settings)
    {
        qstring result;
        int count = 0;
        std::set<ea_t> visited_funcs;
        recursive_get_xrefs_context(ea, settings, false, 0, visited_funcs, result, count);
        if (result.empty())
            return "// No calls to other functions found.";
        return result.c_str();
    }

    std::string get_struct_usage_context(ea_t ea)
    {
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return "// Struct usage analysis requires a valid function context.";

        cfuncptr_t cfunc(nullptr); // Initialize to null explicitly
        try
        {
            mba_ranges_t mbr(pfn);
            cfunc = decompile(mbr);
        }
        catch (const vd_failure_t&)
        {
            return "// Struct usage analysis requires a decompilable function.";
        }

        if (!cfunc)
            return "// Struct usage analysis requires a decompilable function.";

        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars || lvars->empty())
            return "// No local variables found for struct usage analysis.";

        int this_var_idx = -1;
        tinfo_t struct_tif;

        for (int i = 0; i < lvars->size(); ++i)
        {
            lvar_t& lvar = (*lvars)[i];
            if (lvar.is_thisarg() || (lvar.is_arg_var() && lvar.type().is_ptr() && lvar.type().get_pointed_object().is_udt()))
            {
                this_var_idx = i;
                struct_tif = lvar.type().get_pointed_object();
                break;
            }
        }

        if (this_var_idx == -1 || !struct_tif.is_udt())
        {
            return "// Could not identify a struct pointer argument for usage analysis.";
        }

        qstring struct_name;
        struct_tif.get_type_name(&struct_name);
        if (struct_name.empty())
            struct_name.sprnt("struct_at_0x%a", ea);

        struct member_access_visitor_t : public ctree_visitor_t
        {
            cfunc_t* cfunc;
            int this_var_idx;
            std::map<uint64, std::set<std::string>> accesses;
            std::map<ea_t, std::string> stringified_insns;

            member_access_visitor_t(cfunc_t* cf, int idx)
                : ctree_visitor_t(CV_PARENTS), cfunc(cf), this_var_idx(idx) {}

            cinsn_t* get_parent_insn()
            {
                for (ssize_t i = parents.size() - 1; i >= 0; --i)
                {
                    citem_t* p = parents[i];
                    if (!p->is_expr())
                        return (cinsn_t*)p;
                }
                return nullptr;
            }

            int idaapi visit_expr(cexpr_t* expr) override
            {
                if ((expr->op == cot_memptr || expr->op == cot_memref) && expr->x && expr->x->op == cot_var)
                {
                    if (expr->x->v.idx == this_var_idx)
                    {
                        uint64 member_offset = expr->m;
                        cinsn_t* parent_insn = get_parent_insn();
                        if (parent_insn)
                        {
                            ea_t insn_ea = parent_insn->ea;
                            if (stringified_insns.find(insn_ea) == stringified_insns.end())
                            {
                                qstring line;
                                qstring_printer_t pr(cfunc, line, false);
                                parent_insn->print(0, pr);
                                tag_remove(&line);
                                stringified_insns[insn_ea] = line.c_str();
                            }
                            qstring usage_line;
                            usage_line.sprnt("// 0x%a: %s", expr->ea, stringified_insns[insn_ea].c_str());
                            accesses[member_offset].insert(usage_line.c_str());
                        }
                        else
                        {
                            qstring insn_str;
                            expr->print1(&insn_str, cfunc);
                            tag_remove(&insn_str);
                            qstring usage_line;
                            usage_line.sprnt("// 0x%a: %s", expr->ea, insn_str.c_str());
                            accesses[member_offset].insert(usage_line.c_str());
                        }
                    }
                }
                return 0;
            }
        };

        member_access_visitor_t visitor(cfunc, this_var_idx);
        visitor.apply_to(&cfunc->body, nullptr);

        if (visitor.accesses.empty())
        {
            qstring result;
            result.sprnt("// No direct member accesses for struct '%s' found in this function.", struct_name.c_str());
            return result.c_str();
        }

        qstring output;
        output.sprnt("// Member accesses for struct '%s' found in this function:\n", struct_name.c_str());
        for (const auto& pair : visitor.accesses)
        {
            udm_t udm;
            if (struct_tif.get_udm_by_offset(&udm, pair.first * 8) >= 0)
            {
                output.cat_sprnt("//   - Member: %s (offset 0x%X)\n", udm.name.c_str(), (uint32)udm.offset / 8);
            }
            else
            {
                output.cat_sprnt("//   - Member at offset 0x%X\n", (uint32)pair.first);
            }
            for (const auto& usage : pair.second)
            {
                output.cat_sprnt("//     usage: %s\n", usage.c_str());
            }
        }
        return output.c_str();
    }

    std::string get_data_xrefs_for_struct(const tinfo_t& struct_tif, const settings_t& settings)
    {
        if (!struct_tif.is_udt())
            return "// Not a valid UDT (struct/union).";

        qstring struct_name;
        struct_tif.get_type_name(&struct_name);
        if (struct_name.empty())
            struct_name = "anonymous_struct";

        qstring output;
        output.sprnt("// Data cross-references to members of struct '%s':\n", struct_name.c_str());
        bool found_any = false;

        udt_type_data_t udt_data;
        if (!struct_tif.get_udt_details(&udt_data))
            return output.c_str(); // No UDT details, return empty xrefs

        for (size_t i = 0; i < udt_data.size(); ++i)
        {
            const udm_t& udm = udt_data[i];
            tid_t member_tid = struct_tif.get_udm_tid(i);
            if (member_tid == BADADDR)
                continue;

            qstrvec_t member_xrefs;
            xrefblk_t xb;
            for (bool ok = xb.first_to(member_tid, XREF_DATA); ok && member_xrefs.size() < (size_t)settings.xref_context_count; ok = xb.next_to())
            {
                qstring func_name_qstr = "UnknownFunction";
                func_t* pfn = get_func(xb.from);
                if (pfn)
                    get_func_name(&func_name_qstr, pfn->start_ea);
                std::string func_name = func_name_qstr.c_str();

                char xtype_char = xrefchar(xb.type);
                const char* access_type = (xtype_char == 'w') ? "Write" : (xtype_char == 'r') ? "Read" : "Offset";

                qstring disasm_line_qstr;
                generate_disasm_line(&disasm_line_qstr, xb.from, GENDSM_REMOVE_TAGS);
                disasm_line_qstr.trim2();
                std::string disasm_line = disasm_line_qstr.c_str();

                qstring line;
                line.sprnt("//  - %s in %s at 0x%a: %s", access_type, func_name.c_str(), xb.from, disasm_line.c_str());
                member_xrefs.push_back(line);
            }

            if (!member_xrefs.empty())
            {
                found_any = true;
                output.cat_sprnt("// Member: %s::%s (offset 0x%X)\n", struct_name.c_str(), udm.name.c_str(), (uint32)(udm.offset / 8));
                for (const auto& xref_line : member_xrefs)
                {
                    output.append(xref_line);
                    output.append("\n");
                }
                output.append("\n");
            }
        }

        if (!found_any)
        {
            output.sprnt("// No data cross-references found for members of struct '%s'.", struct_name.c_str());
        }

        return output.c_str();
    }

    nlohmann::json get_context_for_prompt(ea_t ea, bool include_struct_context, size_t max_len)
    {
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            qstring err_msg;
            err_msg.sprnt("No function found at address 0x%a.", ea);
            return { {"ok", false}, {"message", err_msg.c_str()} };
        }

        auto code_pair = get_function_code(ea, max_len);
        if (code_pair.second == "Error")
        {
            return { {"ok", false}, {"message", code_pair.first} };
        }

        qstring ea_hex_str;
        ea_hex_str.sprnt("%a", ea);

        nlohmann::json context = {
            {"ok", true},
            {"code", code_pair.first},
            {"language", code_pair.second},
            {"func_ea_hex", ea_hex_str.c_str()},
            {"xrefs_to", get_code_xrefs_to(ea, g_settings)},
            {"xrefs_from", get_code_xrefs_from(ea, g_settings)},
        };

        tinfo_t func_tif;
        if (get_tinfo(&func_tif, ea))
        {
            qstring func_proto;
            func_tif.print(&func_proto, "", 0, 0, PRTYPE_1LINE | PRTYPE_NOARGS);
            context["func_prototype"] = func_proto.c_str();
        }
        else
        {
            context["func_prototype"] = "// Could not retrieve function prototype.";
        }

        context["local_vars"] = "// Decompilation failed or not available.";
        context["decompiler_warnings"] = "// No decompiler warnings.";
        if (include_struct_context)
        {
            context["struct_context"] = "// Decompilation failed or not available.";
        }

        if (init_hexrays_plugin())
        {
            try
            {
                mba_ranges_t mbr(pfn);
                cfuncptr_t cfunc = decompile(mbr);
                if (cfunc)
                {
                    lvars_t* lvars = cfunc->get_lvars();
                    if (lvars && !lvars->empty())
                    {
                        qstring lvars_str;
                        for (const auto& lv : *lvars)
                        {
                            lvars_str.cat_sprnt("// %s %s; // location: %s, size: %d\n",
                                lv.type().dstr(),
                                lv.name.c_str(),
                                lv.location.dstr(),
                                lv.width);
                        }
                        context["local_vars"] = lvars_str.c_str();
                    }
                    else
                    {
                        context["local_vars"] = "// No local variables found.";
                    }

                    hexwarns_t& warns = cfunc->get_warnings();
                    if (!warns.empty())
                    {
                        qstring warns_str;
                        for (const auto& warn : warns)
                        {
                            warns_str.append(warn.text.c_str());
                            warns_str.append("\n");
                        }
                        context["decompiler_warnings"] = warns_str.c_str();
                    }

                    if (include_struct_context)
                    {
                        tinfo_t struct_tif;
                        lvar_t* this_lvar = nullptr;
                        if (lvars)
                        {
                            for (auto& lv : *lvars)
                            {
                                if (lv.is_thisarg())
                                {
                                    this_lvar = &lv;
                                    break;
                                }
                            }
                            if (this_lvar == nullptr)
                            {
                                for (auto& lv : *lvars)
                                {
                                    if (lv.is_arg_var() && lv.type().is_ptr() && lv.type().get_pointed_object().is_udt())
                                    {
                                        this_lvar = &lv;
                                        break;
                                    }
                                }
                            }
                        }
                        if (this_lvar && this_lvar->type().is_ptr())
                        {
                            struct_tif = this_lvar->type().get_pointed_object();
                        }

                        if (struct_tif.is_udt())
                        {
                            std::string usage_context = get_struct_usage_context(ea);
                            std::string data_xref_context = get_data_xrefs_for_struct(struct_tif, g_settings);
                            context["struct_context"] = usage_context + "\n\n" + data_xref_context;
                        }
                        else
                        {
                            context["struct_context"] = "// No struct context could be determined for this function.";
                        }
                    }
                }
            }
            catch (const vd_failure_t&) {}
        }

        qstring string_xrefs_str = "// No string literals referenced.\n";
        std::set<qstring> found_strings;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            xrefblk_t xb;
            for (bool ok_ref = xb.first_from(fii.current(), XREF_DATA); ok_ref; ok_ref = xb.next_from())
            {
                flags64_t s_flags = get_flags(xb.to);
                if (is_strlit(s_flags))
                {
                    int32 strtype = get_str_type(xb.to);
                    qstring s;
                    if (get_strlit_contents(&s, xb.to, -1, strtype) > 0)
                    {
                        if (found_strings.find(s) == found_strings.end())
                        {
                            if (found_strings.empty()) string_xrefs_str.clear();
                            string_xrefs_str.cat_sprnt("\"%s\"\n", s.c_str());
                            found_strings.insert(s);
                        }
                    }
                }
            }
        }
        context["string_xrefs"] = string_xrefs_str.c_str();
        return context;
    }

    std::string format_prompt(const char* prompt_template, const nlohmann::json& context)
    {
        std::string result = prompt_template;
        for (auto const& [key, val] : context.items())
        {
            std::string placeholder = "{" + key + "}";
            if (val.is_string())
            {
                size_t pos = result.find(placeholder);
                while (pos != std::string::npos)
                {
                    result.replace(pos, placeholder.length(), val.get<std::string>());
                    pos = result.find(placeholder, pos + val.get<std::string>().length());
                }
            }
        }
        return result;
    }

    void apply_struct_from_cpp(const std::string& cpp_code, ea_t ea)
    {
        std::string struct_code;
        std::smatch match_md;
        if (std::regex_search(cpp_code, match_md, std::regex("```(?:cpp)?\\s*([\\s\\S]*?)\\s*```")))
        {
            struct_code = match_md[1].str();
        }
        else
        {
            if (cpp_code.find("struct") != std::string::npos)
            {
                struct_code = cpp_code;
            }
            else
            {
                warning("AiDA: AI response did not contain a C++ struct definition.\n"
                        "Full response:\n%s", cpp_code.c_str());
                return;
            }
        }

        struct_code.erase(0, struct_code.find_first_not_of(" \t\n\r"));
        struct_code.erase(struct_code.find_last_not_of(" \t\n\r") + 1);

        std::smatch match_name;
        if (!std::regex_search(struct_code, match_name, std::regex("struct\\s+([a-zA-Z_][a-zA-Z0-9_]*)")))
        {
            warning("AiDA: Could not find a valid struct name in the AI-generated code.");
            msg("--- Invalid Code Snippet ---\n%s\n----------------------------\n", struct_code.c_str());
            return;
        }
        std::string original_struct_name = match_name[1].str();
        std::string final_struct_name = original_struct_name;

        til_t* idati = get_idati();
        if (get_type_ordinal(idati, final_struct_name.c_str()) != 0)
        {
            qstring question;
            question.sprnt("A struct named '%s' already exists. What would you like to do?", final_struct_name.c_str());
            
            int choice = ask_buttons("~O~verwrite", "~R~ename", "~C~ancel", ASKBTN_CANCEL, question.c_str());

            if (choice == ASKBTN_YES)
            {
                msg("AiDA: Struct '%s' already exists, overwriting.\n", final_struct_name.c_str());
                if (!del_named_type(idati, final_struct_name.c_str(), NTF_TYPE))
                {
                    warning("AiDA: Failed to delete existing struct '%s'. Aborting overwrite.", final_struct_name.c_str());
                    return;
                }
            }
            else if (choice == ASKBTN_NO)
            {
                int counter = 1;
                do
                {
                    qstring temp_qstr;
                    temp_qstr.sprnt("%s_%d", original_struct_name.c_str(), counter++);
                    final_struct_name = temp_qstr.c_str();
                } while (get_type_ordinal(idati, final_struct_name.c_str()) != 0);
                msg("AiDA: Renaming to '%s' to avoid conflict.\n", final_struct_name.c_str());
            }
            else
            {
                msg("AiDA: Struct creation cancelled by user.\n");
                return;
            }
        }

        if (final_struct_name != original_struct_name)
        {
            struct_code = std::regex_replace(struct_code, std::regex("struct\\s+" + original_struct_name), "struct " + final_struct_name);
        }

        msg("--- AiDA: Attempting to parse the following C++ struct ---\n%s\n--------------------------------------------------------\n", struct_code.c_str());

        if (parse_decls(idati, struct_code.c_str(), msg, HTI_DCL) != 0)
        {
            warning("AiDA: Failed to parse the C++ struct. See the Output window for details and the code that was attempted.");
            return;
        }

        msg("AiDA: Struct '%s' created/updated successfully.\n", final_struct_name.c_str());

        uint32 ordinal = get_type_ordinal(idati, final_struct_name.c_str());
        if (ordinal != 0)
        {
            open_loctypes_window(ordinal);
        }

        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            msg("AiDA: No function at 0x%a to apply type to.\n", ea);
            return;
        }

        if (!init_hexrays_plugin())
        {
            msg("AiDA: Hex-Rays decompiler not available. Cannot automatically apply type to function arguments.\n");
            return;
        }

        try
        {
            cfuncptr_t cfunc = decompile(pfn);
            if (cfunc == nullptr)
            {
                warning("AiDA: Could not decompile function at 0x%a to apply type.", ea);
                return;
            }

            lvars_t* lvars = cfunc->get_lvars();
            lvar_t* target_lvar = nullptr;

            if (lvars)
            {
                for (auto& lv : *lvars)
                {
                    if (lv.is_thisarg())
                    {
                        target_lvar = &lv;
                        break;
                    }
                }
                if (target_lvar == nullptr)
                {
                    for (auto& lv : *lvars)
                    {
                        if (lv.is_arg_var() && lv.type().is_ptr())
                        {
                            target_lvar = &lv;
                            break;
                        }
                    }
                }
            }

            if (target_lvar)
            {
                qstring new_type_str;
                new_type_str.sprnt("%s*", final_struct_name.c_str());

                tinfo_t tif;
                if (tif.parse(new_type_str.c_str()))
                {
                    lvar_saved_info_t lsi;
                    lsi.ll = *target_lvar;
                    lsi.type = tif;

                    if (modify_user_lvar_info(pfn->start_ea, MLI_TYPE, lsi))
                    {
                        msg("AiDA: Applied type '%s' to argument '%s'.\n", new_type_str.c_str(), target_lvar->name.c_str());
                        mark_cfunc_dirty(pfn->start_ea, true);
                    }
                    else
                    {
                        warning("AiDA: Failed to apply type '%s' to lvar '%s'.", new_type_str.c_str(), target_lvar->name.c_str());
                    }
                }
            }
            else
            {
                msg("AiDA: Could not find a suitable argument to apply the new struct type to.\n");
            }
        }
        catch (const vd_failure_t&)
        {
            warning("AiDA: Decompilation failed, cannot automatically apply type.");
        }
        catch (const std::exception& e)
        {
            warning("AiDA: An unexpected error occurred during type application: %s", e.what());
        }
    }
    bool is_word_char(char c)
    {
        return qisalnum(c) || c == '_' || c == ':';
    }

    bool ensure_function_context(ea_t ea) {
        if (get_func(ea) == nullptr) {
            warning("AiDA: Please place the cursor inside a function.");
            return false;
        }
        return true;
    }
    qstring qstring_tolower(const qstring& s)
    {
        qstring lower_s = s;
        qstrlwr(lower_s.begin());
        return lower_s;
    }

    bool get_address_from_line_pos(ea_t* out_ea, const char* /*line*/, int /*x*/)
    {
        TWidget* view = get_current_viewer();
        if (view == nullptr)
            return false;

        listing_location_t lloc;
        if (get_custom_viewer_location(&lloc, view, CVLF_USE_MOUSE))
        {
            if (lloc.loc != nullptr && lloc.loc->place() != nullptr)
            {
                if (const ea_t ea = lloc.loc->place()->toea(); ea != BADADDR)
                {
                    *out_ea = ea;
                    return true;
                }
            }
        }
        return false;
    }
}