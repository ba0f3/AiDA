#include "aida_pro.hpp"
#include <regex>

int idaapi action_handler::activate(action_activation_ctx_t* ctx)
{
    action_func(ctx, plugin);
    return 1;
}

action_state_t idaapi action_handler::update(action_update_ctx_t* ctx)
{
    if (action_func == handle_show_settings || action_func == handle_scan_for_offsets)
        return AST_ENABLE_ALWAYS;

    return AST_ENABLE_ALWAYS;
}

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& analysis) {
        action_helpers::handle_ai_response(analysis, "AI Analysis for 0x%a",
            [func_ea](const std::string& content) {
                qstring title;
                title.sprnt("AI Analysis for 0x%a", func_ea);
                show_text_in_viewer(title.c_str(), content);
            });
    };
    plugin->ai_client->analyze_function(func_ea, on_complete);
}

void handle_rename_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    qstring current_name;
    if (get_func_name(&current_name, func_ea) > 0 && is_uname(current_name.c_str()))
    {
        qstring question;
        question.sprnt("HIDECANCEL\nThis function already has a user-defined name ('%s').\nDo you want to ask the AI for a new one anyway?", current_name.c_str());
        if (ask_buttons("~Y~es", "~N~o", nullptr, ASKBTN_NO, question.c_str()) != ASKBTN_YES)
        {
            return;
        }
    }

    auto on_complete = [func_ea](const std::string& name) {
        action_helpers::handle_ai_response(name, "Suggested Name",
            [func_ea](const std::string& suggested_name) {
                func_t* pfn_cb = get_func(func_ea);
                if (!pfn_cb)
                {
                    warning("AiDA: Function at 0x%a no longer exists.", func_ea);
                    return;
                }

                qstring clean_name = suggested_name.c_str();
                clean_name.replace("`", "");
                clean_name.replace("'", "");
                clean_name.replace("\"", "");
                clean_name.trim2();

                if (clean_name.length() >= MAXNAMELEN - 10)
                {
                    clean_name.resize(MAXNAMELEN - 10);
                    msg("AiDA: Truncated long suggested name.\n");
                }

                if (!validate_name(&clean_name, VNT_IDENT, SN_NOCHECK))
                {
                    warning("AiDA: The suggested name '%s' is not a valid identifier, even after sanitization.", clean_name.c_str());
                    return;
                }

                qstring question;
                question.sprnt("Rename function at 0x%a to:\n\n%s\n\nApply this change?", pfn_cb->start_ea, clean_name.c_str());
                if (ask_buttons("~Y~es", "~N~o", nullptr, ASKBTN_YES, question.c_str()) == ASKBTN_YES)
                {
                    if (set_name(pfn_cb->start_ea, clean_name.c_str(), SN_FORCE | SN_NODUMMY))
                    {
                        msg("AiDA: Function at 0x%a renamed to '%s'.\n", pfn_cb->start_ea, clean_name.c_str());
                    }
                    else
                    {
                        warning("AiDA: Failed to set new function name. It might be invalid or already in use.");
                    }
                }
            });
    };
    plugin->ai_client->suggest_name(func_ea, on_complete);
}

void handle_auto_comment(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& json_comments) {
        action_helpers::handle_ai_response(json_comments, "AI Comments",
            [func_ea](const std::string& content) {
                std::string json_str = content;
                static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
                std::smatch match;
                if (std::regex_search(content, match, md_json_re) && match.size() > 1)
                {
                    json_str = match[1].str();
                }

                try
                {
                    cfuncptr_t cfunc(nullptr);
                    if (init_hexrays_plugin())
                    {
                        func_t* pfn_for_decomp = get_func(func_ea);
                        if (pfn_for_decomp != nullptr)
                        {
                            try { cfunc = decompile(pfn_for_decomp); }
                            catch (const vd_failure_t&) 
                            {
                                msg("AiDA: Decompilation failed for 0x%a, comments will only be added to disassembly.\n", func_ea);
                            }
                        }
                    }

                    auto comments = nlohmann::json::parse(json_str);
                    if (!comments.is_array())
                    {
                        warning("AiDA: AI response for comments is not a JSON array.");
                        return;
                    }

                    int count = 0;
                    for (const auto& item : comments)
                    {
                        if (!item.is_object() || !item.contains("address") || !item.contains("comment"))
                            continue;

                        std::string addr_str = item["address"];
                        std::string comment_str = item["comment"];

                        ea_t ea;
                        if (sscanf(addr_str.c_str(), "0x%llX", &ea) != 1 && sscanf(addr_str.c_str(), "%llX", &ea) != 1)
                            continue;

                        if (!is_mapped(ea))
                            continue;

                        qstring q_comment = comment_str.c_str();
                        q_comment.trim2();
                        if (q_comment.empty())
                            continue;

                        qstring existing_comment;
                        get_cmt(&existing_comment, ea, false);

                        qstring new_comment;
                        if (existing_comment.empty())
                        {
                            new_comment = q_comment;
                        }
                        else
                        {
                            new_comment.sprnt("%s\n%s", q_comment.c_str(), existing_comment.c_str());
                        }
                        
                        set_cmt(ea, new_comment.c_str(), false);
                        count++;

                        if (cfunc != nullptr)
                        {
                            treeloc_t loc;
                            loc.ea = ea;
                            loc.itp = ITP_BLOCK1;

                            const char* existing_pcomment = cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
                            qstring new_pcomment;
                            if (existing_pcomment == nullptr || *existing_pcomment == '\0')
                            {
                                new_pcomment = q_comment;
                            }
                            else
                            {
                                new_pcomment.sprnt("%s\n%s", q_comment.c_str(), existing_pcomment);
                            }
                            cfunc->set_user_cmt(loc, new_pcomment.c_str());
                        }
                    }

                    if (count > 0)
                    {
                        msg("AiDA: Added %d comments to function at 0x%a.\n", count, func_ea);
                        if (cfunc != nullptr)
                        {
                            cfunc->save_user_cmts();
                            cfunc->refresh_func_ctext(); 
                        }
                        request_refresh(IWID_DISASM);
                    }
                    else
                    {
                        msg("AiDA: AI did not provide any valid comments.\n");
                    }
                }
                catch (const nlohmann::json::parse_error& e)
                {
                    warning("AiDA: Failed to parse AI response as JSON: %s", e.what());
                }
            });
    };
    plugin->ai_client->generate_comments(func_ea, on_complete);
}

void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& struct_cpp) {
        action_helpers::handle_ai_response(struct_cpp, "Generated Struct",
            [func_ea](const std::string& content) {
                ida_utils::apply_struct_from_cpp(content, func_ea);
            });
    };
    plugin->ai_client->generate_struct(func_ea, on_complete);
}

void handle_generate_hook(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& hook_code) {
        action_helpers::handle_ai_response(hook_code, "Generated Hook",
            [func_ea](const std::string& content) {
                qstring func_name;
                get_func_name(&func_name, func_ea);
                qstring title;
                title.sprnt("MinHook Snippet for %s", func_name.c_str());
                show_text_in_viewer(title.c_str(), content);
            });
    };
    plugin->ai_client->generate_hook(func_ea, on_complete);
}

void handle_custom_query(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    qstring question;
    if (ask_str(&question, HIST_SRCH, "Ask AI about this function:"))
    {
        auto on_complete = [question](const std::string& analysis) {
            action_helpers::handle_ai_response(analysis, "AI Query",
                [question](const std::string& content) {
                    qstring title;
                    title.sprnt("AI Query: %s", question.c_str());
                    show_text_in_viewer(title.c_str(), content);
                });
        };
        plugin->ai_client->custom_query(func_ea, question.c_str(), on_complete);
    }
}

void handle_copy_context(action_activation_ctx_t* ctx, aida_plugin_t* /*plugin*/)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    nlohmann::json context = ida_utils::get_context_for_prompt(func_ea, true);
    
    if (!context.value("ok", false))
    {
        warning("AiDA: Failed to gather context: %s", context.value("message", "Unknown error").c_str());
        return;
    }

    std::string clipboard_text = ida_utils::format_context_for_clipboard(context);

    if (ida_utils::set_clipboard_text(clipboard_text.c_str()))
    {
        qstring func_name;
        get_func_name(&func_name, func_ea);
        msg("AiDA: Context for function '%s' (0x%a) copied to clipboard.\n", func_name.c_str(), func_ea);
    }
    else
    {
        warning("AiDA: Failed to copy context to clipboard.");
    }
}

void handle_rename_all(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& rename_suggestions) {
        action_helpers::handle_ai_response(rename_suggestions, "Rename Suggestions",
            [func_ea](const std::string& content) {
                qstring summary = ida_utils::apply_renames_from_ai(func_ea, content);
                if (summary.empty())
                {
                    msg("AiDA: No valid renames suggested by AI or nothing to rename.\n");
                    return;
                }

                qstring title;
                title.sprnt("Renaming summary for 0x%a", func_ea);
                show_text_in_viewer(title.c_str(), summary.c_str());

                if (init_hexrays_plugin())
                {
                    mark_cfunc_dirty(func_ea, true);
                }
                request_refresh(IWID_DISASM | IWID_PSEUDOCODE);
            });
    };
    plugin->ai_client->rename_all(func_ea, on_complete);
}

void handle_scan_for_offsets(action_activation_ctx_t* /*ctx*/, aida_plugin_t* /*plugin*/)
{
    msg("====================================================\n");
    msg("--- Starting Unreal Engine Pointer Scan ---\n");
    warning("Scan for Engine Pointers is not yet implemented in the C++ version.");
    // unreal::scan_for_unreal_patterns(plugin->ai_client, g_settings); COMING SOON!!!
}

void handle_show_settings(action_activation_ctx_t* /*ctx*/, aida_plugin_t* plugin)
{
    SettingsForm::show_and_apply(plugin);
}

namespace action_helpers {
void handle_ai_response(const std::string& result, const qstring& title_prefix,
                        std::function<void(const std::string&)> success_action)
{
    if (!result.empty() && result.find("Error:") == std::string::npos)
    {
        success_action(result);
    }
    else if (!result.empty())
    {
        warning("AiDA: %s", result.c_str());
    }
}
}