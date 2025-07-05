#include "aida_pro.hpp"

int idaapi action_handler::activate(action_activation_ctx_t* ctx)
{
    action_func(ctx, plugin);
    return 1;
}

action_state_t idaapi action_handler::update(action_update_ctx_t* ctx)
{
    if (action_func == handle_show_settings || action_func == handle_scan_for_offsets)
        return AST_ENABLE_ALWAYS;

    if (!plugin || !plugin->ai_client || !plugin->ai_client->is_available())
        return AST_DISABLE_FOR_WIDGET;

    if (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM)
        return AST_DISABLE_FOR_WIDGET;

    if (action_func != handle_show_settings && action_func != handle_scan_for_offsets)
    {
        if (get_func(ctx->cur_ea) == nullptr)
            return AST_DISABLE_FOR_WIDGET;
    }

    return AST_ENABLE_FOR_WIDGET;
}

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    const ea_t func_ea = ctx->cur_ea;
    if (get_func(func_ea) == nullptr)
    {
        warning("AiDA: Please place the cursor inside a function.");
        return;
    }

    auto on_complete = [func_ea](const std::string& analysis) {
        if (!analysis.empty() && analysis.find("Error:") == std::string::npos)
        {
            qstring title;
            title.sprnt("AI Analysis for 0x%a", func_ea);
            show_text_in_viewer(title.c_str(), analysis);
        }
        else if (!analysis.empty())
        {
            warning("AiDA: %s", analysis.c_str());
        }
        };
    plugin->ai_client->analyze_function(func_ea, on_complete);
}

void handle_rename_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = get_func(ctx->cur_ea);
    if (!pfn)
    {
        warning("AiDA: Please place the cursor inside a function.");
        return;
    }
    const ea_t func_ea = pfn->start_ea;

    qstring current_name;
    if (get_name(&current_name, func_ea) > 0 && is_uname(current_name.c_str()))
    {
        qstring question;
        question.sprnt("HIDECANCEL\nThis function already has a user-defined name ('%s').\nDo you want to ask the AI for a new one anyway?", current_name.c_str());
        if (ask_buttons("~Y~es", "~N~o", nullptr, ASKBTN_NO, question.c_str()) != ASKBTN_YES)
        {
            return;
        }
    }

    auto on_complete = [func_ea](const std::string& name) {
        if (!name.empty() && name.find("Error:") == std::string::npos)
        {
            func_t* pfn_cb = get_func(func_ea);
            if (!pfn_cb)
            {
                warning("AiDA: Function at 0x%a no longer exists.", func_ea);
                return;
            }

            qstring clean_name = name.c_str();
            clean_name.replace("`", "");
            clean_name.trim2();

            if (!validate_name(&clean_name, VNT_IDENT))
            {
                warning("AiDA: The suggested name '%s' is not a valid identifier.", clean_name.c_str());
                return;
            }

            qstring question;
            question.sprnt("Rename function at 0x%a to:\n\n%s\n\nApply this change?", pfn_cb->start_ea, clean_name.c_str());
            if (ask_buttons("~Y~es", "~N~o", nullptr, ASKBTN_YES, question.c_str()) == ASKBTN_YES)
            {
                if (set_name(pfn_cb->start_ea, clean_name.c_str(), SN_FORCE))
                {
                    msg("AiDA: Function at 0x%a renamed to '%s'.\n", pfn_cb->start_ea, clean_name.c_str());
                }
                else
                {
                    warning("AiDA: Failed to set new function name. It might be invalid or already in use.");
                }
            }
        }
        else if (!name.empty())
        {
            warning("AiDA: %s", name.c_str());
        }
        };
    plugin->ai_client->suggest_name(func_ea, on_complete);
}

void handle_auto_comment(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = get_func(ctx->cur_ea);
    if (!pfn)
    {
        warning("AiDA: Please place the cursor inside a function.");
        return;
    }
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& analysis) {
        if (!analysis.empty() && analysis.find("Error:") == std::string::npos)
        {
            func_t* pfn_cb = get_func(func_ea);
            if (!pfn_cb)
            {
                warning("AiDA: Function at 0x%a no longer exists.", func_ea);
                return;
            }

            std::smatch match;
            std::string summary;
            if (std::regex_search(analysis, match, std::regex("High-Level Purpose:\\s*(.*)")))
            {
                summary = match[1].str();
            }
            else
            {
                size_t first_line_end = analysis.find('\n');
                summary = analysis.substr(0, first_line_end);
            }

            qstring comment;
            get_func_cmt(&comment, pfn_cb, true);
            if (comment.find("AI Assist:") == qstring::npos)
            {
                qstring new_comment;
                if (comment.empty())
                    new_comment.sprnt("// AI Assist: %s", summary.c_str());
                else
                    new_comment.sprnt("// AI Assist: %s\n%s", summary.c_str(), comment.c_str());

                set_func_cmt(pfn_cb, new_comment.c_str(), true);

                if (init_hexrays_plugin())
                {
                    cfuncptr_t cfunc = decompile(pfn_cb);
                    if (cfunc != nullptr)
                    {
                        cfunc->refresh_func_ctext();
                    }
                    else
                    {
                        mark_cfunc_dirty(pfn_cb->start_ea, true);
                        request_refresh(IWID_DISASM);
                    }
                }
                else
                {
                    request_refresh(IWID_DISASM);
                }

                msg("AiDA: Comment added to function at 0x%a.\n", pfn_cb->start_ea);
            }
            else
            {
                msg("AiDA: AI-generated comment already exists.\n");
            }
        }
        else if (!analysis.empty())
        {
            warning("AiDA: %s", analysis.c_str());
        }
    };
    plugin->ai_client->analyze_function(func_ea, on_complete);
}

void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    const ea_t func_ea = ctx->cur_ea;
    if (get_func(func_ea) == nullptr)
    {
        warning("AiDA: Please place the cursor inside a function to generate a struct.");
        return;
    }

    auto on_complete = [func_ea](const std::string& struct_cpp) {
        if (!struct_cpp.empty() && struct_cpp.find("Error:") == std::string::npos)
        {
            ida_utils::apply_struct_from_cpp(struct_cpp, func_ea);
        }
        else if (!struct_cpp.empty())
        {
            warning("AiDA: %s", struct_cpp.c_str());
        }
        };
    plugin->ai_client->generate_struct(func_ea, on_complete);
}

void handle_generate_hook(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    func_t* pfn = get_func(ctx->cur_ea);
    if (!pfn)
    {
        warning("AiDA: Please place the cursor inside a function to generate a hook.");
        return;
    }
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& hook_code) {
        if (!hook_code.empty() && hook_code.find("Error:") == std::string::npos)
        {
            qstring func_name;
            get_func_name(&func_name, func_ea);
            qstring title;
            title.sprnt("MinHook Snippet for %s", func_name.c_str());
            show_text_in_viewer(title.c_str(), hook_code);
        }
        else if (!hook_code.empty())
        {
            warning("AiDA: %s", hook_code.c_str());
        }
        };
    plugin->ai_client->generate_hook(func_ea, on_complete);
}

void handle_custom_query(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    const ea_t func_ea = ctx->cur_ea;
    if (get_func(func_ea) == nullptr)
    {
        warning("AiDA: Please place the cursor inside a function for a custom query.");
        return;
    }

    qstring question;
    if (ask_str(&question, HIST_SRCH, "Ask AI about this function:"))
    {
        auto on_complete = [question](const std::string& analysis) {
            if (!analysis.empty() && analysis.find("Error:") == std::string::npos)
            {
                qstring title;
                title.sprnt("AI Query: %s", question.c_str());
                show_text_in_viewer(title.c_str(), analysis);
            }
            else if (!analysis.empty())
            {
                warning("AiDA: %s", analysis.c_str());
            }
            };
        plugin->ai_client->custom_query(func_ea, question.c_str(), on_complete);
    }
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