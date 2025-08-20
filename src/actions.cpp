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

    return AST_ENABLE_ALWAYS;
}

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    const ea_t func_ea = ctx->cur_ea;
    if (!ida_utils::ensure_function_context(func_ea))
        return;

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
    const ea_t func_ea = ctx->cur_ea;
    func_t* pfn = get_func(func_ea);
    if (!ida_utils::ensure_function_context(func_ea))
        return;

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
    const ea_t func_ea = ctx->cur_ea;
    if (!ida_utils::ensure_function_context(func_ea))
        return;

    auto on_complete = [func_ea](const std::string& comment_text) {
        action_helpers::handle_ai_response(comment_text, "AI Comment",
            [func_ea](const std::string& content) {
                func_t* pfn_cb = get_func(func_ea);
                if (!pfn_cb)
                {
                    warning("AiDA: Function at 0x%a no longer exists.", func_ea);
                    return;
                }

                qstring summary = content.c_str();
                summary.replace("\n", " ");
                summary.replace("\r", " ");
                summary.replace("`", "");
                summary.replace("'", "");
                summary.replace("\"", "");
                summary.trim2();

                if (summary.length() > 82)
                {
                    summary.resize(82);
                    msg("AiDA: Truncated long AI comment to 82 characters.\n");
                }

                if (summary.empty())
                {
                    warning("AiDA: AI returned an empty comment.");
                    return;
                }

                qstring existing_comment;
                get_func_cmt(&existing_comment, pfn_cb, true);

                if (existing_comment.find("// AI Assist:") != qstring::npos)
                {
                    msg("AiDA: AI-generated comment already exists. Skipping.\n");
                    return;
                }

                qstring new_comment;
                qstring ai_comment_line;
                ai_comment_line.sprnt("// AI Assist: %s", summary.c_str());

                if (existing_comment.empty())
                {
                    new_comment = ai_comment_line;
                }
                else
                {
                    new_comment.sprnt("%s\n%s", ai_comment_line.c_str(), existing_comment.c_str());
                }

                set_func_cmt(pfn_cb, new_comment.c_str(), true);

                if (init_hexrays_plugin())
                {
                    mark_cfunc_dirty(pfn_cb->start_ea, true);
                }

                request_refresh(IWID_DISASM);
                msg("AiDA: Comment added to function at 0x%a.\n", pfn_cb->start_ea);
            });
    };
    plugin->ai_client->generate_comment(func_ea, on_complete);
}

void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    const ea_t func_ea = ctx->cur_ea;
    if (!ida_utils::ensure_function_context(func_ea))
        return;

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
    const ea_t func_ea = ctx->cur_ea;
    func_t* pfn = get_func(func_ea);
    if (!ida_utils::ensure_function_context(func_ea))
        return;

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
    const ea_t func_ea = ctx->cur_ea;
    if (!ida_utils::ensure_function_context(func_ea))
        return;

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