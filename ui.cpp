#include "aida_pro.hpp"
#include <moves.hpp>

namespace ida_utils
{
    static bool get_address_from_line_pos(ea_t* out_ea, const char* line, int x)
    {
        if (line == nullptr)
            return false;

        const char* target_ptr = tag_advance(line, x);

        const char* p_on = nullptr;
        for (const char* p = target_ptr; p >= line; --p)
        {
            if (*p == COLOR_ON && p[1] == COLOR_ADDR)
            {
                p_on = p;
                break;
            }
        }

        if (p_on == nullptr)
            return false;

        const char* p_addr = p_on + 2;

        const char* p_off = strstr(p_addr, SCOLOR_OFF SCOLOR_ADDR);
        if (p_off == nullptr || target_ptr > p_off)
            return false;

        qstring addr_str;
        addr_str.append(p_addr, COLOR_ADDR_SIZE);

        return str2ea(out_ea, addr_str.c_str());
    }
}

static bool idaapi handle_viewer_dblclick(TWidget* viewer, int /*shift*/, void* /*ud*/)
{
    qstring word;
    if (get_highlight(&word, viewer, nullptr))
    {
        ea_t ea = BADADDR;
        if (str2ea(&ea, word.c_str()))
        {
            jumpto(ea);
            return true;
        }
    }

    return false;
}

static void update_provider_visibility(form_actions_t& fa, int provider_idx)
{
    fa.show_field(11, provider_idx == 0);
    fa.show_field(12, provider_idx == 0);

    fa.show_field(21, provider_idx == 1);
    fa.show_field(22, provider_idx == 1);

    fa.show_field(31, provider_idx == 2);
    fa.show_field(32, provider_idx == 2);
}

static int idaapi settings_form_cb(int fid, form_actions_t& fa)
{
    int provider_idx = 0;
    switch (fid)
    {
    case CB_INIT:
        fa.get_combobox_value(0, &provider_idx);
        update_provider_visibility(fa, provider_idx);
        break;

    case 0:
        fa.get_combobox_value(0, &provider_idx);
        update_provider_visibility(fa, provider_idx);
        break;
    }
    return 1;
}

// this stupid form almost gave me an aneurysm
void SettingsForm::show_and_apply(aida_plugin_t* plugin_instance)
{
    static const char form_str[] =
        "STARTITEM 0\n"
        "BUTTON YES Ok\n"
        "BUTTON CANCEL Cancel\n"
        "AI Assistant Settings\n\n"
        "%/\n"
        "<#API Provider Configuration#Provider:b0:0:20::>\n\n"

        "<Gemini API Key:q11:64:64::>\n"
        "<Gemini Model Name:q12:32:32::>\n"

        "<OpenAI API Key:q21:64:64::>\n"
        "<OpenAI Model Name:q22:32:32::>\n"

        "<Anthropic API Key:q31:64:64::>\n"
        "<Anthropic Model Name:q32:32:32::>\n\n"

        "<#Analysis Parameters#XRef Context Count:D:10:10::>\n"
        "<XRef Analysis Depth:D:10:10::>\n"
        "<Code Snippet Lines:D:10:10::>\n"
        "<Bulk Processing Delay (sec):q:10:10::>\n"
        "<Max Prompt Tokens:D:10:10::>";

    static const char* const providers_list_items[] = { "Gemini", "OpenAI", "Anthropic" };
    qstrvec_t providers_qstrvec;
    for (const auto& p : providers_list_items)
        providers_qstrvec.push_back(p);

    qstring provider_setting = g_settings.api_provider.c_str();
    qstrlwr(provider_setting.begin());
    int provider_idx = 0;
    if (provider_setting == "openai") provider_idx = 1;
    else if (provider_setting == "anthropic") provider_idx = 2;

    qstring gemini_key = g_settings.gemini_api_key.c_str();
    qstring gemini_model = g_settings.gemini_model_name.c_str();
    qstring openai_key = g_settings.openai_api_key.c_str();
    qstring openai_model = g_settings.openai_model_name.c_str();
    qstring anthropic_key = g_settings.anthropic_api_key.c_str();
    qstring anthropic_model = g_settings.anthropic_model_name.c_str();

    qstring bulk_delay_str;
    bulk_delay_str.sprnt("%.2f", g_settings.bulk_processing_delay);

    sval_t xref_count = g_settings.xref_context_count;
    sval_t xref_depth = g_settings.xref_analysis_depth;
    sval_t snippet_lines = g_settings.xref_code_snippet_lines;
    sval_t max_tokens = g_settings.max_prompt_tokens;

    if (ask_form(form_str,
        &settings_form_cb,
        &providers_qstrvec,
        &provider_idx,
        &gemini_key,
        &gemini_model,
        &openai_key,
        &openai_model,
        &anthropic_key,
        &anthropic_model,
        &xref_count,
        &xref_depth,
        &snippet_lines,
        &bulk_delay_str,
        &max_tokens
    ) > 0)
    {
        g_settings.api_provider = providers_list_items[provider_idx];

        g_settings.gemini_api_key = gemini_key.c_str();
        g_settings.gemini_model_name = gemini_model.c_str();
        g_settings.openai_api_key = openai_key.c_str();
        g_settings.openai_model_name = openai_model.c_str();
        g_settings.anthropic_api_key = anthropic_key.c_str();
        g_settings.anthropic_model_name = anthropic_model.c_str();

        g_settings.xref_context_count = static_cast<int>(xref_count);
        g_settings.xref_analysis_depth = static_cast<int>(xref_depth);
        g_settings.xref_code_snippet_lines = static_cast<int>(snippet_lines);
        g_settings.max_prompt_tokens = static_cast<int>(max_tokens);

        try
        {
            g_settings.bulk_processing_delay = std::stod(bulk_delay_str.c_str());
        }
        catch (const std::exception& e)
        {
            warning("AI Assistant: Invalid value for bulk processing delay: '%s'. Using previous value. Error: %s", bulk_delay_str.c_str(), e.what());
        }

        g_settings.save();

        if (plugin_instance)
        {
            msg("AI Assistant: Settings updated. Re-initializing AI client...\n");
            plugin_instance->reinit_ai_client();
        }
    }
}

void idaapi close_handler(TWidget* /*cv*/, void* ud)
{
    strvec_t* lines_ptr = (strvec_t*)ud;
    delete lines_ptr;
}

void show_text_in_viewer(const char* title, const std::string& text_content)
{
    if (text_content.empty() || text_content.find_first_not_of(" \t\n\r") == std::string::npos)
    {
        warning("AI returned an empty or whitespace-only response. Nothing to display.");
        return;
    }

    TWidget* existing_viewer = find_widget(title);
    if (existing_viewer)
    {
        close_widget(existing_viewer, 0);
    }

    strvec_t* lines_ptr = new strvec_t();

    std::string marked_up_content = ida_utils::markup_text_with_addresses(text_content);

    std::stringstream ss(marked_up_content);
    std::string line;
    while (std::getline(ss, line, '\n'))
    {
        lines_ptr->push_back(simpleline_t(line.c_str()));
    }

    simpleline_place_t s1;
    simpleline_place_t s2;
    s2.n = lines_ptr->empty() ? 0 : static_cast<uint32>(lines_ptr->size() - 1);

    TWidget* viewer = create_custom_viewer(title, &s1, &s2, &s1, nullptr, lines_ptr, nullptr, nullptr);
    if (viewer == nullptr)
    {
        warning("Could not create viewer '%s'.", title);
        delete lines_ptr;
        return;
    }

    static custom_viewer_handlers_t handlers(
        nullptr, // keydown
        nullptr, // popup
        nullptr, // mouse_moved
        nullptr, // click
        handle_viewer_dblclick, // dblclick
        nullptr, // curpos
        close_handler, // close
        nullptr, // help
        nullptr, // adjust_place
        nullptr, // get_place_xcoord
        nullptr, // location_changed
        nullptr); // can_navigate

    set_custom_viewer_handlers(viewer, &handlers, lines_ptr);

    display_widget(viewer, WOPN_DP_TAB | WOPN_RESTORE);
}

static int idaapi finish_populating_widget_popup(TWidget* widget, TPopupMenu* popup_handle, const action_activation_ctx_t* ctx)
{
    if (ctx && (ctx->widget_type == BWN_PSEUDOCODE || ctx->widget_type == BWN_DISASM))
    {
        const char* menu_root = "AI Assistant/";

        attach_action_to_popup(widget, popup_handle, "ai_assistant:analyze", (qstring(menu_root) + "Analyze/").c_str());
        attach_action_to_popup(widget, popup_handle, "ai_assistant:rename", (qstring(menu_root) + "Analyze/").c_str());
        attach_action_to_popup(widget, popup_handle, "ai_assistant:comment", (qstring(menu_root) + "Analyze/").c_str());

        attach_action_to_popup(widget, popup_handle, "ai_assistant:gen_struct", (qstring(menu_root) + "Generate/").c_str());
        attach_action_to_popup(widget, popup_handle, "ai_assistant:gen_hook", (qstring(menu_root) + "Generate/").c_str());

        attach_action_to_popup(widget, popup_handle, nullptr, menu_root);

        attach_action_to_popup(widget, popup_handle, "ai_assistant:scan_for_offsets", menu_root);
        attach_action_to_popup(widget, popup_handle, "ai_assistant:custom_query", menu_root);

        attach_action_to_popup(widget, popup_handle, nullptr, menu_root);

        attach_action_to_popup(widget, popup_handle, "ai_assistant:settings", menu_root);
    }
    return 0;
}

ssize_t idaapi ui_callback(void* /*user_data*/, int notification_code, va_list va)
{
    if (notification_code == ui_finish_populating_widget_popup)
    {
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
    return 0;
}