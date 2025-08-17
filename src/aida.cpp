#include "aida_pro.hpp"

aida_plugin_t::aida_plugin_t()
{
    msg("--- AI Assistant Plugin Loading ---\n");
    g_settings.load(this);
    reinit_ai_client();
    register_actions();
    hook_to_notification_point(HT_UI, ui_callback, this);
    msg("--- AI Assistant Plugin Loaded Successfully ---\n");
}

aida_plugin_t::~aida_plugin_t()
{
    unhook_from_notification_point(HT_UI, ui_callback, this);
    unregister_actions();
    msg("--- AI Assistant Plugin has been unloaded ---\n");
}

void aida_plugin_t::reinit_ai_client()
{
    ai_client = get_ai_client(g_settings);
    if (!ai_client || !ai_client->is_available())
    {
        msg("AI Assistant: No AI client is available. AI features will be limited.\n");
    }
}

bool idaapi aida_plugin_t::run(size_t /*arg*/)
{
    info("AI Assistant is active. Use the right-click context menu in a code view or Tools->AI Assistant.");
    return true;
}

void aida_plugin_t::register_actions()
{
    struct action_def_t {
        const char* name;
        const char* label;
        action_handler::action_func_t handler;
        const char* shortcut;
    };

    static const action_def_t action_definitions[] = {
        {"ai_assistant:analyze", "Analyze function...", handle_analyze_function, "Ctrl+Alt+A"},
        {"ai_assistant:rename", "Suggest new name...", handle_rename_function, "Ctrl+Alt+S"},
        {"ai_assistant:comment", "Add AI-generated comment", handle_auto_comment, "Ctrl+Alt+C"},
        {"ai_assistant:gen_struct", "Generate struct from function", handle_generate_struct, "Ctrl+Alt+G"},
        {"ai_assistant:gen_hook", "Generate MinHook C++ snippet", handle_generate_hook, "Ctrl+Alt+H"},
        {"ai_assistant:custom_query", "Custom query...", handle_custom_query, "Ctrl+Alt+Q"},
        {"ai_assistant:scan_for_offsets", "Scan for Engine Pointers (Coming Soon!)", handle_scan_for_offsets, ""},
        {"ai_assistant:settings", "Settings...", handle_show_settings, "Ctrl+Alt+O"},
    };

    const char* menu_root = "AI Assistant/";

    for (const auto& def : action_definitions)
    {
        actions_list.push_back(def.name);
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name,
            def.label,
            new action_handler(def.handler, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
            msg("AI Assistant: Failed to register action %s\n", def.name);
            continue;
        }
        attach_action_to_menu(menu_root, def.name, SETMENU_APP);
    }
}

void aida_plugin_t::unregister_actions()
{
    for (const auto& action_name : actions_list)
    {
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
}

static plugmod_t* idaapi init()
{
    return new aida_plugin_t();
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "AI-powered game reversing assistant",
  "Right-click in code views or use the Tools->AI Assistant menu",
  "AI Assistant",
  ""
};