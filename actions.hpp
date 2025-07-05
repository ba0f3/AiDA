#pragma once

#include <kernwin.hpp>

class aida_plugin_t;

struct action_handler : public action_handler_t
{
    using action_func_t = void (*)(action_activation_ctx_t*, aida_plugin_t*);
    action_func_t action_func;
    aida_plugin_t* plugin;

    action_handler(action_func_t func, aida_plugin_t* p) : action_handler_t(), action_func(func), plugin(p) {}

    int idaapi activate(action_activation_ctx_t* ctx) override;
    action_state_t idaapi update(action_update_ctx_t* ctx) override;
};

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_rename_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_auto_comment(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_generate_hook(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_custom_query(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_scan_for_offsets(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_show_settings(action_activation_ctx_t* ctx, aida_plugin_t* plugin);