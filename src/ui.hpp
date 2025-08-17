#pragma once

#include <ida.hpp>
#include <kernwin.hpp>
#include <memory>

class aida_plugin_t;



struct form_field_t
{
    static qstring combobox(const char* const* items, size_t count);
};

typedef TWidget simplecustviewer_t;

class SettingsForm
{
public:
    static void show_and_apply(aida_plugin_t* plugin_instance);
};

void show_text_in_viewer(const char* title, const std::string& text_content);

ssize_t idaapi ui_callback(void* user_data, int notification_code, va_list va);