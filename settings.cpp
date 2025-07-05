#include "aida_pro.hpp"

settings_t g_settings;

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(settings_t,
    api_provider,
    gemini_api_key, gemini_model_name,
    openai_api_key, openai_model_name,
    anthropic_api_key, anthropic_model_name,
    xref_context_count, xref_analysis_depth, xref_code_snippet_lines,
    bulk_processing_delay, max_prompt_tokens,
    max_root_func_scan_count, max_root_func_candidates,
    temperature
)

static qstring get_config_file()
{
    qstring path = get_user_idadir();
    path.append("/ai_assistant.cfg");
    return path;
}

static bool save_settings_to_file(const settings_t& settings, const qstring& path)
{
    try
    {
        nlohmann::json j = settings;
        std::string json_str = j.dump(4);

        FILE* fp = qfopen(path.c_str(), "wb");
        if (fp == nullptr)
        {
            warning("AiDA: Failed to open settings file for writing: %s", path.c_str());
            return false;
        }

        file_janitor_t fj(fp);

        size_t written = qfwrite(fp, json_str.c_str(), json_str.length());
        if (written != json_str.length())
        {
            warning("AiDA: Failed to write all settings to %s", path.c_str());
            return false;
        }

        msg("AI Assistant: Settings saved to %s\n", path.c_str());
        return true;
    }
    catch (const std::exception& e)
    {
        warning("AI Assistant: Failed to serialize settings: %s", e.what());
        return false;
    }
}

static bool load_settings_from_file(settings_t* settings, const qstring& path)
{
    if (!qfileexist(path.c_str()))
        return false;

    FILE* fp = qfopen(path.c_str(), "rb");
    if (fp == nullptr)
        return false;

    file_janitor_t fj(fp);

    uint64 file_size = qfsize(fp);
    if (file_size == 0)
        return false;

    qstring json_data;
    json_data.resize(file_size);
    if (qfread(fp, json_data.begin(), file_size) != file_size)
    {
        warning("AiDA: Failed to read settings file: %s", path.c_str());
        return false;
    }

    try
    {
        nlohmann::json j = nlohmann::json::parse(json_data.c_str());
        *settings = j.get<settings_t>();
        return true;
    }
    catch (const std::exception& e)
    {
        warning("AI Assistant: Could not parse config file %s: %s", path.c_str(), e.what());
        return false;
    }
}


settings_t::settings_t() :
    api_provider(""),
    gemini_api_key(""),
    gemini_model_name("gemini-1.5-flash-latest"),
    openai_api_key(""),
    openai_model_name("gpt-4-turbo"),
    anthropic_api_key(""),
    anthropic_model_name("claude-3-sonnet-20240229"),
    xref_context_count(5),
    xref_analysis_depth(3),
    xref_code_snippet_lines(30),
    bulk_processing_delay(1.5),
    max_prompt_tokens(30000),
    max_root_func_scan_count(40),
    max_root_func_candidates(40),
    temperature(0.1)
{
}

void settings_t::save()
{
    save_settings_to_file(*this, get_config_file());
}

void settings_t::load(aida_plugin_t* plugin_instance)
{
    bool has_env_keys = false;
    qstring val;

    if (gemini_api_key.empty() && qgetenv("GEMINI_API_KEY", &val))
    {
        gemini_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openai_api_key.empty() && qgetenv("OPENAI_API_KEY", &val))
    {
        openai_api_key = val.c_str();
        has_env_keys = true;
    }
    if (anthropic_api_key.empty() && qgetenv("ANTHROPIC_API_KEY", &val))
    {
        anthropic_api_key = val.c_str();
        has_env_keys = true;
    }

    if (has_env_keys)
    {
        msg("AI Assistant: Loaded one or more API keys from environment variables.\n");
    }

    bool config_exists_and_valid = load_from_file();

    if (!config_exists_and_valid || api_provider.empty())
    {
        info("AI Assistant: Welcome! Please configure the plugin to begin.");
        SettingsForm::show_and_apply(plugin_instance);
        return;
    }

    if (config_exists_and_valid)
    {
        msg("AI Assistant: Loaded settings from %s\n", get_config_file().c_str());
    }

    if (!api_provider.empty() && get_active_api_key().empty())
    {
        prompt_for_api_key();
    }
}

bool settings_t::load_from_file()
{
    return load_settings_from_file(this, get_config_file());
}

std::string settings_t::get_active_api_key() const
{
    qstring provider = api_provider.c_str();
    qstrlwr(provider.begin());
    if (provider == "gemini") return gemini_api_key;
    if (provider == "openai") return openai_api_key;
    if (provider == "anthropic") return anthropic_api_key;
    return "";
}

void settings_t::prompt_for_api_key()
{
    qstring provider_name = api_provider.c_str();
    if (!provider_name.empty())
        provider_name[0] = qtoupper(provider_name[0]);

    warning("AI Assistant: %s API key not found.", provider_name.c_str());

    qstring key;
    qstring question;
    question.sprnt("Please enter your %s API key to continue:", provider_name.c_str());
    if (ask_str(&key, HIST_SRCH, question.c_str()))
    {
        qstring provider = api_provider.c_str();
        qstrlwr(provider.begin());
        if (provider == "gemini") gemini_api_key = key.c_str();
        else if (provider == "openai") openai_api_key = key.c_str();
        else if (provider == "anthropic") anthropic_api_key = key.c_str();
        save();
    }
    else
    {
        warning("AI Assistant will be disabled until an API key is provided for %s.", provider_name.c_str());
    }
}