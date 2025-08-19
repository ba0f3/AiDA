#include "aida_pro.hpp"

settings_t g_settings;

const std::vector<std::string> settings_t::gemini_models = {
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-pro-latest",
    "gemini-1.5-pro",
    "gemini-1.5-pro-002",
    "gemini-1.5-flash-latest",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
    "gemini-1.5-flash-8b-latest",
    "gemini-2.0-flash-exp",
    "gemini-2.0-flash-lite-preview",
    "gemini-2.0-pro-exp",
    "gemini-2.0-flash-thinking-exp",
    "gemma-3-1b-it",
    "gemma-3-4b-it",
    "gemma-3-12b-it",
    "gemma-3-27b-it",
    "gemma-3n-e4b-it",
    "gemma-3n-e2b-it"
};

const std::vector<std::string> settings_t::openai_models = {
  "gpt-5",
  "gpt-5-mini",
  "gpt-5-nano",
  "o3-pro",
  "o3",
  "o3-mini",
  "o1-pro",
  "o1",
  "o4-mini",
  "gpt-4.5-preview",
  "gpt-4.1",
  "gpt-4.1-mini",
  "gpt-4.1-nano",
  "gpt-4o",
  "gpt-4-turbo",
  "gpt-4",
  "gpt-4o-mini",
  "gpt-3.5-turbo",
  "gpt-3.5-turbo-16k",
};

const std::vector<std::string> settings_t::anthropic_models = {
  "claude-opus-4-0",
  "claude-sonnet-4-0",
  "claude-3.5-sonnet-latest",
  "claude-3.5-haiku-latest",
  "claude-3-opus-latest",
  "claude-3-sonnet-latest",
  "claude-3-haiku-latest",
  "claude-2.1",
  "claude-2",
  "claude-instant-v1.2",
};

const std::vector<std::string> settings_t::copilot_models = {
    "claude-sonnet-4",
    "claude-3.7-sonnet-thought",
    "gemini-2.5-pro",
    "claude-3.7-sonnet",
    "gpt-4.1-2025-04-14",
    "gpt-4.1",
    "o4-mini-2025-04-16",
    "o4-mini",
    "o3-mini-2025-01-31",
    "o3-mini",
    "o3-mini-paygo",
    "claude-3.5-sonnet",
    "gemini-2.0-flash-001",
    "gpt-4o-2024-11-20",
    "gpt-4o-2024-08-06",
    "gpt-4o-2024-05-13",
    "gpt-4o",
    "gpt-4o-copilot",
    "gpt-4-o-preview",
    "gpt-4-0125-preview",
    "gpt-4",
    "gpt-4-0613",
    "gpt-4o-mini-2024-07-18",
    "gpt-4o-mini",
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-0613",
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(settings_t,
    api_provider,
    gemini_api_key, gemini_model_name,
    openai_api_key, openai_model_name,
    anthropic_api_key, anthropic_model_name,
    copilot_proxy_address, copilot_model_name,
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
    gemini_model_name("gemini-2.0-flash"),
    openai_api_key(""),
    openai_model_name("gpt-5"),
    anthropic_api_key(""),
    anthropic_model_name("claude-3.5-sonnet-latest"),
    copilot_proxy_address("http://127.0.0.1:4141"),
    copilot_model_name("gpt-4o"),
    xref_context_count(5),
    xref_analysis_depth(3),
    xref_code_snippet_lines(30),
    bulk_processing_delay(1.5),
    max_prompt_tokens(1048576),
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
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == "gemini") return gemini_api_key;
    if (provider == "openai") return openai_api_key;
    if (provider == "anthropic") return anthropic_api_key;
    if (provider == "copilot") return copilot_proxy_address;
    return "";
}

void settings_t::prompt_for_api_key()
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());

    if (provider == "copilot")
    {
        warning("AI Assistant: Copilot provider is selected, but the proxy address is not configured. Please set it in the settings dialog.");
        return;
    }

    qstring provider_name = api_provider.c_str();
    if (!provider_name.empty())
        provider_name[0] = qtoupper(provider_name[0]);

    warning("AI Assistant: %s API key not found.", provider_name.c_str());

    qstring key;
    qstring question;
    question.sprnt("Please enter your %s API key to continue:", provider_name.c_str());
    if (ask_str(&key, HIST_SRCH, question.c_str()))
    {
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