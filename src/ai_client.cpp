#include "aida_pro.hpp"
using json = nlohmann::json;


static int idaapi timer_cb(void* ud);

struct AIClient::ai_request_t : public exec_request_t
{
    std::string result;
    bool was_cancelled;
    AIClient::callback_t callback;
    qtimer_t timer;
    qstring request_type;
    std::weak_ptr<void> client_validity_token;

    ai_request_t(
        AIClient::callback_t cb,
        qtimer_t t,
        qstring req_type,
        std::shared_ptr<void> validity_token)
        : was_cancelled(false),
        callback(std::move(cb)),
        timer(t),
        request_type(std::move(req_type)),
        client_validity_token(validity_token) {}

    ~ai_request_t() override = default;

    ssize_t idaapi execute() override
    {
        std::shared_ptr<void> client_validity_sp = client_validity_token.lock();
        if (!client_validity_sp)
        {
            delete this;
            return 0;
        }

        try
        {
            if (timer != nullptr)
            {
                unregister_timer(timer);
                timer = nullptr;
            }

            if (was_cancelled)
            {
                msg("AiDA: Request for %s was cancelled.\n", request_type.c_str());
            }
            else if (callback)
            {
                callback(result);
            }
        }
        catch (const std::exception& e)
        {
            warning("AI Assistant: Exception caught during AI request callback execution: %s", e.what());
        }
        catch (...)
        {
            warning("AI Assistant: Unknown exception caught during AI request callback execution.");
        }

        delete this;
        return 0;
    }
};

static int idaapi timer_cb(void* ud)
{
    auto* client = static_cast<AIClient*>(ud);

    if (client->_task_done.load())
    {
        return -1;
    }

    if (user_cancelled())
    {
        client->cancel_current_request();
        return -1;
    }

    if (!client->_is_request_active.load())
    {
        client->_is_request_active = true;
        msg("AiDA: Request for %s is in progress, please wait...\n", client->_current_request_type.c_str());
    }
    else
    {
        int elapsed = client->_elapsed_secs.load();
        msg("AiDA: Request for %s is in progress... elapsed time: %d second%s.\n",
            client->_current_request_type.c_str(),
            elapsed,
            elapsed == 1 ? "" : "s");
    }

    client->_elapsed_secs++;
    return 1000; // Reschedule for 1 second later
}

AIClient::AIClient(const settings_t& settings)
    : _settings(settings), _validity_token(std::make_shared<char>()) {}

AIClient::~AIClient()
{
    _validity_token.reset();
    cancel_current_request();
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }
}

void AIClient::cancel_current_request()
{
    _cancelled = true;
    std::shared_ptr<httplib::Client> client_to_stop;
    {
        std::lock_guard<std::mutex> lock(_http_client_mutex);
        client_to_stop = _http_client;
    }

    if (client_to_stop)
    {
        client_to_stop->stop();
    }
}

void AIClient::_generate(const std::string& prompt_text, callback_t callback, double temperature, const qstring& request_type)
{
    std::lock_guard<std::mutex> lock(_worker_thread_mutex);
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }

    _cancelled = false;
    _task_done = false;
    _is_request_active = false;
    _current_request_type = request_type;
    _elapsed_secs = 0;

    qtimer_t timer = register_timer(1000, timer_cb, this);

    auto req = new ai_request_t(callback, timer, request_type, _validity_token);

    auto worker_func = [this, prompt_text, temperature, req, validity_token = this->_validity_token]() {
        std::string result;
        try
        {
            result = this->_blocking_generate(prompt_text, temperature);
        }
        catch (const std::exception& e)
        {
            result = "Error: Exception in worker thread: ";
            result += e.what();
            warning("AiDA: %s", result.c_str());
        }
        catch (...)
        {
            result = "Error: Unknown exception in worker thread.";
            warning("AiDA: %s", result.c_str());
        }

        _task_done = true;

        req->was_cancelled = _cancelled.load();
        if (!req->was_cancelled)
        {
            req->result = std::move(result);
        }

        execute_sync(*req, MFF_NOWAIT);
    };

    _worker_thread = std::thread(worker_func);
}

std::string AIClient::_http_post_request(
    const std::string& host,
    const std::string& path,
    const httplib::Headers& headers,
    const std::string& body,
    std::function<std::string(const json&)> response_parser)
{
    std::shared_ptr<httplib::Client> current_client;
    try
    {
        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client = std::make_shared<httplib::Client>(host.c_str());
            current_client = _http_client;
        }

        current_client->set_default_headers(headers);
        current_client->set_read_timeout(600); // 10 minutes
        current_client->set_connection_timeout(10);

        auto res = current_client->Post(
            path.c_str(),
            body.c_str(),
            body.length(),
            "application/json",
            [this](uint64_t, uint64_t) {
                return !_cancelled.load();
            });

        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client.reset();
        }

        if (_cancelled)
            return "Error: Operation cancelled.";

        if (!res)
        {
            auto err = res.error();
            if (err == httplib::Error::Canceled) {
                return "Error: Operation cancelled.";
            }
            return "Error: HTTP request failed: " + httplib::to_string(err);
        }
        if (res->status != 200)
        {
            qstring error_details = "No details in response body.";
            if (!res->body.empty())
            {
                try
                {
                    error_details = json::parse(res->body).dump(2).c_str();
                }
                catch (const json::parse_error&)
                {
                    error_details = res->body.c_str();
                }
            }
            msg("AiDA: API Error. Host: %s, Status: %d\nResponse body: %s\n", host.c_str(), res->status, error_details.c_str());
            return "Error: API returned status " + std::to_string(res->status);
        }
        json jres = json::parse(res->body);
        return response_parser(jres);
    }
    catch (const std::exception& e)
    {
        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client.reset();
        }
        warning("AI Assistant: API call to %s failed: %s\n", host.c_str(), e.what());
        return std::string("Error: API call failed. Details: ") + e.what();
    }
}

std::string AIClient::_blocking_generate(const std::string& prompt_text, double temperature)
{
    if (!is_available())
        return "Error: AI client is not initialized. Check API key.";

    auto payload = _get_api_payload(prompt_text, temperature);
    auto headers = _get_api_headers();
    auto host = _get_api_host();
    auto path = _get_api_path(_model_name);
    auto parser = [this](const json& jres) { return _parse_api_response(jres); };

    return _http_post_request(host, path, headers, payload.dump(), parser);
}

void AIClient::analyze_function(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    std::string prompt = ida_utils::format_prompt(ANALYZE_FUNCTION_PROMPT, context);

    _generate(prompt, callback, _settings.temperature, "function analysis");
}

void AIClient::suggest_name(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    std::string prompt = ida_utils::format_prompt(SUGGEST_NAME_PROMPT, context);
    _generate(prompt, callback, 0.0, "name suggestion");
}

void AIClient::generate_struct(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, true);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    std::string prompt = ida_utils::format_prompt(GENERATE_STRUCT_PROMPT, context);
    _generate(prompt, callback, 0.0, "struct generation");
}

void AIClient::generate_hook(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    qstring q_func_name;
    get_func_name(&q_func_name, ea);
    std::string func_name = q_func_name.c_str();
    
    static const std::regex non_alnum_re("[^a-zA-Z0-9_]");
    std::string clean_func_name = std::regex_replace(func_name, non_alnum_re, "_");
    
    context["func_name"] = clean_func_name;

    std::string prompt = ida_utils::format_prompt(GENERATE_HOOK_PROMPT, context);
    _generate(prompt, callback, 0.0, "hook generation");
}

void AIClient::custom_query(ea_t ea, const std::string& question, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    context["user_question"] = question;
    std::string prompt = ida_utils::format_prompt(CUSTOM_QUERY_PROMPT, context);
    _generate(prompt, callback, _settings.temperature, "custom query");
}

void AIClient::locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, false, 16000);
    if (!context["ok"].get<bool>())
    {
        callback(BADADDR);
        return;
    }
    context["target_name"] = target_name;
    std::string prompt = ida_utils::format_prompt(LOCATE_GLOBAL_POINTER_PROMPT, context);

    auto on_result = [callback, target_name](const std::string& result) {
        if (!result.empty() && result.find("Error:") == std::string::npos && result.find("None") == std::string::npos)
        {
            try
            {
                static const std::regex backtick_re("`");
                std::string clean_result = std::regex_replace(result, backtick_re, "");
                clean_result.erase(0, clean_result.find_first_not_of(" \t\n\r"));
                clean_result.erase(clean_result.find_last_not_of(" \t\n\r") + 1);
                ea_t addr = std::stoull(clean_result, nullptr, 16);
                callback(addr);
            }
            catch (const std::exception&)
            {
                msg("AI Assistant: AI returned a non-address value for %s: %s\n", target_name.c_str(), result.c_str());
                callback(BADADDR);
            }
        }
        else
        {
            callback(BADADDR);
        }
    };
    _generate(prompt, on_result, 0.0, "global pointer location");
}

GeminiClient::GeminiClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.gemini_model_name;
}

bool GeminiClient::is_available() const
{
    return !_settings.gemini_api_key.empty();
}


std::string GeminiClient::_get_api_host() const { return "https://generativelanguage.googleapis.com"; }
std::string GeminiClient::_get_api_path(const std::string& model_name) const { return "/v1beta/models/" + model_name + ":generateContent?key=" + _settings.gemini_api_key; }
httplib::Headers GeminiClient::_get_api_headers() const { return {}; }
json GeminiClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"contents", {{{"role", "user"}, {"parts", {{{"text", prompt_text}}}}}}},
        {"generationConfig", {{"temperature", temperature}}}
    };
}
std::string GeminiClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("candidates") && !jres["candidates"].empty())
    {
        return jres["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
    }
    msg("AiDA: Invalid Gemini API response.\nResponse body: %s\n", jres.dump().c_str());
    return "Error: Received empty or invalid response from API. " + jres.dump();
}

OpenAIClient::OpenAIClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.openai_model_name;
}

bool OpenAIClient::is_available() const
{
    return !_settings.openai_api_key.empty();
}

std::string OpenAIClient::_get_api_host() const { return "https://api.openai.com"; }
std::string OpenAIClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers OpenAIClient::_get_api_headers() const
{
    return {
        {"Authorization", "Bearer " + _settings.openai_api_key},
        {"Content-Type", "application/json"}
    };
}
json OpenAIClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", BASE_PROMPT}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"temperature", temperature}
    };
}
std::string OpenAIClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("choices") && !jres["choices"].empty())
    {
        return jres["choices"][0]["message"]["content"].get<std::string>();
    }
    msg("AiDA: Invalid OpenAI API response.\nResponse body: %s\n", jres.dump().c_str());
    return "Error: Received empty or invalid response from API. " + jres.dump();
}

AnthropicClient::AnthropicClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.anthropic_model_name;
}

bool AnthropicClient::is_available() const
{
    return !_settings.anthropic_api_key.empty();
}

std::string AnthropicClient::_get_api_host() const { return "https://api.anthropic.com"; }
std::string AnthropicClient::_get_api_path(const std::string&) const { return "/v1/messages"; }
httplib::Headers AnthropicClient::_get_api_headers() const
{
    return {
        {"x-api-key", _settings.anthropic_api_key},
        {"anthropic-version", "2023-06-01"},
        {"Content-Type", "application/json"}
    };
}
json AnthropicClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"model", _model_name},
        {"system", BASE_PROMPT},
        {"messages", {{{"role", "user"}, {"content", prompt_text}}}},
        {"max_tokens", 4096},
        {"temperature", temperature}
    };
}
std::string AnthropicClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("content") && !jres["content"].empty())
    {
        return jres["content"][0]["text"].get<std::string>();
    }
    msg("AiDA: Invalid Anthropic API response.\nResponse body: %s\n", jres.dump().c_str());
    return "Error: Received empty or invalid response from API. " + jres.dump();
}

CopilotClient::CopilotClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.copilot_model_name;
}

bool CopilotClient::is_available() const
{
    return !_settings.copilot_proxy_address.empty();
}

std::string CopilotClient::_get_api_host() const { return _settings.copilot_proxy_address; }
std::string CopilotClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers CopilotClient::_get_api_headers() const { return {{"Content-Type", "application/json"}}; }
json CopilotClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", BASE_PROMPT}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"temperature", temperature}
    };
}
std::string CopilotClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("choices") && !jres["choices"].empty())
    {
        return jres["choices"][0]["message"]["content"].get<std::string>();
    }
    msg("AiDA: Invalid Copilot API response.\nResponse body: %s\n", jres.dump().c_str());
    return "Error: Received empty or invalid response from API. " + jres.dump();
}

std::unique_ptr<AIClient> get_ai_client(const settings_t& settings)
{
    qstring provider = ida_utils::qstring_tolower(settings.api_provider.c_str());

    msg("AI Assistant: Initializing AI provider: %s\n", provider.c_str());

    if (provider == "gemini")
    {
        return std::make_unique<GeminiClient>(settings);
    }
    else if (provider == "openai")
    {
        return std::make_unique<OpenAIClient>(settings);
    }
    else if (provider == "anthropic")
    {
        return std::make_unique<AnthropicClient>(settings);
    }
    else if (provider == "copilot")
    {
        return std::make_unique<CopilotClient>(settings);
    }
    else
    {
        warning("AI Assistant: Unknown AI provider '%s' in settings. No AI features will be available.", provider.c_str());
        return nullptr;
    }
}