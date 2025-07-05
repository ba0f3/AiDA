#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

#include <ida.hpp>
#include <kernwin.hpp>
#include <httplib.h>

class AIClientBase
{
public:
    using callback_t = std::function<void(const std::string&)>;
    using addr_callback_t = std::function<void(ea_t)>;

    AIClientBase(const settings_t& settings);
    virtual ~AIClientBase();

    virtual bool is_available() const = 0;
    virtual void analyze_function(ea_t ea, callback_t callback);
    virtual void suggest_name(ea_t ea, callback_t callback);
    virtual void generate_struct(ea_t ea, callback_t callback);
    virtual void generate_hook(ea_t ea, callback_t callback);
    virtual void custom_query(ea_t ea, const std::string& question, callback_t callback);
    virtual void locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback);

    void cancel_current_request();

    std::atomic<bool> _task_done{false};

protected:
    const settings_t& _settings;
    std::string _model_name;

    std::thread _worker_thread;
    std::mutex _worker_thread_mutex;

    std::shared_ptr<httplib::Client> _http_client;
    std::mutex _http_client_mutex;

    std::atomic<bool> _cancelled{false};

    void _generate(const std::string& prompt_text, callback_t callback, double temperature);
    virtual std::string _blocking_generate(const std::string& prompt_text, double temperature) = 0;
    std::string _http_post_request(
        const std::string& host,
        const std::string& path,
        const httplib::Headers& headers,
        const std::string& body,
        std::function<std::string(const nlohmann::json&)> response_parser);

private:
    std::shared_ptr<void> _validity_token;
    
    struct ai_request_t;
};

class GeminiClient : public AIClientBase
{
public:
    GeminiClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _blocking_generate(const std::string& prompt_text, double temperature) override;
};

class OpenAIClient : public AIClientBase
{
public:
    OpenAIClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _blocking_generate(const std::string& prompt_text, double temperature) override;
};

class AnthropicClient : public AIClientBase
{
public:
    AnthropicClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _blocking_generate(const std::string& prompt_text, double temperature) override;
};

std::unique_ptr<AIClientBase> get_ai_client(const settings_t& settings);