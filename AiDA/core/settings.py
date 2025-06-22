import json
import os
import ida_kernwin
import ida_diskio

def get_config_file():
    return os.path.join(ida_diskio.get_user_idadir(), "ai_assistant.cfg")

class PluginSettings:
    def __init__(self):
        self.api_provider = ""

        self.gemini_api_key = ""
        self.gemini_model_name = 'gemini-1.5-flash-latest'

        self.openai_api_key = ""
        self.openai_model_name = 'gpt-4-turbo'

        self.anthropic_api_key = ""
        self.anthropic_model_name = 'claude-3-sonnet-20240229'

        self.xref_context_count = 5
        self.xref_analysis_depth = 3
        self.xref_code_snippet_lines = 30
        self.bulk_processing_delay = 1.5
        self.max_prompt_tokens = 30000

        self.max_root_func_scan_count = 40
        self.max_root_func_candidates = 40

    def save(self):
        config_path = get_config_file()
        try:
            with open(config_path, "w") as f:
                json.dump(self.__dict__, f, indent=4)
            ida_kernwin.msg(f"AI Assistant: Settings saved to {config_path}\n")
        except IOError as e:
            ida_kernwin.warning(f"AI Assistant: Failed to save settings: {e}")

    def load(self, plugin_instance=None):
        has_env_keys = False
        if not self.gemini_api_key and os.getenv("GEMINI_API_KEY"):
            self.gemini_api_key = os.getenv("GEMINI_API_KEY")
            has_env_keys = True
        if not self.openai_api_key and os.getenv("OPENAI_API_KEY"):
            self.openai_api_key = os.getenv("OPENAI_API_KEY")
            has_env_keys = True
        if not self.anthropic_api_key and os.getenv("ANTHROPIC_API_KEY"):
            self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            has_env_keys = True

        if has_env_keys:
            ida_kernwin.msg("AI Assistant: Loaded one or more API keys from environment variables.\n")

        config_exists_and_valid = self._load_from_file()

        if not config_exists_and_valid or not self.api_provider:
            ida_kernwin.info("AI Assistant: Welcome! Please configure the plugin to begin.")
            
            from ..ui import SettingsForm
            SettingsForm.show_and_apply(plugin_instance)
            return

        if config_exists_and_valid:
            ida_kernwin.msg(f"AI Assistant: Loaded settings from {get_config_file()}\n")

        if self.api_provider and not self.get_active_api_key():
            self._prompt_for_api_key()


    def _load_from_file(self):
        config_path = get_config_file()
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    loaded_settings = json.load(f)
                    self.__dict__.update(loaded_settings)
                return True
            except (IOError, json.JSONDecodeError) as e:
                ida_kernwin.warning(f"AI Assistant: Could not parse config file {config_path}: {e}")
        return False

    def get_active_api_key(self):
        provider = self.api_provider.lower()
        if provider == "gemini":
            return self.gemini_api_key
        elif provider == "openai":
            return self.openai_api_key
        elif provider == "anthropic":
            return self.anthropic_api_key
        return ""

    def _prompt_for_api_key(self):
        provider_name = self.api_provider.capitalize()
        ida_kernwin.warning(f"AI Assistant: {provider_name} API key not found.")
        key = ida_kernwin.ask_str(
            "",
            ida_kernwin.HIST_SRCH,
            f"Please enter your {provider_name} API key to continue:"
        )
        if key:
            provider = self.api_provider.lower()
            if provider == "gemini":
                self.gemini_api_key = key
            elif provider == "openai":
                self.openai_api_key = key
            elif provider == "anthropic":
                self.anthropic_api_key = key
            self.save()
        else:
            ida_kernwin.warning(f"AI Assistant will be disabled until an API key is provided for {provider_name}.")

SETTINGS = PluginSettings()