import ida_idaapi
import ida_kernwin

from . import actions
from . import ui
from .ai import get_ai_client
from .core.settings import SETTINGS

try:
    import google.generativeai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    ida_kernwin.warning(
        "AI Assistant: 'google-generativeai' package not found.\n\n"
        "If you want to use the Gemini provider, please close IDA and install it from your terminal:\n"
        "<path_to_ida_python> -m pip install google-generativeai\n\n"
        "The plugin will continue to load, but Gemini features will be disabled."
    )

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    ida_kernwin.warning(
        "AI Assistant: 'openai' package not found.\n\n"
        "If you want to use the OpenAI provider (ChatGPT/Copilot), please close IDA and install it from your terminal:\n"
        "<path_to_ida_python> -m pip install openai\n\n"
        "The plugin will continue to load, but OpenAI features will be disabled."
    )

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    ida_kernwin.warning(
        "AI Assistant: 'anthropic' package not found.\n\n"
        "If you want to use the Anthropic provider (Claude), please close IDA and install it from your terminal:\n"
        "<path_to_ida_python> -m pip install anthropic\n\n"
        "The plugin will continue to load, but Anthropic features will be disabled."
    )


class AIAssistantPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "AI-powered game reversing assistant"
    help = "Right-click in code views or use the Tools->AI Assistant menu"
    wanted_name = "AI Assistant"
    wanted_hotkey = ""

    def init(self):
        ida_kernwin.msg("--- AI Assistant Plugin Loading ---\n")

        self.hooks = None
        self.ai_client = None
        self.actions_list = []

        SETTINGS.load(self)

        self.ai_client = get_ai_client(SETTINGS)
        if not self.ai_client or not self.ai_client.is_available():
            ida_kernwin.msg("AI Assistant: No AI client is available. AI features will be limited.\n")
            if not GENAI_AVAILABLE and not OPENAI_AVAILABLE and not ANTHROPIC_AVAILABLE:
                ida_kernwin.warning(
                    "AI Assistant: No AI libraries (google-generativeai, openai, anthropic) are installed.\n"
                    "The plugin will have no functionality. Please install one of them.")

        action_definitions = [
            ("ai_assistant:scan_for_offsets", "Scan for Engine Pointers (Coming Soon!)", actions.handle_scan_for_offsets, "Ctrl+Alt+F"),
            ("ai_assistant:analyze", "Analyze function...", actions.handle_analyze_function, "Ctrl+Alt+A"),
            ("ai_assistant:rename", "Suggest new name...", actions.handle_rename_function, "Ctrl+Alt+S"),
            ("ai_assistant:comment", "Add AI-generated comment", actions.handle_auto_comment, "Ctrl+Alt+C"),
            ("ai_assistant:gen_struct", "Generate struct from function", actions.handle_generate_struct, "Ctrl+Alt+G"),
            ("ai_assistant:gen_hook", "Generate MinHook C++ snippet", actions.handle_generate_hook, "Ctrl+Alt+H"),
            ("ai_assistant:custom_query", "Custom query...", actions.handle_custom_query, "Ctrl+Alt+Q"),
            ("ai_assistant:settings", "Settings...", actions.handle_show_settings, "Ctrl+Alt+O"),
        ]

        menu_root = "Tools/AI Assistant/"
        for name, desc, handler, hotkey in action_definitions:
            self.actions_list.append(name)
            if ida_kernwin.register_action(ida_kernwin.action_desc_t(name, desc, actions.ActionHandler(handler, self), hotkey)):
                pass
            else:
                ida_kernwin.msg(f"AI Assistant: Failed to register action {name}\n")

        self.hooks = ui.UIHooks()
        self.hooks.hook()

        ida_kernwin.msg("--- AI Assistant Plugin Loaded Successfully ---\n")
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        ida_kernwin.info("AI Assistant is active. Use the right-click context menu in a code view.")

    def term(self):
        if self.hooks:
            self.hooks.unhook()

        for action_name in self.actions_list:
            ida_kernwin.unregister_action(action_name)

        ida_kernwin.msg("--- To use AiDA: Edit -> Plugins -> AI Assistant ---\n")

_plugin_instance = None
def PLUGIN_ENTRY():
    global _plugin_instance
    if _plugin_instance is None:
        _plugin_instance = AIAssistantPlugin()
    return _plugin_instance