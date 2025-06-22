import re
import ida_kernwin

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    anthropic = None

from .base_client import AIClientBase
from . import prompts
from ..core import ida_utils

class AnthropicClient(AIClientBase):
    def __init__(self, settings):
        super().__init__(settings)
        if not ANTHROPIC_AVAILABLE:
            self.model = None
            return

        if not self.settings.anthropic_api_key:
            self.model = None
            ida_kernwin.msg("AI Assistant: Anthropic client disabled; API key is missing.\n")
            return

        try:
            self.client = anthropic.Anthropic(api_key=self.settings.anthropic_api_key)
            self.model = self.settings.anthropic_model_name
        except Exception as e:
            ida_kernwin.warning(f"AI Assistant: Anthropic client configuration failed. Check API Key/Model Name.\nError: {e}\n")
            self.model = None

    def is_available(self):
        return self.model is not None

    def _generate(self, prompt_text, temperature=0.1):
        if not self.is_available():
            return "Error: Anthropic client is not initialized. Check API key and installation."

        try:
            ida_kernwin.show_wait_box(f"Querying Anthropic ({self.model})...")
            
            system_prompt = prompts.BASE_PROMPT
            user_prompt = prompt_text.replace(prompts.BASE_PROMPT, "").strip()

            if len(user_prompt) > self.settings.max_prompt_tokens:
                ida_kernwin.msg("AI Assistant: Warning: Prompt is too long, truncating...\n")
                user_prompt = user_prompt[:self.settings.max_prompt_tokens]

            response = self.client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=4096,
                temperature=temperature,
            )
            ida_kernwin.hide_wait_box()
            
            if not response.content:
                return "Error: Received empty response from API."

            return response.content[0].text.strip()

        except anthropic.AuthenticationError as e:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"Anthropic API Error: {e}. This is likely due to an invalid or disabled API Key.")
            self.model = None
            return f"Error: Invalid API Key. {e}"
        except Exception as e:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"AI Assistant: Anthropic API call failed: {e}\n")
            return f"Error: API call failed. Details: {e}"

    def analyze_function(self, ea):
        context = ida_utils.get_context_for_prompt(ea)
        if not context["ok"]: return context["message"]
        prompt = prompts.ANALYZE_FUNCTION_PROMPT.format(**context)
        return self._generate(prompt)

    def suggest_name(self, ea):
        context = ida_utils.get_context_for_prompt(ea)
        if not context["ok"]: return context["message"]
        prompt = prompts.SUGGEST_NAME_PROMPT.format(**context)
        name = self._generate(prompt, 0.0)
        return name.replace("`", "").strip() if name else None

    def generate_struct(self, ea):
        context = ida_utils.get_context_for_prompt(ea, include_struct_context=True)
        if not context["ok"]: return context["message"]
        prompt = prompts.GENERATE_STRUCT_PROMPT.format(**context)
        return self._generate(prompt, 0.0)

    def generate_hook(self, ea):
        import ida_name
        code, lang = ida_utils.get_function_code(ea)
        if lang == "Error": return code
        func_name = ida_name.get_name(ea)
        clean_func_name = re.sub(r'[^a-zA-Z0-9_]', '_', func_name)
        prompt = prompts.GENERATE_HOOK_PROMPT.format(func_name=clean_func_name, func_ea=ea, code=code)
        return self._generate(prompt, 0.0)

    def custom_query(self, ea, question):
        context = ida_utils.get_context_for_prompt(ea)
        if not context["ok"]: return context["message"]
        prompt = prompts.CUSTOM_QUERY_PROMPT.format(user_question=question, **context)
        return self._generate(prompt, 0.4)

    def locate_global_pointer(self, ea, target_name):
        code, lang = ida_utils.get_function_code(ea, 16000)
        if lang == "Error":
            return None

        prompt = prompts.LOCATE_GLOBAL_POINTER_PROMPT.format(
            target_name=target_name,
            code=code
        )
        
        result = self._generate(prompt, 0.0)

        if result and "Error:" not in result and "None" not in result:
            try:
                return int(result.strip().replace('`', ''), 16)
            except (ValueError, TypeError):
                ida_kernwin.msg(f"AI Assistant: AI returned a non-address value for {target_name}: {result}\n")
                return None
        
        return None