import ida_kernwin
from .gemini_client import GeminiClient
from .openai_client import OpenAIClient
from .anthropic_client import AnthropicClient

def get_ai_client(settings):
    provider = settings.api_provider.lower()
    
    ida_kernwin.msg(f"AI Assistant: Initializing AI provider: {provider}\n")

    if provider == "gemini":
        return GeminiClient(settings)
    elif provider == "openai":
        return OpenAIClient(settings)
    elif provider == "anthropic":
        return AnthropicClient(settings)
    else:
        ida_kernwin.warning(f"AI Assistant: Unknown AI provider '{provider}' in settings. No AI features will be available.")
        return None