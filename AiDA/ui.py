import ida_kernwin
import ida_lines
import re
import ida_bytes
import ida_idaapi
from .core.settings import SETTINGS
from .ai import get_ai_client

class SettingsForm(ida_kernwin.Form):
    def __init__(self, settings):
        self._settings = settings
        
        form_str = """AI Assistant Settings
STARTITEM 0
{fChangeCb}
<##API Provider Configuration##Provider:{fProvider}>

<##Gemini##API Key:{iGeminiApiKey}>
<Model Name:{iGeminiModelName}>

<##OpenAI##API Key:{iOpenAiApiKey}>
<Model Name:{iOpenAiModelName}>

<##Anthropic##API Key:{iAnthropicApiKey}>
<Model Name:{iAnthropicModelName}>

<##Analysis Parameters##XRef Context Count:{iXrefCount}>
<XRef Analysis Depth:{iXrefDepth}>
<Code Snippet Lines:{iSnippetLines}>
<Bulk Processing Delay (sec):{sBulkDelay}>
<Max Prompt Tokens:{iMaxTokens}>
"""
        provider_map = {"gemini": 0, "openai": 1, "anthropic": 2}
        
        gemini_models = [
            'gemini-2.5-pro',
            'gemini-2.5-flash',
            'gemini-2.0-flash',
            'gemini-1.5-flash-latest',
            'gemini-1.5-pro-latest',
            'gemini-1.0-pro'
        ]
        openai_models = [
            'gpt-4-turbo',
            'gpt-4o',
            'gpt-4o-mini',
            'gpt-4.1',
            'gpt-4',
            'o3',
            'o3-mini',
            'o3-pro',
            'o4-mini',
            'o4-mini-high',
            'gpt-3.5-turbo'
        ]
        anthropic_models = [
            'claude-opus-4-0',
            'claude-sonnet-4-0',
            'claude-3-7-sonnet-latest'
            'claude-3-5-sonnet-latest',
            'claude-3-5-haiku-latest',
            'claude-3-opus-latest',
            'claude-3-sonnet-latest',
            'claude-3-haiku-latest',
            'claude-2'
        ]

        controls = {
            'fChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
            'fProvider': ida_kernwin.Form.DropdownListControl(
                items=["Gemini", "OpenAI", "Anthropic"],
                readonly=True,
                selval=provider_map.get(self._settings.api_provider.lower(), 0)),
            
            'iGeminiApiKey': ida_kernwin.Form.StringInput(
                value=self._settings.gemini_api_key,
                swidth=60,
                tp=ida_kernwin.Form.FT_ASCII),

            'iGeminiModelName': ida_kernwin.Form.DropdownListControl(
                items=gemini_models,
                readonly=False,
                selval=self._settings.gemini_model_name,
                swidth=60),

            'iOpenAiApiKey': ida_kernwin.Form.StringInput(
                value=self._settings.openai_api_key,
                swidth=60,
                tp=ida_kernwin.Form.FT_ASCII),

            'iOpenAiModelName': ida_kernwin.Form.DropdownListControl(
                items=openai_models,
                readonly=False,
                selval=self._settings.openai_model_name,
                swidth=60),

            'iAnthropicApiKey': ida_kernwin.Form.StringInput(
                value=self._settings.anthropic_api_key,
                swidth=60,
                tp=ida_kernwin.Form.FT_ASCII),

            'iAnthropicModelName': ida_kernwin.Form.DropdownListControl(
                items=anthropic_models,
                readonly=False,
                selval=self._settings.anthropic_model_name,
                swidth=60),

            'iXrefCount': ida_kernwin.Form.NumericInput(value=self._settings.xref_context_count, tp=ida_kernwin.Form.FT_DEC),
            'iXrefDepth': ida_kernwin.Form.NumericInput(value=self._settings.xref_analysis_depth, tp=ida_kernwin.Form.FT_DEC),
            'iSnippetLines': ida_kernwin.Form.NumericInput(value=self._settings.xref_code_snippet_lines, tp=ida_kernwin.Form.FT_DEC),
            
            'sBulkDelay': ida_kernwin.Form.StringInput(
                value=str(self._settings.bulk_processing_delay),
                swidth=10,
                tp=ida_kernwin.Form.FT_ASCII),

            'iMaxTokens': ida_kernwin.Form.NumericInput(value=self._settings.max_prompt_tokens, tp=ida_kernwin.Form.FT_DEC),
        }
        ida_kernwin.Form.__init__(self, form_str, controls)


    def OnFormChange(self, fid):
        if fid == -1 or fid == self.fProvider.id:
            provider_idx = self.GetControlValue(self.fProvider)

            show_gemini = (provider_idx == 0)
            self.ShowField(self.iGeminiApiKey, show_gemini)
            self.ShowField(self.iGeminiModelName, show_gemini)
            
            show_openai = (provider_idx == 1)
            self.ShowField(self.iOpenAiApiKey, show_openai)
            self.ShowField(self.iOpenAiModelName, show_openai)

            show_anthropic = (provider_idx == 2)
            self.ShowField(self.iAnthropicApiKey, show_anthropic)
            self.ShowField(self.iAnthropicModelName, show_anthropic)
        
        return 1

    @staticmethod
    def show_and_apply(plugin_instance):
        form = SettingsForm(SETTINGS)
        form.Compile()
        
        if not form.Compiled():
            ida_kernwin.warning("AI Assistant: Could not compile the settings form. Check for syntax errors.")
            return

        ok = form.Execute()
        if ok == 1:
            provider_map = {0: "gemini", 1: "openai", 2: "anthropic"}
            SETTINGS.api_provider = provider_map[form.fProvider.value]
            
            SETTINGS.gemini_api_key = form.iGeminiApiKey.value
            SETTINGS.gemini_model_name = form.iGeminiModelName.value
            SETTINGS.openai_api_key = form.iOpenAiApiKey.value
            SETTINGS.openai_model_name = form.iOpenAiModelName.value
            SETTINGS.anthropic_api_key = form.iAnthropicApiKey.value
            SETTINGS.anthropic_model_name = form.iAnthropicModelName.value
            
            SETTINGS.xref_context_count = form.iXrefCount.value
            SETTINGS.xref_analysis_depth = form.iXrefDepth.value
            SETTINGS.xref_code_snippet_lines = form.iSnippetLines.value
            
            try:
                SETTINGS.bulk_processing_delay = float(form.sBulkDelay.value)
            except (ValueError, TypeError):
                ida_kernwin.warning(f"Invalid value for Bulk Processing Delay: '{form.sBulkDelay.value}'. Setting not changed.")

            SETTINGS.max_prompt_tokens = form.iMaxTokens.value
            SETTINGS.save()
            
            if plugin_instance:
                ida_kernwin.msg("AI Assistant: Settings updated. Re-initializing AI client...\n")
                plugin_instance.ai_client = get_ai_client(SETTINGS)

        form.Free()

class InteractiveTextViewer(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super(InteractiveTextViewer, self).__init__()

    def OnDblClick(self, shift):
        word = self.GetCurrentWord()
        if not word:
            return False

        cleaned_word = word.strip().strip("`'\"():,.[];")
        if cleaned_word.startswith('&'):
            cleaned_word = cleaned_word[1:]

        if not cleaned_word:
            return False

        ea = ida_kernwin.str2ea(cleaned_word)

        if ea is not None and ea != ida_idaapi.BADADDR and ida_bytes.is_mapped(ea):
            ida_kernwin.jumpto(ea)
            return True

        return False

def show_text_in_viewer(title, text_content):
    if not text_content or not text_content.strip():
        ida_kernwin.warning("AI returned an empty or whitespace-only response. Nothing to display.")
        return

    existing_viewer = ida_kernwin.find_widget(title)
    if existing_viewer:
        ida_kernwin.close_widget(existing_viewer, 0)
    
    viewer = InteractiveTextViewer()
    
    if not viewer.Create(title):
        alt_title = f"{title} (2)"
        if not viewer.Create(alt_title):
            ida_kernwin.warning(f"Could not create viewer '{title}' or '{alt_title}'.")
            return
            
    for line in text_content.splitlines():
        clean_line = ida_lines.tag_remove(line)
        viewer.AddLine(clean_line)
    
    viewer.Show()

class UIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ctx and ctx.widget_type in [ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM]:
            menu_path = "AI Assistant/"
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:analyze", menu_path + "Analyze/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:rename", menu_path + "Analyze/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:comment", menu_path + "Analyze/")
            
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:gen_struct", menu_path + "Generate/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:gen_hook", menu_path + "Generate/")
            
            ida_kernwin.attach_action_to_popup(widget, popup_handle, None, menu_path)
            
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:scan_for_offsets", menu_path)
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:custom_query", menu_path)
            
            ida_kernwin.attach_action_to_popup(widget, popup_handle, None, menu_path)
            
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "ai_assistant:settings", menu_path)
        return 0