import ida_kernwin
import ida_funcs
import ida_name
import ida_hexrays
import re

from . import ui
from .core import ida_utils
from .core.settings import SETTINGS
from .patterns import unreal

class ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, action_func, plugin_instance):
        super().__init__()
        self.action_func = action_func
        self.plugin = plugin_instance

    def activate(self, ctx):
        self.action_func(ctx, self.plugin)
        return 1

    def update(self, ctx):
        if not self.plugin.ai_client or not self.plugin.ai_client.is_available():
            if self.action_func in [handle_show_settings, handle_scan_for_offsets]:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

        if self.action_func not in [handle_show_settings, handle_scan_for_offsets]:
            if ctx.widget_type not in [ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM]:
                return ida_kernwin.AST_DISABLE_FOR_WIDGET

        return ida_kernwin.AST_ENABLE_FOR_WIDGET

def handle_analyze_function(ctx, plugin):
    analysis = plugin.ai_client.analyze_function(ctx.cur_ea)
    if analysis and "Error:" not in analysis:
        ui.show_text_in_viewer(f"AI Analysis for 0x{ctx.cur_ea:X}", analysis)

def handle_rename_function(ctx, plugin):
    func = ida_funcs.get_func(ctx.cur_ea)
    if not func: return
    name = plugin.ai_client.suggest_name(func.start_ea)
    if name and "Error:" not in name:
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, f"Rename function at 0x{func.start_ea:X} to:\n\n{name}\n\nApply?") == ida_kernwin.ASKBTN_YES:
            ida_name.set_name(func.start_ea, name, ida_name.SN_CHECK)

def handle_auto_comment(ctx, plugin):
    func = ida_funcs.get_func(ctx.cur_ea)
    if not func: return
    analysis = plugin.ai_client.analyze_function(func.start_ea)
    if analysis and "Error:" not in analysis:
        summary_match = re.search(r"High-Level Purpose:\s*(.*)", analysis)
        summary = summary_match.group(1) if summary_match else analysis.split('\n')[0]
        comment = ida_funcs.get_func_cmt(func, True) or ""
        if "AI Assist:" not in comment:
            new_comment = f"// AI Assist: {summary}\n{comment}"
            ida_funcs.set_func_cmt(func, new_comment, True)
            ida_kernwin.refresh_idaview_anyway()
            vdui = ida_hexrays.get_widget_vdui(ctx.widget)
            if vdui: vdui.refresh_view(True)
            ida_kernwin.msg(f"Comment added to function at 0x{func.start_ea:X}.\n")
        else:
            ida_kernwin.msg("AI-generated comment already exists.\n")

def handle_generate_struct(ctx, plugin):
    from .ai import prompts
    context = ida_utils.get_context_for_prompt(ctx.cur_ea, include_struct_context=True)
    if not context["ok"]:
        ida_kernwin.warning(f"AiDA: {context['message']}")
        return

    prompt = prompts.GENERATE_STRUCT_PROMPT.format(
        code=context["code"],
        struct_context=context["struct_context"]
    )
    struct_cpp = plugin.ai_client._generate(prompt, 0.0)
    if struct_cpp and "Error:" not in struct_cpp:
        ida_utils.apply_struct_from_cpp(struct_cpp, ctx.cur_ea)

def handle_generate_hook(ctx, plugin):
    func = ida_funcs.get_func(ctx.cur_ea)
    if not func: return
    hook_code = plugin.ai_client.generate_hook(func.start_ea)
    if hook_code and "Error:" not in hook_code:
        ui.show_text_in_viewer(f"MinHook Snippet for {ida_name.get_name(func.start_ea)}", hook_code)

def handle_custom_query(ctx, plugin):
    question = ida_kernwin.ask_str("", ida_kernwin.HIST_SRCH, "Ask AI about this function:")
    if question:
        analysis = plugin.ai_client.custom_query(ctx.cur_ea, question)
        if analysis and "Error:" not in analysis:
            ui.show_text_in_viewer(f"AI Query: {question}", analysis)

def handle_scan_for_offsets(ctx, plugin):
    ida_kernwin.msg("====================================================\n")
    ida_kernwin.msg("--- Starting Unreal Engine Pointer Scan ---\n")
    unreal.scan_for_unreal_patterns(plugin.ai_client, SETTINGS)

def handle_show_settings(ctx, plugin):
    ui.SettingsForm.show_and_apply(plugin)