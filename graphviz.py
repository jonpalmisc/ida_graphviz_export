import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_gdl
import ida_lines
import ida_name
import ida_ua


def _node_name(block: ida_gdl.BasicBlock) -> str:
    return f"bb_{block.start_ea}"


def _label_escape(line: str) -> str:
    return line.replace("\n", "\\l").replace('"', '\\"')


NODE_STYLE = f"shape=box fontname=Courier"


def to_dot(func: ida_funcs.func_t) -> str:
    nodes = []
    edges = []

    blocks = ida_gdl.FlowChart(func)
    for block in blocks:
        body = ""

        if label := ida_name.get_short_name(block.start_ea):
            body += label + ":\n"

        cur_ea = block.start_ea
        while cur_ea < block.end_ea:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, cur_ea)
            if not insn:
                print("Failed to decode instruction while making graph!")
                break

            line = ida_lines.generate_disasm_line(cur_ea)
            body += ida_lines.tag_remove(line) + "\n"

            cur_ea += insn_len

        nodes.append(
            f'  {_node_name(block)}[{NODE_STYLE} label="{_label_escape(body)}"];'
        )

        for next_block in block.succs():
            edges.append(f"  {_node_name(block)} -> {_node_name(next_block)};")

    return "\n".join(["digraph {"] + edges + [""] + nodes + ["}"])


class export_dot_handler_t(ida_kernwin.action_handler_t):
    dump_only: bool

    def __init__(self, dump_only: bool = False):
        ida_kernwin.action_handler_t.__init__(self)
        self.dump_only = dump_only

    def activate(self, ctx):  # pyright: ignore
        dot = to_dot(ctx.cur_func)
        if self.dump_only:
            print(dot)
            return 1

        path = ida_kernwin.ask_file(True, "graph.dot", "Save graph as DOT file")
        if path:
            with open(path, "w") as f:
                f.write(dot)

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE if ctx.cur_func else ida_kernwin.AST_DISABLE


class graphviz_ui_hooks_t(ida_kernwin.UI_Hooks):
    popup_actions = []

    def finish_populating_widget_popup(self, widget, popup):  # pyright: ignore
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            "graphviz:ProduceDOT",
            f"&Graphviz/",
            ida_kernwin.SETMENU_APP,
        )
        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            "graphviz:DumpDOT",
            f"&Graphviz/",
            ida_kernwin.SETMENU_APP,
        )


class graphviz_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_DRAW | ida_idaapi.PLUGIN_HIDE
    help = ""
    comment = "Graphviz exporter"
    wanted_name = "graphviz"
    wanted_hotkey = ""

    ui_hooks: graphviz_ui_hooks_t

    def init(self):
        self.ui_hooks = graphviz_ui_hooks_t()

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "graphviz:ProduceDOT",
                "~C~reate Graphviz DOT file...",
                export_dot_handler_t(False),
                None,
                "Export the current function's CFG as Graphviz DOT code",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "graphviz:DumpDOT",
                "~D~ump Graphviz DOT code",
                export_dot_handler_t(True),
                None,
                "Print the current function's CFG as Graphviz DOT code in the command line window",
            )
        )

        ida_kernwin.attach_action_to_menu(
            "File/Produce file/",
            "graphviz:ProduceDOT",
            ida_kernwin.SETMENU_APP | ida_kernwin.SETMENU_ENSURE_SEP,
        )

        self.ui_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self):  # pyright: ignore
        pass

    def term(self):
        self.ui_hooks.unhook()


def PLUGIN_ENTRY():
    return graphviz_plugin_t()
