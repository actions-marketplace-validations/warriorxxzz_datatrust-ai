import os
import importlib.util

def load_custom_plugins():
    plugins = []
    plugin_dir = "datatrust_plugins"
    
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir)
        return plugins

    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and filename != "__init__.py":
            filepath = os.path.join(plugin_dir, filename)
            try:
                spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "scan_line"):
                    plugins.append(module)
            except Exception:
                pass
    return plugins
