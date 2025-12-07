import importlib.util, sys, traceback
try:
    spec = importlib.util.spec_from_file_location('log_adapter_mod', 'log_adapter.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    print('Imported OK')
except Exception:
    traceback.print_exc()
    sys.exit(2)
