"""Compile all .py files in the repo and exit non-zero on failures."""
import py_compile, os, sys
errs = []
for root, _, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            p = os.path.join(root, f)
            try:
                py_compile.compile(p, doraise=True)
            except Exception as e:
                print('COMPILE_ERROR', p, e)
                errs.append(p)
if errs:
    print('COMPILE_FAILED', len(errs))
    sys.exit(1)
print('COMPILE_OK')
