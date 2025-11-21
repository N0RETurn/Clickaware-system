import os
import shutil

# Locate your venv site-packages
site_packages = r"C:\Users\ikipyegon\Desktop\Clickaware-extension\.venv\Lib\site-packages"
base_py = os.path.join(site_packages, "flask_admin", "base.py")
backup_py = os.path.join(site_packages, "flask_admin", "base.py.bak")

# Check file exists
if not os.path.isfile(base_py):
    print(f"❌ Could not find {base_py}. Please check the path.")
    exit(1)

# Backup first
shutil.copy2(base_py, backup_py)
print(f"🗄️ Backup created at {backup_py}")

# Read file
with open(base_py, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Attempt to patch
changed = False
for i, line in enumerate(lines):
    if "return fn(cls=self, **kwargs)" in line:
        print(f"🔧 Found line {i+1}: {line.strip()}")
        lines[i] = line.replace("return fn(cls=self, **kwargs)", "return fn(*args, **kwargs)")
        changed = True

if changed:
    # Write back
    with open(base_py, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print("✅ Successfully patched flask_admin/base.py to remove 'cls' argument.")
else:
    print("⚠️ No changes made. The target line was not found. It may already be patched.")
