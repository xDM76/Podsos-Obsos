#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — IDE & Desktop JS Patcher
=============================================================================
  Патчинг JavaScript-файлов оболочки Electron для Antigravity IDE и Desktop
  (порт из confeden/Antigravity: patch_ide.rs).
=============================================================================
"""

import os
import re
import shutil

JS_BAK = ".ag_backup"
MARKER_PREFIX = "// UNLOCKED_PODSOS_OBSOS"

def backup_file(path: str):
    bak = path + JS_BAK
    if not os.path.exists(bak):
        try:
            shutil.copy2(path, bak)
        except Exception as e:
            print(f"Внимание: не удалось создать бэкап {bak}: {e}")

def restore_file(path: str) -> bool:
    bak = path + JS_BAK
    if os.path.exists(bak):
        try:
            shutil.copy2(bak, path)
            os.remove(bak)
            return True
        except Exception:
            pass
    return False

def patch_ide_main_js(main_js_path: str) -> bool:
    """Патчит main.js в Antigravity IDE (VSCode-based fork)."""
    if not os.path.isfile(main_js_path):
        return False
    try:
        with open(main_js_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if MARKER_PREFIX in content:
            return True

        pattern = (
            r'async\s+([A-Za-z_$0-9]+)\(([A-Za-z_$0-9]+)\)\s*\{\s*'
            r'if\(this\.([A-Za-z_$0-9]+)\.send\(\{type:[A-Za-z_$0-9]+\.isGcpTos\?"GCP_SIGN_IN":"SIGN_IN"\}\),'
            r'this\.([A-Za-z_$0-9]+)\.resetIsTierGCPTos\(\),this\.[A-Za-z_$0-9]+\.isGoogleInternal\)\{'
            r'try\{await this\.([A-Za-z_$0-9]+)\.loadCodeAssist\([A-Za-z_$0-9]+\);'
            r'const\{settings:([A-Za-z_$0-9]+),userTier:([A-Za-z_$0-9]+)\}=await this\.refreshUserStatus\([A-Za-z_$0-9]+\),'
            r'([A-Za-z_$0-9]+)=([A-Za-z_$0-9]+)\([A-Za-z_$0-9]+\);'
            r'this\.([A-Za-z_$0-9]+)\.pushUpdate\([A-Za-z_$0-9]+\),'
            r'this\.[A-Za-z_$0-9]+\.send\(\{type:"AUTH_SUCCESS",tokenInfo:[A-Za-z_$0-9]+\}\),'
            r'this\.([A-Za-z_$0-9]+)\.fire\(\{settings:[A-Za-z_$0-9]+,userTier:[A-Za-z_$0-9]+\}\)\}'
            r'catch\(([A-Za-z_$0-9]+)\)\{.*?(?:return\}|return;\s*\})'
        )
        match = re.search(pattern, content)
        if match:
            fname = match.group(1)
            var_t = match.group(2)
            var_t_send = match.group(3)
            var_y = match.group(4)
            var_func = match.group(9)
            var_f = match.group(10)
            var_h = match.group(11)
            var_i = match.group(8)

            payload = (
                f"async {fname}({var_t}){{\n"
                f"    this.{var_t_send}.send({{type:{var_t}.isGcpTos?\"GCP_SIGN_IN\":\"SIGN_IN\"}});\n"
                f"    this.{var_y}.resetIsTierGCPTos();\n"
                f"    try {{\n"
                f"        try {{ await this.{var_y}.loadCodeAssist({var_t}); }} catch(_) {{}}\n"
                f"        try {{ await this.{var_y}.onboardUser(\"standard-tier\", {var_t}); }} catch(_) {{\n"
                f"            try {{ await this.{var_y}.onboardUser(\"free-tier\", {var_t}); }} catch(__) {{}}\n"
                f"        }}\n"
                f"        let __res = {{ settings: {{}}, userTier: {{ id: \"pro\", description: \"Pro\" }} }};\n"
                f"        try {{ __res = await this.refreshUserStatus({var_t}); }} catch(_) {{}}\n"
                f"        const {var_i} = {var_func}({var_t});\n"
                f"        try {{ this.{var_f}.pushUpdate({var_i}); }} catch(_) {{}}\n"
                f"        this.{var_t_send}.send({{type:\"AUTH_SUCCESS\",tokenInfo:{var_t}}});\n"
                f"        this.{var_h}.fire({{settings:__res.settings, userTier:__res.userTier}});\n"
                f"    }} catch(e) {{}}\n"
                f"    return;\n"
            )

            new_content = content[:match.start()] + payload + content[match.end():] + f"\n{MARKER_PREFIX}\n"
            backup_file(main_js_path)
            with open(main_js_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            return True
    except Exception:
        pass
    return False
