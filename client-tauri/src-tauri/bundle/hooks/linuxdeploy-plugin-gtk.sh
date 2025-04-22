#! /usr/bin/env bash
# src-tauri/bundle/hooks/linuxdeploy-plugin-gtk.sh

# （以下はデフォルトスクリプトの冒頭）
gsettings get org.gnome.desktop.interface gtk-theme 2>/dev/null | grep -qi "dark" && GTK_THEME_VARIANT="dark" || GTK_THEME_VARIANT="light"
APPIMAGE_GTK_THEME="${APPIMAGE_GTK_THEME:-"Adwaita:$GTK_THEME_VARIANT"}"
export APPDIR="${APPDIR:-"$(dirname "$(realpath "$0")")"}"

# ── ここから環境変数パス修正 ──
export GSETTINGS_SCHEMA_DIR="$APPDIR/usr/share/glib-2.0/schemas"
export GTK_PATH="$APPDIR/usr/lib/x86_64-linux-gnu/gtk-3.0"
# ── パス修正ここまで ──

# GLib スキーマを確実にコンパイル
if [ -d "$GSETTINGS_SCHEMA_DIR" ]; then
  glib-compile-schemas "$GSETTINGS_SCHEMA_DIR"
fi

# 以下は元のプラグイン処理…
