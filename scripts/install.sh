#!/usr/bin/env bash
# install.sh — cài skill vbs-scan-security cho mọi platform có trên máy.
#
# Detection (auto):
#   - Claude Code        → binary `claude`               → ~/.claude/skills/vbs-scan-security
#   - OpenAI Codex CLI   → binary `codex`                → ~/.agents/skills/vbs-scan-security
#   - Google Antigravity → app /Applications/Antigravity.app
#                          HOẶC binary `agy`             → ~/.gemini/antigravity/skills/vbs-scan-security
#
# Antigravity là IDE (không phải CLI). Detection check app folder hoặc CLI tool `agy`
# (user tự install qua menu trong Antigravity IDE).
#
# Mặc định dùng symlink (sửa rule canonical → live update). Có flag --copy để copy thay symlink.
#
# Usage:
#   ./scripts/install.sh                       # auto-detect, symlink mode
#   ./scripts/install.sh --copy                # copy mode
#   ./scripts/install.sh --only=codex          # chỉ cài cho 1 platform (force, bỏ qua detection)
#   ./scripts/install.sh --only=antigravity    # ép cài Antigravity (kể cả khi chưa cài app)
#   ./scripts/install.sh --all                 # cài cho cả 3 platform (bỏ qua detection)
#   ./scripts/install.sh --dry-run             # in plan, không chạy

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="symlink"
ONLY=""
FORCE_ALL=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --copy)     MODE="copy" ;;
    --symlink)  MODE="symlink" ;;
    --only=*)   ONLY="${arg#--only=}" ;;
    --all)      FORCE_ALL=1 ;;
    --dry-run)  DRY_RUN=1 ;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

# Detection cho từng platform. Return 0 nếu detected, 1 nếu không.
detect_claude()       { command -v claude >/dev/null 2>&1; }
detect_codex()        { command -v codex >/dev/null 2>&1; }
detect_antigravity()  {
  # macOS standard install
  [ -d "/Applications/Antigravity.app" ] && return 0
  # CLI tool agy (user tự install qua menu Antigravity IDE)
  command -v agy >/dev/null 2>&1 && return 0
  return 1
}

# Map: short-key|platform-name|detect-function|source-folder|target-dir
platforms=(
  "claude|Claude Code|detect_claude|$ROOT/skills/vbs-scan-security|$HOME/.claude/skills/vbs-scan-security"
  "codex|OpenAI Codex|detect_codex|$ROOT/skills/codex/vbs-scan-security|$HOME/.agents/skills/vbs-scan-security"
  "antigravity|Google Antigravity|detect_antigravity|$ROOT/skills/antigravity/vbs-scan-security|$HOME/.gemini/antigravity/skills/vbs-scan-security"
)

installed=0
skipped=0

for entry in "${platforms[@]}"; do
  IFS='|' read -r short name detect_fn source target <<<"$entry"

  # Filter by --only
  if [ -n "$ONLY" ] && [ "$short" != "$ONLY" ]; then
    continue
  fi

  echo ""
  echo "─── $name ───"

  # Source must exist
  if [ ! -d "$source" ]; then
    echo "  ⏭  Source folder missing: $source"
    skipped=$((skipped+1))
    continue
  fi

  # Detection (unless --only or --all forces install regardless)
  if [ -z "$ONLY" ] && [ $FORCE_ALL -eq 0 ]; then
    if ! $detect_fn; then
      echo "  ⏭  $name không detect được — skipping."
      echo "      Force install: --only=$short hoặc --all"
      skipped=$((skipped+1))
      continue
    fi
  fi

  echo "  Source: $source"
  echo "  Target: $target"
  echo "  Mode:   $MODE"

  if [ $DRY_RUN -eq 1 ]; then
    echo "  [dry-run] would install"
    continue
  fi

  # Handle existing target
  if [ -L "$target" ]; then
    current=$(readlink "$target")
    if [ "$current" = "$source" ]; then
      echo "  ⏭  Already symlinked to correct source — skipping"
      skipped=$((skipped+1))
      continue
    fi
    backup_dir="$HOME/.vbsec-install-backups"
    mkdir -p "$backup_dir"
    backup="$backup_dir/$(basename "$target").backup-$(date +%Y%m%d-%H%M%S)"
    echo "  ⚠  Existing symlink points elsewhere — moving to $backup"
    mv "$target" "$backup"
  elif [ -e "$target" ]; then
    backup_dir="$HOME/.vbsec-install-backups"
    mkdir -p "$backup_dir"
    backup="$backup_dir/$(basename "$target").backup-$(date +%Y%m%d-%H%M%S)"
    echo "  ⚠  Existing folder found — moving to $backup"
    mv "$target" "$backup"
  fi

  # Ensure parent dir exists (Antigravity user mới chưa có ~/.gemini/antigravity/skills/)
  parent_dir=$(dirname "$target")
  if [ ! -d "$parent_dir" ]; then
    echo "  📁 Tạo parent dir: $parent_dir"
    mkdir -p "$parent_dir"
  fi

  # Install
  if [ "$MODE" = "symlink" ]; then
    ln -s "$source" "$target"
    echo "  ✅ Symlinked"
  else
    cp -R "$source" "$target"
    echo "  ✅ Copied"
  fi

  installed=$((installed+1))
done

echo ""
echo "═══════════════════════════════════════"
echo "  Installed: $installed"
echo "  Skipped:   $skipped"
echo "═══════════════════════════════════════"

if [ $installed -gt 0 ]; then
  echo ""
  echo "Test ngay:"
  detect_claude       && echo "  - Claude:      claude → gõ /vbs-scan-security"
  detect_codex        && echo "  - Codex:       codex → gõ \$vbs-scan-security  (hoặc /skills)"
  detect_antigravity  && echo "  - Antigravity: mở Antigravity app, nói 'scan security' trong Agent Manager"
fi

if [ $skipped -gt 0 ] && [ -z "$ONLY" ] && [ $FORCE_ALL -eq 0 ]; then
  echo ""
  echo "💡 Để force cài cho platform chưa detect: ./scripts/install.sh --only=<claude|codex|antigravity>"
  echo "   Hoặc cài cho cả 3:                    ./scripts/install.sh --all"
fi
