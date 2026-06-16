#!/usr/bin/env bash
# Post-process DMG to hide .VolumeIcon.icns
DMG="$1"
if [ -z "$DMG" ]; then
  DMG="$(find target/debug/bundle/dmg -name '*.dmg' | head -1)"
fi
[ -z "$DMG" ] && exit 0

# Mount, hide the icon, unmount
MOUNT_DIR=$(mktemp -d)
hdiutil attach "$DMG" -mountpoint "$MOUNT_DIR" -nobrowse -quiet 2>/dev/null
if [ -f "$MOUNT_DIR/.VolumeIcon.icns" ]; then
  SetFile -a V "$MOUNT_DIR/.VolumeIcon.icns" 2>/dev/null
  echo "Hidden .VolumeIcon.icns"
fi
hdiutil detach "$MOUNT_DIR" -quiet 2>/dev/null
rmdir "$MOUNT_DIR" 2>/dev/null
