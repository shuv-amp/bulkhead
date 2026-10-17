#!/bin/sh
# Rebuild the README figures in docs/assets at 2x, transparent, light and dark.
# Needs python3 and a Chromium-based browser (set BROWSER=/path/to/chrome).
set -e
D=$(cd "$(dirname "$0")" && pwd)
B=${BROWSER:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
mkdir -p "$D/fonts"
for f in inter-tight:500 inter-tight:600 inter:400 inter:500 inter:600 jetbrains-mono:400 jetbrains-mono:500; do
  n=${f%%:*}; w=${f##*:}
  [ -f "$D/fonts/$n-$w.woff2" ] || curl -sfL -o "$D/fonts/$n-$w.woff2" \
    "https://cdn.jsdelivr.net/fontsource/fonts/$n@5.2.5/latin-$w-normal.woff2"
done
python3 -I "$D/figures.py" | while read -r name theme w h; do
  "$B" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --default-background-color=00000000 --window-size="$w,$h" \
    --screenshot="$D/../$name-$theme.png" "file://$D/html/$name-$theme.html" >/dev/null 2>&1
  echo "docs/assets/$name-$theme.png"
done

# Fig. 3 animated: every frame rendered (one browser launch each, ~10 min), then one GIF per theme, the end held 3 s.
python3 -I "$D/figures.py" frames | while read -r name theme w h n; do
  mkdir -p "$D/html/png-$theme"
  for f in "$D/html/attack-$theme"/*.html; do
    "$B" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 --window-size="$w,$h" \
      --screenshot="$D/html/png-$theme/$(basename "$f" .html).png" "file://$f" </dev/null >/dev/null 2>&1
  done
  ffmpeg -loglevel error -y -framerate 12 -i "$D/html/png-$theme/%04d.png" \
    -vf "tpad=stop_mode=clone:stop_duration=3,split[a][b];[a]palettegen=max_colors=64:stats_mode=full[p];[b][p]paletteuse=dither=none" \
    "$D/../attack-$theme.gif"
  echo "docs/assets/attack-$theme.gif"
done
