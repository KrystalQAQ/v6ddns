// Runs before the stylesheet paints so a pinned theme never flashes light.
// The CSS maps this meta tag onto `color-scheme`, and light-dark() follows it.
(() => {
  "use strict";
  const KEY = "v6ddns-theme";
  let mode = "system";
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark" || stored === "system") mode = stored;
  } catch {
    /* storage can be unavailable; system is a fine default */
  }
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    meta.setAttribute("content", mode === "light" ? "light" : mode === "dark" ? "dark" : "light dark");
  }
  document.documentElement.dataset.theme = mode;
})();
