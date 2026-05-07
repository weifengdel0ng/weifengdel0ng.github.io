(function () {
  var STORAGE_KEY = "hakilong:panel-opacity";
  var DEFAULT_OPACITY = 0.88;
  var EASTER_EGG_STORAGE_KEY = "hakilong:jump-bottom-reaches";
  var EASTER_EGG_UNLOCK_COUNT = 5;

  function clampOpacity(value) {
    var numeric = parseFloat(value);
    if (!isFinite(numeric)) {
      numeric = DEFAULT_OPACITY;
    }
    return Math.max(0.35, Math.min(1, numeric));
  }

  function applyOpacity(value) {
    var opacity = clampOpacity(value);
    document.documentElement.style.setProperty("--site-panel-opacity", opacity.toFixed(2));
    document.documentElement.style.setProperty("--site-panel-soft-opacity", Math.min(opacity + 0.04, 1).toFixed(2));
    return opacity;
  }

  function syncControl(opacity) {
    var slider = document.querySelector("[data-panel-opacity-slider]");
    var value = document.querySelector("[data-panel-opacity-value]");
    if (slider) {
      slider.value = String(Math.round(opacity * 100));
    }
    if (value) {
      value.textContent = Math.round(opacity * 100) + "%";
    }
  }

  function loadOpacity() {
    try {
      return clampOpacity(localStorage.getItem(STORAGE_KEY) || DEFAULT_OPACITY);
    } catch (error) {
      console.debug("panel opacity load failed", error);
      return DEFAULT_OPACITY;
    }
  }

  function saveOpacity(opacity) {
    try {
      localStorage.setItem(STORAGE_KEY, opacity.toFixed(2));
    } catch (error) {
      console.debug("panel opacity save failed", error);
    }
  }

  function isHomepage() {
    var path = window.location.pathname || "/";
    return path === "/" || path === "/index.html";
  }

  function loadBottomReachCount() {
    try {
      var value = parseInt(localStorage.getItem(EASTER_EGG_STORAGE_KEY) || "0", 10);
      return Number.isFinite(value) ? Math.max(0, value) : 0;
    } catch (error) {
      console.debug("bottom reach count load failed", error);
      return 0;
    }
  }

  function saveBottomReachCount(count) {
    try {
      localStorage.setItem(EASTER_EGG_STORAGE_KEY, String(Math.max(0, count)));
    } catch (error) {
      console.debug("bottom reach count save failed", error);
    }
  }

  function bindBottomEasterEgg() {
    if (!isHomepage()) {
      return;
    }

    var container = document.querySelector("[data-bottom-easter-egg]");
    if (!container) {
      return;
    }

    var count = loadBottomReachCount();
    var atBottom = false;

    function syncState() {
      if (count > 0) {
        container.classList.add("is-hint-visible");
      }
      if (count >= EASTER_EGG_UNLOCK_COUNT) {
        container.classList.add("is-card-visible");
      }
    }

    function detectBottom() {
      var doc = document.documentElement;
      var threshold = 8;
      var reachedBottom = window.innerHeight + window.scrollY >= doc.scrollHeight - threshold;

      if (reachedBottom && !atBottom) {
        atBottom = true;
        count += 1;
        saveBottomReachCount(count);
        syncState();
      } else if (!reachedBottom) {
        atBottom = false;
      }
    }

    syncState();
    detectBottom();
    window.addEventListener("scroll", detectBottom, { passive: true });
    window.addEventListener("resize", detectBottom);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var opacity = applyOpacity(loadOpacity());
    syncControl(opacity);
    bindBottomEasterEgg();

    var slider = document.querySelector("[data-panel-opacity-slider]");
    if (!slider) {
      return;
    }

    slider.addEventListener("input", function (event) {
      var nextOpacity = applyOpacity(event.target.value / 100);
      syncControl(nextOpacity);
    });

    slider.addEventListener("change", function (event) {
      var nextOpacity = applyOpacity(event.target.value / 100);
      syncControl(nextOpacity);
      saveOpacity(nextOpacity);
    });
  });
})();
