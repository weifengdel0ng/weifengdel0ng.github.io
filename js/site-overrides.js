(function () {
  var STORAGE_KEY = "hakilong:panel-opacity";
  var DEFAULT_OPACITY = 0.88;

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

  document.addEventListener("DOMContentLoaded", function () {
    var opacity = applyOpacity(loadOpacity());
    syncControl(opacity);

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
