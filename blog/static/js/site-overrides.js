(function () {
  var STORAGE_KEY = "hakilong:panel-opacity";
  var DEFAULT_OPACITY = 0.88;
  var EASTER_EGG_STORAGE_KEY = "hakilong:jump-click-count";
  var EASTER_EGG_INITIAL_COUNT = 10;

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

  function loadEasterEggCount() {
    try {
      var value = parseInt(localStorage.getItem(EASTER_EGG_STORAGE_KEY) || String(EASTER_EGG_INITIAL_COUNT), 10);
      return Number.isFinite(value) ? Math.max(0, Math.min(EASTER_EGG_INITIAL_COUNT, value)) : EASTER_EGG_INITIAL_COUNT;
    } catch (error) {
      console.debug("easter egg count load failed", error);
      return EASTER_EGG_INITIAL_COUNT;
    }
  }

  function saveEasterEggCount(count) {
    try {
      localStorage.setItem(EASTER_EGG_STORAGE_KEY, String(Math.max(0, count)));
    } catch (error) {
      console.debug("easter egg count save failed", error);
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

    var hint = container.querySelector("[data-bottom-easter-hint]");
    var card = container.querySelector("[data-bottom-easter-card]");
    var count = loadEasterEggCount();

    function render() {
      container.classList.add("is-hint-visible");
      if (hint) {
        hint.textContent = count > 0 ? "\u518d\u70b9" + count + "\u6b21\u5c31\u8981\u70b8\u4e86" : "\u53ef\u4ee5\u8fdb\u5165\u5c0f\u6e38\u620f";
      }

      if (count <= 0) {
        container.classList.add("is-card-visible");
        if (hint) {
          hint.hidden = true;
        }
        if (card) {
          card.hidden = false;
        }
      } else {
        container.classList.remove("is-card-visible");
        if (hint) {
          hint.hidden = false;
        }
        if (card) {
          card.hidden = true;
        }
      }
    }

    if (hint) {
      hint.addEventListener("click", function () {
        if (count <= 0) {
          return;
        }
        count -= 1;
        saveEasterEggCount(count);
        render();
      });
    }

    if (card) {
      card.addEventListener("click", function () {
        count = 0;
        saveEasterEggCount(count);
        render();
      });
    }

    if (count < 0 || count > EASTER_EGG_INITIAL_COUNT) {
      count = EASTER_EGG_INITIAL_COUNT;
      saveEasterEggCount(count);
    }

    render();
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

