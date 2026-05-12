(function () {
  var BASE_PATH = "/live2d/luotianyi/";
  var MODEL_PATH = BASE_PATH + "model/tianyi/model.json";
  var SONGS_PATH = BASE_PATH + "songs.json";
  var POSITION_KEY = "hakilong:live2d-position";
  var HIDDEN_KEY = "hakilong:live2d-hidden";
  var MESSAGE_TIMEOUT = 5000;

  function ready(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback);
    } else {
      callback();
    }
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function randomItem(items) {
    return items[Math.floor(Math.random() * items.length)];
  }

  function safeJsonParse(value) {
    try {
      return JSON.parse(value);
    } catch (error) {
      return null;
    }
  }

  function getStorageItem(key) {
    try {
      return localStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  function setStorageItem(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (error) {
      console.debug("live2d storage write failed", error);
    }
  }

  ready(function () {
    var widget = document.querySelector("[data-live2d-widget]");
    var canvas = document.getElementById("hakilong-live2d-canvas");
    var message = document.querySelector("[data-live2d-message]");
    var hideButton = document.querySelector("[data-live2d-hide]");
    var restoreButton = document.querySelector("[data-live2d-restore]");
    var singButton = document.querySelector("[data-live2d-sing]");
    var hideTimer = null;
    var currentAudio = null;
    var songsPromise = null;
    var dragging = null;
    var suppressNextClick = false;

    if (!widget || !canvas) {
      return;
    }

    if (window.matchMedia && window.matchMedia("(max-width: 860px)").matches) {
      return;
    }

    function showMessage(text, timeout) {
      if (!message || !text) {
        return;
      }
      window.clearTimeout(hideTimer);
      message.textContent = text;
      message.classList.add("is-visible");
      hideTimer = window.setTimeout(function () {
        message.classList.remove("is-visible");
      }, timeout || MESSAGE_TIMEOUT);
    }

    function applySavedPosition() {
      var saved = safeJsonParse(getStorageItem(POSITION_KEY));
      if (!saved || typeof saved.left !== "number" || typeof saved.top !== "number") {
        return;
      }
      var maxLeft = Math.max(0, window.innerWidth - widget.offsetWidth);
      var maxTop = Math.max(0, window.innerHeight - widget.offsetHeight);
      widget.style.left = clamp(saved.left, 0, maxLeft) + "px";
      widget.style.top = clamp(saved.top, 0, maxTop) + "px";
      widget.style.right = "auto";
      widget.style.bottom = "auto";
    }

    function savePosition() {
      var rect = widget.getBoundingClientRect();
      setStorageItem(POSITION_KEY, JSON.stringify({
        left: Math.round(rect.left),
        top: Math.round(rect.top)
      }));
    }

    function setHidden(hidden) {
      widget.classList.toggle("is-hidden", hidden);
      if (restoreButton) {
        restoreButton.hidden = !hidden;
      }
      setStorageItem(HIDDEN_KEY, hidden ? "1" : "0");
    }

    function loadSongs() {
      if (!songsPromise) {
        songsPromise = fetch(SONGS_PATH)
          .then(function (response) {
            if (!response.ok) {
              throw new Error("songs fetch failed: " + response.status);
            }
            return response.json();
          })
          .then(function (songs) {
            return Array.isArray(songs) ? songs.filter(function (song) {
              return song && song.url;
            }) : [];
          });
      }
      return songsPromise;
    }

    function stopSong() {
      if (currentAudio) {
        currentAudio.pause();
        currentAudio.src = "";
        currentAudio = null;
      }
      if (singButton) {
        singButton.textContent = "Sing";
      }
    }

    function playRandomSong() {
      if (currentAudio) {
        stopSong();
        showMessage("\u5df2\u6682\u505c\u3002", 2200);
        return;
      }

      loadSongs()
        .then(function (songs) {
          if (!songs.length) {
            showMessage("\u6ca1\u6709\u627e\u5230\u53ef\u64ad\u653e\u7684\u6b4c\u66f2\u3002");
            return;
          }
          var song = randomItem(songs);
          currentAudio = new Audio(song.url);
          currentAudio.preload = "none";
          currentAudio.addEventListener("ended", stopSong, { once: true });
          currentAudio.addEventListener("error", function () {
            stopSong();
            showMessage("\u6b4c\u66f2\u94fe\u63a5\u6682\u65f6\u4e0d\u53ef\u7528\u3002");
          }, { once: true });
          var playResult = currentAudio.play();
          if (playResult && typeof playResult.then === "function") {
            playResult.catch(function () {
              stopSong();
              showMessage("\u6d4f\u89c8\u5668\u62e6\u622a\u4e86\u64ad\u653e\uff0c\u70b9\u4e00\u4e0b Sing \u518d\u8bd5\u3002");
            });
          }
          if (singButton) {
            singButton.textContent = "Pause";
          }
          showMessage("\u6b63\u5728\u64ad\u653e\uff1a" + (song.name || "\u6d1b\u5929\u4f9d"));
        })
        .catch(function () {
          showMessage("\u6b4c\u66f2\u5217\u8868\u52a0\u8f7d\u5931\u8d25\u3002");
        });
    }

    function startDrag(event) {
      if (event.button !== undefined && event.button !== 0) {
        return;
      }
      var target = event.target;
      if (target && target.closest && target.closest("button")) {
        return;
      }
      var rect = widget.getBoundingClientRect();
      dragging = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        left: rect.left,
        top: rect.top,
        moved: false
      };
      widget.classList.add("is-dragging");
      widget.setPointerCapture(event.pointerId);
    }

    function moveDrag(event) {
      if (!dragging || event.pointerId !== dragging.pointerId) {
        return;
      }
      var dx = event.clientX - dragging.startX;
      var dy = event.clientY - dragging.startY;
      if (Math.abs(dx) + Math.abs(dy) > 4) {
        dragging.moved = true;
      }
      var maxLeft = Math.max(0, window.innerWidth - widget.offsetWidth);
      var maxTop = Math.max(0, window.innerHeight - widget.offsetHeight);
      widget.style.left = clamp(dragging.left + dx, 0, maxLeft) + "px";
      widget.style.top = clamp(dragging.top + dy, 0, maxTop) + "px";
      widget.style.right = "auto";
      widget.style.bottom = "auto";
      event.preventDefault();
    }

    function endDrag(event) {
      if (!dragging || event.pointerId !== dragging.pointerId) {
        return;
      }
      var wasMoved = dragging.moved;
      dragging = null;
      widget.classList.remove("is-dragging");
      try {
        widget.releasePointerCapture(event.pointerId);
      } catch (error) {
      }
      if (wasMoved) {
        savePosition();
        suppressNextClick = true;
        window.setTimeout(function () {
          suppressNextClick = false;
        }, 160);
      }
    }

    applySavedPosition();

    if (getStorageItem(HIDDEN_KEY) === "1") {
      setHidden(true);
    }

    if (typeof window.loadlive2d === "function") {
      try {
        window.loadlive2d("hakilong-live2d-canvas", MODEL_PATH);
      } catch (error) {
        console.error("Live2D load failed", error);
      }
    } else {
      console.error("Live2D loader is unavailable");
    }

    showMessage("\u6d1b\u5929\u4f9d\u5df2\u4e0a\u7ebf\uff0c\u53ef\u4ee5\u62d6\u52a8\u6211\u3002", 4200);

    canvas.addEventListener("pointerdown", startDrag);
    window.addEventListener("pointermove", moveDrag);
    window.addEventListener("pointerup", endDrag);
    window.addEventListener("pointercancel", endDrag);
    window.addEventListener("resize", applySavedPosition);

    canvas.addEventListener("click", function () {
      if (suppressNextClick) {
        suppressNextClick = false;
        return;
      }
      showMessage(randomItem([
        "\u60f3\u542c\u6211\u5531\u6b4c\u5417\uff1f",
        "\u4e0d\u8981\u52a8\u624b\u52a8\u811a\u7684\u3002",
        "\u4eca\u5929\u4e5f\u8981\u597d\u597d\u5199\u535a\u5ba2\u3002"
      ]));
    });

    if (hideButton) {
      hideButton.addEventListener("click", function () {
        setHidden(true);
        stopSong();
      });
    }

    if (restoreButton) {
      restoreButton.addEventListener("click", function () {
        setHidden(false);
        showMessage("\u6211\u56de\u6765\u4e86\u3002", 3000);
      });
    }

    if (singButton) {
      singButton.addEventListener("click", playRandomSong);
    }
  });
})();
