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
    var currentSong = null;
    var songList = [];
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
            songList = Array.isArray(songs) ? songs.filter(function (song) {
              return song && song.url;
            }) : [];
            return songList;
          })
          .catch(function () {
            songList = [];
            return songList;
          });
      }
      return songsPromise;
    }

    function stopSong() {
      if (currentSong) {
        currentSong.stop();
        currentSong = null;
      }
      if (singButton) {
        singButton.textContent = "Sing";
      }
    }

    function playLocalMelody(songName) {
      var AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) {
        showMessage("\u5f53\u524d\u6d4f\u89c8\u5668\u4e0d\u652f\u6301 WebAudio\u3002");
        return;
      }

      var context = new AudioContext();
      var masterGain = context.createGain();
      var notes = [
        [392, 0.22],
        [440, 0.22],
        [494, 0.28],
        [587, 0.34],
        [523, 0.22],
        [494, 0.22],
        [440, 0.32],
        [392, 0.28],
        [330, 0.22],
        [392, 0.22],
        [440, 0.28],
        [494, 0.42],
        [440, 0.24],
        [392, 0.24],
        [330, 0.46]
      ];
      var startAt = context.currentTime + 0.03;
      var cursor = startAt;
      var oscillators = [];

      masterGain.gain.setValueAtTime(0.0001, context.currentTime);
      masterGain.gain.exponentialRampToValueAtTime(0.13, context.currentTime + 0.04);
      masterGain.connect(context.destination);

      notes.forEach(function (note, index) {
        var frequency = note[0];
        var duration = note[1];
        var oscillator = context.createOscillator();
        var noteGain = context.createGain();
        var endAt = cursor + duration;

        oscillator.type = index % 3 === 0 ? "sine" : "triangle";
        oscillator.frequency.setValueAtTime(frequency, cursor);
        noteGain.gain.setValueAtTime(0.0001, cursor);
        noteGain.gain.exponentialRampToValueAtTime(0.95, cursor + 0.015);
        noteGain.gain.exponentialRampToValueAtTime(0.0001, Math.max(cursor + 0.02, endAt - 0.035));
        oscillator.connect(noteGain);
        noteGain.connect(masterGain);
        oscillator.start(cursor);
        oscillator.stop(endAt);
        oscillators.push(oscillator);
        cursor = endAt + 0.035;
      });

      var songHandle = {
        stop: function () {
          oscillators.forEach(function (oscillator) {
            try {
              oscillator.stop();
            } catch (error) {
            }
          });
          masterGain.gain.cancelScheduledValues(context.currentTime);
          masterGain.gain.setTargetAtTime(0.0001, context.currentTime, 0.025);
          window.setTimeout(function () {
            context.close().catch(function () {
            });
          }, 120);
        }
      };
      currentSong = songHandle;

      context.resume()
        .then(function () {
          if (singButton) {
            singButton.textContent = "Pause";
          }
          showMessage("\u6b63\u5728\u64ad\u653e\uff1a" + songName);
          window.setTimeout(function () {
            if (currentSong === songHandle) {
              stopSong();
            }
          }, Math.max(1200, Math.round((cursor - context.currentTime) * 1000) + 120));
        })
        .catch(function () {
          stopSong();
          showMessage("\u64ad\u653e\u5931\u8d25\uff0c\u8bf7\u518d\u70b9\u4e00\u4e0b Sing\u3002");
        });
    }

    function playRandomSong() {
      if (currentSong) {
        stopSong();
        showMessage("\u5df2\u6682\u505c\u3002", 2200);
        return;
      }

      var song = songList.length ? randomItem(songList) : null;
      playLocalMelody((song && song.name) || "\u6d1b\u5929\u4f9d\u7535\u5b50\u5c0f\u8c03");
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
    loadSongs();

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
