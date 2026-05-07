(function () {
  function noop() {}

  if (!window.wx) {
    window.wx = {
      config: noop,
      ready: function (callback) {
        if (typeof callback === "function") {
          callback();
        }
      },
      error: noop,
      onMenuShareTimeline: noop,
      onMenuShareAppMessage: noop,
      updateAppMessageShareData: noop,
      updateTimelineShareData: noop
    };
  }

  function hideLoading() {
    var loading = document.getElementById("loading");
    if (loading) {
      loading.style.display = "none";
    }
  }

  function applyPatch() {
    if (window.Data) {
      window.Data.DomainUrl = "/games/jump";
      if (typeof window.Data.IsFilinInfo === "undefined") {
        window.Data.IsFilinInfo = true;
      }
      if (typeof window.Data.LuckyNumber === "undefined") {
        window.Data.LuckyNumber = 0;
      }
    }

    if (window.WeixinUtil && window.WeixinUtil.prototype) {
      window.WeixinUtil.prototype.initWeixinInfo = noop;
    }

    if (window.Main && window.Main.prototype) {
      window.Main.prototype.sharefun = noop;
    }

    if (window.GameMian && window.GameMian.prototype) {
      window.GameMian.prototype.requestUserinfo = function () {
        if (window.Data) {
          window.Data.IsFilinInfo = true;
          window.Data.LuckyNumber = 0;
        }
        hideLoading();
      };
    }

    if (window.MyLucky && window.MyLucky.prototype) {
      window.MyLucky.prototype.GameLuckingFun = function () {
        hideLoading();
        if (this && Array.isArray(this.nowlist)) {
          this.nowlist.length = 0;
        }
      };
    }

    return !!(window.Data && window.Main && window.GameMian && window.MyLucky);
  }

  var attempts = 0;
  var timer = window.setInterval(function () {
    attempts += 1;
    if (applyPatch() || attempts > 80) {
      window.clearInterval(timer);
      hideLoading();
    }
  }, 150);
})();
