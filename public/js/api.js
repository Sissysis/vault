(function () {
  window.API = {
    async request(path, options) {
      options = options || {};
      const res = await fetch(path, {
        method: options.method || "GET",
        headers: Object.assign(
          { "Content-Type": "application/json" },
          options.headers || {}
        ),
        body: options.body,
        credentials: "same-origin",
      });
      let data = null;
      try {
        data = await res.json();
      } catch (e) {
        data = null;
      }
      return { status: res.status, data };
    },
  };
})();