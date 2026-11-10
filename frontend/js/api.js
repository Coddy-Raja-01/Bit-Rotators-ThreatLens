(() => {
  const apiBase = String(window.THREATLENS_API_BASE_URL || "").replace(/\/+$/, "");

  window.apiFetch = (path, options = {}) => {
    const url = /^https?:\/\//i.test(path) ? path : `${apiBase}${path}`;
    return window.fetch(url, { credentials: "include", ...options });
  };
})();
