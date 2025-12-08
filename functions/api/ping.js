export default {
  async fetch() {
    return new Response(
      "API_PING_OK__" + new Date().toISOString(),
      {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store, no-cache, max-age=0",
        },
      }
    );
  },
};
