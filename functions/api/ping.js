export default {
  async fetch() {
    return new Response("API_PING_OK_V1", {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  },
};
