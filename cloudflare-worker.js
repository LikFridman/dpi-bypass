// Cloudflare Worker для dpi-bypass: пересылает WebSocket Telegram через сеть Cloudflare.
// Нужен, если у провайдера заблокированы IP-адреса Telegram.
//
// Как развернуть (бесплатно):
//   1. dash.cloudflare.com -> Workers & Pages -> Create -> Worker -> Deploy
//   2. Edit code -> заменить весь код этим файлом -> Deploy
//   3. Скопировать адрес вида  имя.аккаунт.workers.dev
//   4. Записать его одной строкой в  dpi-bypass-data\telegram-worker.txt  и перезапустить dpi-bypass.exe

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.headers.get("Upgrade") !== "websocket" || url.pathname !== "/apiws") {
      return new Response("dpi-bypass worker: ok", { status: 200 });
    }

    const dc = parseInt(url.searchParams.get("dc") || "2", 10);
    if (!(dc >= 1 && dc <= 5)) {
      return new Response("bad dc", { status: 400 });
    }
    const media = url.searchParams.get("media") === "1";
    const test = url.searchParams.get("test") === "1";
    const host = media ? `kws${dc}-1.web.telegram.org` : `kws${dc}.web.telegram.org`;
    const path = test ? "/apiws_test" : "/apiws";

    let upstream;
    try {
      const resp = await fetch(`https://${host}${path}`, {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "binary" },
      });
      upstream = resp.webSocket;
      if (!upstream && media) {
        // у некоторых DC нет отдельного медиа-сервера
        const r2 = await fetch(`https://kws${dc}.web.telegram.org${path}`, {
          headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "binary" },
        });
        upstream = r2.webSocket;
      }
    } catch (e) {
      return new Response("upstream error", { status: 502 });
    }
    if (!upstream) {
      return new Response("upstream refused", { status: 502 });
    }
    upstream.accept();

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    server.addEventListener("message", (e) => {
      try { upstream.send(e.data); } catch (_) { server.close(1011, "upstream"); }
    });
    upstream.addEventListener("message", (e) => {
      try { server.send(e.data); } catch (_) { upstream.close(1011, "client"); }
    });
    const closeBoth = () => {
      try { server.close(1000, "bye"); } catch (_) {}
      try { upstream.close(1000, "bye"); } catch (_) {}
    };
    server.addEventListener("close", closeBoth);
    upstream.addEventListener("close", closeBoth);
    server.addEventListener("error", closeBoth);
    upstream.addEventListener("error", closeBoth);

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "binary" },
    });
  },
};
