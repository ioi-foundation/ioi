import crypto from "node:crypto";
import http from "node:http";

export async function startFakeNativeBrowserCdpServer() {
  const state = {
    url: "https://example.test/",
    title: "Fake CDP",
    clicks: [],
    typed: [],
    keys: [],
    scrolls: [],
  };
  const sockets = new Set();
  const server = http.createServer((request, response) => {
    if (request.url === "/json/version") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        Browser: "FakeCDP/1.0",
        "Protocol-Version": "1.3",
        webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/page/fake`,
      }));
      return;
    }
    response.writeHead(404);
    response.end("not found");
  });

  server.on("upgrade", (request, socket) => {
    const key = request.headers["sec-websocket-key"];
    const accept = crypto
      .createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${accept}`,
      "\r\n",
    ].join("\r\n"));
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("data", (chunk) => {
      for (const frame of decodeClientFrames(chunk)) {
        const command = JSON.parse(frame);
        handleFakeCdpCommand({ command, socket, state });
      }
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    endpointUrl: `http://127.0.0.1:${server.address().port}`,
    state,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function handleFakeCdpCommand({ command, socket, state }) {
  if (command.method === "Page.enable" || command.method === "Runtime.enable") {
    sendServerFrame(socket, { id: command.id, result: {} });
    return;
  }
  if (command.method === "Page.navigate") {
    state.url = command.params?.url ?? state.url;
    state.title = "Navigated";
    sendServerFrame(socket, { id: command.id, result: { frameId: "frame-1" } });
    sendServerFrame(socket, { method: "Page.loadEventFired", params: { timestamp: 1 } });
    return;
  }
  if (command.method === "Input.dispatchKeyEvent") {
    if (command.params?.type === "keyDown") {
      state.keys.push({
        key: command.params?.key ?? "",
        code: command.params?.code ?? "",
        text: command.params?.text ?? "",
      });
    }
    sendServerFrame(socket, { id: command.id, result: {} });
    return;
  }
  if (command.method === "Runtime.evaluate") {
    const expression = String(command.params?.expression ?? "");
    if (expression.includes("document.querySelector") && expression.includes("const text =")) {
      const selector = expression.match(/const selector = "([^"]+)"/)?.[1] ?? "#input";
      const text = expression.match(/const text = "([^"]*)"/)?.[1] ?? "";
      state.typed.push({ selector, text });
      sendServerFrame(socket, {
        id: command.id,
        result: {
          result: {
            type: "object",
            value: {
              typed: true,
              selector,
              tag: "INPUT",
              id: selector.replace(/^#/, ""),
              previous_value_length: 0,
              text_length: text.length,
              bounds: { x: 20, y: 30, width: 200, height: 36 },
            },
          },
        },
      });
      return;
    }
    if (expression.includes("const deltaY =")) {
      const selector = expression.match(/const selector = ([^;]+);/)?.[1] ?? "null";
      const deltaX = Number(expression.match(/const deltaX = (-?\d+(?:\.\d+)?);/)?.[1] ?? 0);
      const deltaY = Number(expression.match(/const deltaY = (-?\d+(?:\.\d+)?);/)?.[1] ?? 0);
      const selectorValue = selector === "null" ? null : selector.replace(/^"|"$/g, "");
      state.scrolls.push({ selector: selectorValue, deltaX, deltaY });
      sendServerFrame(socket, {
        id: command.id,
        result: {
          result: {
            type: "object",
            value: {
              scrolled: true,
              selector: selectorValue,
              target: selectorValue ? "element" : "window",
              delta_x: deltaX,
              delta_y: deltaY,
              before: { x: 0, y: 0 },
              after: { x: deltaX, y: deltaY },
            },
          },
        },
      });
      return;
    }
    if (expression.includes("document.querySelector")) {
      const selector = expression.match(/const selector = "([^"]+)"/)?.[1] ?? "#submit";
      state.clicks.push(selector);
      sendServerFrame(socket, {
        id: command.id,
        result: {
          result: {
            type: "object",
            value: {
              clicked: true,
              selector,
              tag: "BUTTON",
              id: selector.replace(/^#/, ""),
              label: "Submit",
              bounds: { x: 10, y: 20, width: 120, height: 32 },
            },
          },
        },
      });
      return;
    }
    sendServerFrame(socket, {
      id: command.id,
      result: {
        result: {
          type: "object",
          value: {
            url: state.url,
            title: state.title,
            text: state.typed.length > 0
              ? `Typed ${state.typed.at(-1).text}`
              : state.keys.length > 0
                ? `Pressed ${state.keys.at(-1).key}`
                : state.scrolls.length > 0
                  ? `Scrolled ${state.scrolls.at(-1).deltaY}`
                  : state.clicks.length > 0 ? "Clicked" : "Ready",
            html: `<html><head><title>${state.title}</title></head><body><input id="input"><button id="submit">Submit</button></body></html>`,
          },
        },
      },
    });
    return;
  }
  sendServerFrame(socket, { id: command.id, result: {} });
}

function decodeClientFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const first = buffer[offset++];
    const second = buffer[offset++];
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    if (length === 126) {
      length = buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      length = Number(buffer.readBigUInt64BE(offset));
      offset += 8;
    }
    const mask = masked ? buffer.subarray(offset, offset + 4) : null;
    if (masked) offset += 4;
    const payload = Buffer.from(buffer.subarray(offset, offset + length));
    offset += length;
    if (opcode === 0x8) continue;
    if (mask) {
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    frames.push(payload.toString("utf8"));
  }
  return frames;
}

function sendServerFrame(socket, message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x81, payload.length]);
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  socket.write(Buffer.concat([header, payload]));
}
