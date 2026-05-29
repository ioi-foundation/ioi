import childProcess from "node:child_process";
import crypto from "node:crypto";
import http from "node:http";

async function startFakeOpenAiCompatibleServer({ responsesStream = false } = {}) {
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "qwen/qwen3.5-9b" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (responsesStream && body.stream === true) {
        response.setHeader("content-type", "text/event-stream");
        const responseId = "resp_fake_openai_compatible_stream";
        const itemId = "msg_fake_openai_compatible_stream";
        response.write(
          `event: response.created\ndata: ${JSON.stringify({
            type: "response.created",
            response: {
              id: responseId,
              object: "response",
              status: "in_progress",
              model: body.model ?? "qwen/qwen3.5-9b",
              output: [],
            },
          })}\n\n`,
        );
        response.write(
          `event: response.output_item.added\ndata: ${JSON.stringify({
            type: "response.output_item.added",
            output_index: 0,
            item: { id: itemId, type: "message", status: "in_progress", role: "assistant", content: [] },
          })}\n\n`,
        );
        response.write(
          `event: response.output_text.delta\ndata: ${JSON.stringify({
            type: "response.output_text.delta",
            item_id: itemId,
            output_index: 0,
            content_index: 0,
            delta: "fake openai-compatible ",
          })}\n\n`,
        );
        response.write(
          `event: response.output_text.delta\ndata: ${JSON.stringify({
            type: "response.output_text.delta",
            item_id: itemId,
            output_index: 0,
            content_index: 0,
            delta: "streamed response",
          })}\n\n`,
        );
        response.end(
          `event: response.completed\ndata: ${JSON.stringify({
            type: "response.completed",
            response: {
              id: responseId,
              object: "response",
              status: "completed",
              model: body.model ?? "qwen/qwen3.5-9b",
              output_text: "fake openai-compatible streamed response",
              usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
            },
          })}\n\n`,
        );
        return;
      }
      response.statusCode = 404;
      response.end(JSON.stringify({ error: { message: "responses unavailable" } }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        response.setHeader("content-type", "text/event-stream");
        const created = Math.floor(Date.now() / 1000);
        const base = {
          id: "chatcmpl_fake_openai_compatible_stream",
          object: "chat.completion.chunk",
          created,
          model: body.model ?? "qwen/qwen3.5-9b",
        };
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: "fake openai-compatible " }, finish_reason: null }] })}\n\n`);
        response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: "streamed chat" }, finish_reason: null }] })}\n\n`);
        response.write(
          `data: ${JSON.stringify({
            ...base,
            choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
          })}\n\n`,
        );
        response.end("data: [DONE]\n\n");
        return;
      }
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_lmstudio",
          object: "chat.completion",
          model: "qwen/qwen3.5-9b",
          choices: [{ index: 0, message: { role: "assistant", content: "fake lm studio chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 2, completion_tokens: 4, total_tokens: 6 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2, 0.3] }],
          usage: { prompt_tokens: 2, completion_tokens: 0, total_tokens: 2 },
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeOllamaServer({ chatStatus = 200, secret = null } = {}) {
  const loaded = new Set();
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/api/tags") {
      response.end(
        JSON.stringify({
          models: [
            { name: "qwen3:8b", size: 4_900_000_000, digest: "sha256:fixture-qwen" },
            { name: "nomic-embed-text:latest", size: 274_000_000, digest: "sha256:fixture-embed" },
          ],
        }),
      );
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/ps") {
      response.end(
        JSON.stringify({
          models: [...loaded].map((name) => ({
            name,
            model: name,
            size: name.includes("embed") ? 274_000_000 : 4_900_000_000,
            processor: "100% CPU",
            expires_at: new Date(Date.now() + 300000).toISOString(),
          })),
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/generate") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.keep_alive === 0 || body.keep_alive === "0" || body.keep_alive === "0s") {
        loaded.delete(String(body.model));
      } else if (body.model) {
        loaded.add(String(body.model));
      }
      response.end(JSON.stringify({ model: body.model, response: "", done: true }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/chat") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.model) loaded.add(String(body.model));
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: `provider failed ${secret}` }));
        return;
      }
      if (body.stream === true) {
        writeFakeOllamaChatJsonl(response, {
          model: body.model ?? "qwen3:8b",
          chunks: ["fake ollama ", "streamed chat"],
          usage: { prompt_eval_count: 3, eval_count: 5 },
        });
        return;
      }
      response.end(
        JSON.stringify({
          model: "qwen3:8b",
          message: { role: "assistant", content: "fake ollama chat" },
          done: true,
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/embeddings") {
      response.end(JSON.stringify({ embedding: [0.12, 0.34, 0.56] }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeVllmServer({ responsesStatus = 200, chatStatus = 200, secret = null, requiredAuthorization = null, requiredHeaders = null } = {}) {
  const observedHeaders = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (requiredAuthorization || requiredHeaders) {
      observedHeaders.push({ ...request.headers });
      const missingRequiredHeader = requiredHeaders
        ? Object.entries(requiredHeaders).find(([name, value]) => request.headers[String(name).toLowerCase()] !== value)
        : null;
      if ((requiredAuthorization && request.headers.authorization !== requiredAuthorization) || missingRequiredHeader) {
        response.statusCode = 401;
        response.end(JSON.stringify({ error: { message: "provider auth failed" } }));
        return;
      }
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "vllm-qwen" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (responsesStatus !== 200) {
        response.statusCode = responsesStatus;
        response.end(JSON.stringify({ error: { message: `responses unavailable ${secret ?? ""}` } }));
        return;
      }
      if (body.stream === true) {
        writeFakeOpenAiResponseSse(response, {
          responseId: "resp_fake_vllm_stream",
          itemId: "msg_fake_vllm_stream",
          model: body.model ?? "vllm-qwen",
          chunks: ["fake vllm ", "streamed response"],
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        });
        return;
      }
      response.end(
        JSON.stringify({
          id: "resp_fake_vllm",
          object: "response",
          model: "vllm-qwen",
          output_text: "fake vllm response",
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (chatStatus !== 200) {
        response.statusCode = chatStatus;
        response.end(JSON.stringify({ error: { message: `chat failed ${secret}` } }));
        return;
      }
      if (body.stream === true) {
        writeFakeOpenAiChatCompletionSse(response, {
          id: "chatcmpl_fake_vllm_stream",
          model: body.model ?? "vllm-qwen",
          chunks: ["fake vllm ", "streamed chat"],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        });
        return;
      }
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_vllm",
          object: "chat.completion",
          model: "vllm-qwen",
          choices: [{ index: 0, message: { role: "assistant", content: "fake vllm chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.91, 0.82, 0.73] }],
          usage: { prompt_tokens: 2, completion_tokens: 0, total_tokens: 2 },
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    observedHeaders: () => observedHeaders.map((headers) => ({ ...headers })),
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeLlamaCppServer({ embeddingStatus = 200, chatStreamDelayMs = 0 } = {}) {
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify({ object: "list", data: [{ id: "llama-cpp-qwen" }] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/responses") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        writeFakeOpenAiResponseSse(response, {
          responseId: "resp_fake_llama_cpp_stream",
          itemId: "msg_fake_llama_cpp_stream",
          model: body.model ?? "llama-cpp-qwen",
          chunks: ["fake llama.cpp ", "streamed response"],
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        });
        return;
      }
      response.end(
        JSON.stringify({
          id: "resp_fake_llama_cpp",
          object: "response",
          model: "llama-cpp-qwen",
          output_text: "fake llama.cpp response",
          usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = JSON.parse((await readRequestText(request)) || "{}");
      if (body.stream === true) {
        const isAbortProbe = JSON.stringify(body.messages ?? []).includes("deliberately long numbered list");
        const payload = {
          id: "chatcmpl_fake_llama_cpp_stream",
          model: body.model ?? "llama-cpp-qwen",
          chunks: isAbortProbe
            ? Array.from({ length: 12 }, (_, index) => `fake llama.cpp abort chunk ${index}. `)
            : ["fake llama.cpp ", "streamed chat"],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        };
        if (isAbortProbe && chatStreamDelayMs > 0) {
          await writeFakeOpenAiChatCompletionSseSlow(response, payload, chatStreamDelayMs);
        } else {
          writeFakeOpenAiChatCompletionSse(response, payload);
        }
        return;
      }
      response.end(
        JSON.stringify({
          id: "chatcmpl_fake_llama_cpp",
          object: "chat.completion",
          model: "llama-cpp-qwen",
          choices: [{ index: 0, message: { role: "assistant", content: "fake llama.cpp chat" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/embeddings") {
      if (embeddingStatus !== 200) {
        response.statusCode = embeddingStatus;
        response.end(JSON.stringify({ error: { message: "embeddings unsupported by fake llama.cpp fixture" } }));
        return;
      }
      response.end(
        JSON.stringify({
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: [0.44, 0.55, 0.66] }],
          usage: { prompt_tokens: 2, completion_tokens: 0, total_tokens: 2 },
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function writeFakeOllamaChatJsonl(response, { model, chunks, usage }) {
  response.setHeader("content-type", "application/x-ndjson");
  for (const chunk of chunks) {
    response.write(
      `${JSON.stringify({
        model,
        created_at: new Date().toISOString(),
        message: { role: "assistant", content: chunk },
        done: false,
      })}\n`,
    );
  }
  response.end(
    `${JSON.stringify({
      model,
      created_at: new Date().toISOString(),
      message: { role: "assistant", content: "" },
      done: true,
      done_reason: "stop",
      prompt_eval_count: usage.prompt_eval_count,
      eval_count: usage.eval_count,
    })}\n`,
  );
}

function writeFakeOpenAiChatCompletionSse(response, { id, model, chunks, usage }) {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
  };
  response.setHeader("content-type", "text/event-stream");
  response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
  for (const chunk of chunks) {
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }] })}\n\n`);
  }
  response.write(
    `data: ${JSON.stringify({
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      usage,
    })}\n\n`,
  );
  response.end("data: [DONE]\n\n");
}

async function writeFakeOpenAiChatCompletionSseSlow(response, { id, model, chunks, usage }, delayMs) {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
  };
  const frames = [
    { ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] },
    ...chunks.map((chunk) => ({ ...base, choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }] })),
    { ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage },
  ];
  response.setHeader("content-type", "text/event-stream");
  for (const frame of frames) {
    if (response.destroyed || response.writableEnded) return;
    response.write(`data: ${JSON.stringify(frame)}\n\n`);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  if (!response.destroyed && !response.writableEnded) response.end("data: [DONE]\n\n");
}

function writeFakeOpenAiResponseSse(response, { responseId, itemId, model, chunks, usage }) {
  const outputText = chunks.join("");
  response.setHeader("content-type", "text/event-stream");
  response.write(
    `event: response.created\ndata: ${JSON.stringify({
      type: "response.created",
      response: {
        id: responseId,
        object: "response",
        status: "in_progress",
        model,
        output: [],
      },
    })}\n\n`,
  );
  response.write(
    `event: response.output_item.added\ndata: ${JSON.stringify({
      type: "response.output_item.added",
      output_index: 0,
      item: { id: itemId, type: "message", status: "in_progress", role: "assistant", content: [] },
    })}\n\n`,
  );
  for (const chunk of chunks) {
    response.write(
      `event: response.output_text.delta\ndata: ${JSON.stringify({
        type: "response.output_text.delta",
        item_id: itemId,
        output_index: 0,
        content_index: 0,
        delta: chunk,
      })}\n\n`,
    );
  }
  response.end(
    `event: response.completed\ndata: ${JSON.stringify({
      type: "response.completed",
      response: {
        id: responseId,
        object: "response",
        status: "completed",
        model,
        output_text: outputText,
        usage,
      },
    })}\n\n`,
  );
}

async function readRequestText(request) {
  let text = "";
  for await (const chunk of request) text += chunk;
  return text;
}

async function startFakeHuggingFaceCatalogServer({ requiredHeaders = {} } = {}) {
  const modelBytes = Buffer.from("family=qwen-hf-live\ncontext=4096\nquantization=Q4_K_M\n");
  const downloadAttempts = new Map();
  const observed = [];
  const assertHeaders = (request, response) => {
    observed.push({ ...request.headers });
    for (const [header, expected] of Object.entries(requiredHeaders)) {
      if (request.headers[String(header).toLowerCase()] !== expected) {
        response.statusCode = 401;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "unauthorized" }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/api/models") {
      if (!assertHeaders(request, response)) return;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify([
          {
            id: "Qwen/Qwen3-GGUF",
            modelId: "Qwen/Qwen3-GGUF",
            pipeline_tag: "text-generation",
            tags: ["gguf", "qwen", "Q4_K_M"],
            cardData: { license: "apache-2.0" },
            siblings: [
              { rfilename: "qwen-3b-Q4_K_M.gguf", size: modelBytes.length },
              { rfilename: "mlx/qwen-3b-4bit.safetensors", size: 12 },
            ],
          },
        ]),
      );
      return;
    }
    if (request.method === "GET" && url.pathname === "/Qwen/Qwen3-GGUF/resolve/main/qwen-3b-Q4_K_M.gguf") {
      if (!assertHeaders(request, response)) return;
      const status = Number(url.searchParams.get("status") ?? 0);
      if (status >= 400) {
        response.statusCode = status;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "download failed" }));
        return;
      }
      const attemptKey = url.searchParams.get("attempt_key") ?? `${url.pathname}?${url.searchParams.toString()}`;
      const attempt = (downloadAttempts.get(attemptKey) ?? 0) + 1;
      downloadAttempts.set(attemptKey, attempt);
      const range = request.headers.range;
      const dropOnceAfter = Number(url.searchParams.get("drop_once_after") ?? 0);
      if (dropOnceAfter > 0 && attempt === 1 && !range) {
        const chunk = modelBytes.subarray(0, Math.min(dropOnceAfter, modelBytes.length));
        response.setHeader("content-type", "application/octet-stream");
        response.setHeader("content-length", String(modelBytes.length));
        response.write(chunk, () => response.destroy(new Error("deterministic dropped download")));
        return;
      }
      if (range) {
        const offset = Number(String(range).match(/bytes=([0-9]+)-/)?.[1] ?? 0);
        const chunk = modelBytes.subarray(offset);
        response.statusCode = 206;
        response.setHeader("content-range", `bytes ${offset}-${modelBytes.length - 1}/${modelBytes.length}`);
        response.setHeader("content-length", String(chunk.length));
        response.end(chunk);
        return;
      }
      response.setHeader("content-type", "application/octet-stream");
      response.setHeader("content-length", String(modelBytes.length));
      response.end(modelBytes);
      return;
    }
    response.statusCode = 404;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    observedHeaders: () => observed,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeCustomCatalogServer({ requiredHeaders = {} } = {}) {
  const observed = [];
  const assertHeaders = (request, response) => {
    observed.push({ ...request.headers });
    const headers = typeof requiredHeaders === "function" ? requiredHeaders() : requiredHeaders;
    for (const [header, expected] of Object.entries(headers ?? {})) {
      if (request.headers[String(header).toLowerCase()] !== expected) {
        response.statusCode = 401;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ error: "unauthorized" }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/catalog/search") {
      if (!assertHeaders(request, response)) return;
      response.end(
        JSON.stringify({
          results: [
            {
              model_id: "custom/http-vllm-fixture",
              family: "custom-http",
              architecture: "mistral",
              parameter_count: "7B",
              format: "safetensors",
              quantization: "F16",
              size_bytes: 8192,
              context_window: 16384,
              source_url: "fixture://custom-http/vllm-safetensors-f16",
              source_label: "Custom HTTP / vLLM safetensors",
              compatibility: ["vllm", "openai_compatible"],
              tags: ["custom", "vllm"],
              license: "fixture-custom",
            },
          ],
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}`,
    observedHeaders: () => observed,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function startFakeOAuthServer({ accessToken, refreshToken, refreshedAccessToken, refreshedRefreshToken, expiresIn = 90, requirePkce = false } = {}) {
  const observed = [];
  const tokens = {
    access: accessToken ?? `oauth-access-${crypto.randomBytes(6).toString("hex")}`,
    refresh: refreshToken ?? `oauth-refresh-${crypto.randomBytes(6).toString("hex")}`,
    refreshedAccess: refreshedAccessToken ?? `oauth-access-refreshed-${crypto.randomBytes(6).toString("hex")}`,
    refreshedRefresh: refreshedRefreshToken ?? `oauth-refresh-refreshed-${crypto.randomBytes(6).toString("hex")}`,
  };
  let currentAccess = tokens.access;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && url.pathname === "/oauth/authorize") {
      observed.push({
        grantType: "authorization_start",
        stateHash: url.searchParams.get("state") ? crypto.createHash("sha256").update(url.searchParams.get("state")).digest("hex") : null,
        codeChallengeHash: url.searchParams.get("code_challenge")
          ? crypto.createHash("sha256").update(url.searchParams.get("code_challenge")).digest("hex")
          : null,
        method: url.searchParams.get("code_challenge_method"),
        scope: url.searchParams.get("scope"),
      });
      response.end(JSON.stringify({ ok: true }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/oauth/token") {
      const text = await readRequestText(request);
      const params = new URLSearchParams(text);
      const grantType = params.get("grant_type");
      const codeVerifier = params.get("code_verifier");
      observed.push({
        grantType,
        codeHash: params.get("code") ? crypto.createHash("sha256").update(params.get("code")).digest("hex") : null,
        refreshTokenHash: params.get("refresh_token") ? crypto.createHash("sha256").update(params.get("refresh_token")).digest("hex") : null,
        clientIdHash: params.get("client_id") ? crypto.createHash("sha256").update(params.get("client_id")).digest("hex") : null,
        codeVerifierHash: codeVerifier ? crypto.createHash("sha256").update(codeVerifier).digest("hex") : null,
        scope: params.get("scope"),
      });
      if (grantType === "authorization_code" && requirePkce && !codeVerifier) {
        response.statusCode = 401;
        response.end(JSON.stringify({ error: "pkce_required" }));
        return;
      }
      if (grantType === "authorization_code" && params.get("code") === "valid-oauth-code") {
        currentAccess = tokens.access;
        response.end(JSON.stringify({ access_token: tokens.access, refresh_token: tokens.refresh, expires_in: expiresIn, scope: "catalog.read" }));
        return;
      }
      if (grantType === "refresh_token" && params.get("refresh_token") === tokens.refresh) {
        currentAccess = tokens.refreshedAccess;
        response.end(JSON.stringify({ access_token: tokens.refreshedAccess, refresh_token: tokens.refreshedRefresh, expires_in: expiresIn, scope: "catalog.read" }));
        return;
      }
      response.statusCode = 401;
      response.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await listen(server);
  const address = server.address();
  return {
    endpoint: `http://${address.address}:${address.port}/oauth/token`,
    authorizationEndpoint: `http://${address.address}:${address.port}/oauth/authorize`,
    currentAccessToken: () => currentAccess,
    tokens,
    observed: () => observed,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function runChildProcess(command, args, { cwd, env, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const child = childProcess.spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timeout);
      resolve({ status, signal, stdout, stderr, timedOut });
    });
  });
}


export {
  runChildProcess,
  startFakeCustomCatalogServer,
  startFakeHuggingFaceCatalogServer,
  startFakeLlamaCppServer,
  startFakeOAuthServer,
  startFakeOllamaServer,
  startFakeOpenAiCompatibleServer,
  startFakeVllmServer,
};
