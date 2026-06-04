import crypto from "node:crypto";

import {
  anthropicMessage,
  openAiChatCompletion,
  openAiCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./model-mounting/protocol-responses.mjs";
import {
  notFound,
  readBody,
  redact,
  writeJsonResponse,
} from "./runtime-http-utils.mjs";

const STREAM_SHAPE_SAMPLE_LIMIT = 8;

export async function handleOpenAiCompatibilityRoute({ request, response, store, url }) {
  const mounts = store.modelMounting;
  const authorization = compatibilityAuthorization(request);
  if (request.method === "GET" && url.pathname === "/v1/models") {
    writeJsonResponse(response, mounts.openAiModelList());
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderChatCompletionStream(request, response, stream, mounts);
        return;
      }
      await writeOpenAiChatCompletionStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "chat.completions",
      body,
    });
    writeJsonResponse(response, openAiChatCompletion(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/responses") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.responses:*",
        kind: "responses",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderResponseStream(response, stream, mounts);
        return;
      }
      await writeOpenAiResponseStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.responses:*",
      kind: "responses",
      body,
    });
    writeJsonResponse(response, openAiResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/embeddings") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.embeddings:*",
      kind: "embeddings",
      body,
    });
    writeJsonResponse(response, openAiEmbedding(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/completions") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "completions",
      body,
    });
    writeJsonResponse(response, openAiCompletion(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/messages") {
    const body = await readBody(request);
    const canonicalBody = anthropicMessagesToCanonicalBody(body);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body: canonicalBody,
      });
      if (stream.native) {
        await writeAnthropicProviderMessageStream(response, stream, mounts);
        return;
      }
      await writeAnthropicMessageStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "messages",
      body: canonicalBody,
    });
    writeJsonResponse(response, anthropicMessage(invocation));
    return;
  }
  throw notFound("OpenAI-compatible route not found.", {
    method: request.method,
    path: url.pathname,
  });
}

export function isOpenAiCompatibilityRoute(request, url) {
  if (request.method === "GET" && url.pathname === "/v1/models") {
    return Boolean(compatibilityAuthorization(request));
  }
  return [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/messages",
  ].includes(url.pathname);
}

export function compatibilityAuthorization(request) {
  const authorization = firstHeader(request.headers.authorization);
  if (authorization) return authorization;
  const apiKey = firstHeader(request.headers["x-api-key"]);
  if (!apiKey) return undefined;
  return apiKey.startsWith("Bearer ") ? apiKey : `Bearer ${apiKey}`;
}

export function firstHeader(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

export function anthropicMessagesToCanonicalBody(body = {}) {
  return {
    ...body,
    messages: canonicalAnthropicMessages(body),
    max_tokens: body.max_tokens ?? body.maxTokens,
    stream: false,
  };
}

export function canonicalAnthropicMessages(body = {}) {
  const messages = [];
  if (body.system !== undefined) {
    messages.push({ role: "system", content: anthropicContentToText(body.system) });
  }
  for (const message of Array.isArray(body.messages) ? body.messages : []) {
    messages.push({
      role: message?.role ?? "user",
      content: anthropicContentToText(message?.content ?? ""),
    });
  }
  return messages.length > 0 ? messages : [{ role: "user", content: anthropicContentToText(body.input ?? "") }];
}

export function anthropicContentToText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((item) => {
        if (typeof item === "string") return item;
        if (typeof item?.text === "string") return item.text;
        if (typeof item?.content === "string") return item.content;
        if (item?.type === "image" || item?.type === "image_url") return "[image]";
        return JSON.stringify(redact(item ?? {}));
      })
      .join("\n");
  }
  if (content && typeof content === "object") {
    if (typeof content.text === "string") return content.text;
    return JSON.stringify(redact(content));
  }
  return String(content ?? "");
}

export async function writeAnthropicMessageStream(response, invocation, mounts) {
  const message = anthropicMessage(invocation);
  const text = String(message.content?.[0]?.text ?? "");
  const chunks = textChunksForSse(text);
  const usage = message.usage ?? { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 };
  const events = [
    {
      event: "message_start",
      data: {
        type: "message_start",
        message: {
          id: message.id,
          type: "message",
          role: "assistant",
          content: [],
          model: message.model,
          stop_reason: null,
          stop_sequence: null,
          usage: {
            input_tokens: usage.input_tokens,
            output_tokens: 0,
            cache_read_input_tokens: usage.cache_read_input_tokens ?? 0,
          },
        },
      },
    },
    {
      event: "content_block_start",
      data: {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "content_block_delta",
      data: {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: chunk },
      },
    })),
    {
      event: "content_block_stop",
      data: {
        type: "content_block_stop",
        index: 0,
      },
    },
    {
      event: "message_delta",
      data: {
        type: "message_delta",
        delta: {
          stop_reason: message.stop_reason,
          stop_sequence: message.stop_sequence,
        },
        usage: {
          output_tokens: usage.output_tokens,
        },
      },
    },
    {
      event: "message_stop",
      data: {
        type: "message_stop",
        receipt_id: message.receipt_id,
        response_id: message.response_id,
        previous_response_id: message.previous_response_id,
        route_id: message.route_id,
        tool_receipt_ids: message.tool_receipt_ids,
      },
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "anthropic_messages",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

export async function writeAnthropicProviderMessageStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = "anthropic_messages_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const messageId = invocation.responseId?.startsWith("msg_") ? invocation.responseId : `msg_${crypto.randomUUID()}`;
  const startUsage = invocation.tokenCount ?? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "end_turn";
  let buffer = "";
  const writeEvent = (event, data) => {
    response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    written += 1;
  };
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    writeEvent("message_start", {
      type: "message_start",
      message: {
        id: messageId,
        type: "message",
        role: "assistant",
        content: [],
        model: invocation.model,
        stop_reason: null,
        stop_sequence: null,
        usage: {
          input_tokens: startUsage.prompt_tokens ?? startUsage.input_tokens ?? 0,
          output_tokens: 0,
          cache_read_input_tokens: 0,
        },
      },
    });
    writeEvent("content_block_start", {
      type: "content_block_start",
      index: 0,
      content_block: { type: "text", text: "" },
    });
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
        const lines = takeLineBlocks(buffer);
        buffer = lines.remainder;
        for (const line of lines.blocks) {
          if (canceled) break;
          if (response.destroyed || response.writableEnded) {
            markCanceled();
            break;
          }
          const parsed = parseJsonMaybe(line);
          const delta = ollamaStreamDelta(parsed);
          if (delta) {
            outputText += delta;
            writeEvent("content_block_delta", {
              type: "content_block_delta",
              index: 0,
              delta: { type: "text_delta", text: delta },
            });
          }
          if (parsed?.done) {
            providerUsage = ollamaUsage(parsed);
            finishReason = parsed.done_reason ?? "end_turn";
          }
        }
      } else {
        const frames = takeSseFrameBlocks(buffer);
        buffer = frames.remainder;
        for (const frame of frames.blocks) {
          if (canceled) break;
          if (response.destroyed || response.writableEnded) {
            markCanceled();
            break;
          }
          for (const payload of dataPayloadsFromSseBlock(frame)) {
            if (payload === "[DONE]") continue;
            const parsed = parseJsonMaybe(payload);
            const delta =
              parsed?.choices?.[0]?.delta?.content ??
              parsed?.choices?.[0]?.delta?.reasoning_content;
            if (typeof delta === "string" && delta) {
              outputText += delta;
              writeEvent("content_block_delta", {
                type: "content_block_delta",
                index: 0,
                delta: { type: "text_delta", text: delta },
              });
            }
            if (parsed?.usage) providerUsage = parsed.usage;
            if (parsed?.timings) providerUsage = usageFromProviderTimings(parsed.timings, providerUsage);
            const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
            if (nextFinishReason) finishReason = nextFinishReason;
          }
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    if (buffer.trim()) {
      const tailLines = ["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)
        ? takeLineBlocks(`${buffer}\n`).blocks
        : takeSseFrameBlocks(`${buffer}\n\n`).blocks.flatMap((block) => dataPayloadsFromSseBlock(block));
      for (const item of tailLines) {
        const parsed = parseJsonMaybe(item);
        const delta =
          ["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)
            ? ollamaStreamDelta(parsed)
            : parsed?.choices?.[0]?.delta?.content ?? parsed?.choices?.[0]?.delta?.reasoning_content;
        if (typeof delta === "string" && delta) {
          outputText += delta;
          writeEvent("content_block_delta", {
            type: "content_block_delta",
            index: 0,
            delta: { type: "text_delta", text: delta },
          });
        }
        if (parsed?.usage) providerUsage = parsed.usage;
        if (parsed?.timings) providerUsage = usageFromProviderTimings(parsed.timings, providerUsage);
        if (parsed?.done) providerUsage = ollamaUsage(parsed);
        const nextFinishReason = parsed?.choices?.[0]?.finish_reason ?? parsed?.done_reason;
        if (nextFinishReason) finishReason = nextFinishReason;
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const usage = providerUsage ?? invocation.tokenCount ?? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
    if (!response.destroyed && !response.writableEnded) {
      writeEvent("content_block_stop", { type: "content_block_stop", index: 0 });
      writeEvent("message_delta", {
        type: "message_delta",
        delta: {
          stop_reason: finishReason || "end_turn",
          stop_sequence: null,
        },
        usage: {
          output_tokens: usage.completion_tokens ?? usage.output_tokens ?? 0,
        },
      });
      writeEvent("message_stop", {
        type: "message_stop",
        receipt_id: invocation.receipt.id,
        stream_receipt_id: completionReceipt.id,
        response_id: invocation.responseId ?? null,
        previous_response_id: invocation.previousResponseId ?? null,
        route_id: invocation.route.id,
        tool_receipt_ids: invocation.toolReceiptIds ?? [],
        provider_stream: "native",
      });
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

export function textChunksForSse(text) {
  if (!text) return [""];
  const chunks = text.match(/.{1,96}(?:\s+|$)/gs);
  return chunks?.length ? chunks : [text];
}

export async function writeOpenAiChatCompletionStream(response, invocation, mounts) {
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
  const payloads = [
    {
      ...base,
      choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
    },
    ...chunks.map((chunk) => ({
      ...base,
      choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
    })),
    {
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_chat_completions",
    frames: [...payloads.map((payload) => `data: ${JSON.stringify(payload)}\n\n`), "data: [DONE]\n\n"],
  });
}

function createOpenAiProviderStreamShapeSummary() {
  return {
    schemaVersion: "ioi.model.provider_stream_shape.v1",
    jsonPayloads: 0,
    nonJsonPayloads: 0,
    payloadKeySamples: [],
    choiceKeySamples: [],
    deltaKeySamples: [],
    messageKeySamples: [],
    finishReasons: {},
    topLevelFinishReasons: {},
    usageFrames: 0,
    timingFrames: 0,
    delta: {
      contentChunks: 0,
      contentChars: 0,
      reasoningChunks: 0,
      reasoningChars: 0,
      toolCallChunks: 0,
      toolCallItems: 0,
      toolCallIdDeltas: 0,
      toolCallTypeDeltas: 0,
      toolCallNameDeltas: 0,
      toolCallArgumentDeltas: 0,
      toolCallArgumentChars: 0,
      toolCallIndexes: [],
      toolNameRefs: [],
      functionCallChunks: 0,
      functionCallNameDeltas: 0,
      functionCallArgumentDeltas: 0,
      functionCallArgumentChars: 0,
    },
    message: {
      contentFrames: 0,
      contentChars: 0,
      toolCallFrames: 0,
      toolCallItems: 0,
      toolCallNameCount: 0,
      toolCallArgumentChars: 0,
      toolNameRefs: [],
      functionCallFrames: 0,
      functionCallNamePresent: false,
      functionCallArgumentChars: 0,
    },
    _deltaToolArgumentBuffers: Object.create(null),
    _deltaFunctionArgumentBuffer: "",
    _messageToolArguments: [],
    _messageFunctionArgument: "",
  };
}

function observeOpenAiProviderStreamShape(summary, parsed) {
  if (!parsed || typeof parsed !== "object") {
    summary.nonJsonPayloads += 1;
    return;
  }
  summary.jsonPayloads += 1;
  sampleKeys(summary.payloadKeySamples, parsed);
  if (parsed.usage) summary.usageFrames += 1;
  if (parsed.timings) summary.timingFrames += 1;
  countValue(summary.topLevelFinishReasons, parsed.finish_reason);
  const choices = Array.isArray(parsed.choices) ? parsed.choices : [];
  for (const choice of choices) {
    if (!choice || typeof choice !== "object") continue;
    sampleKeys(summary.choiceKeySamples, choice);
    countValue(summary.finishReasons, choice.finish_reason);
    observeOpenAiProviderDeltaShape(summary, choice.delta);
    observeOpenAiProviderMessageShape(summary, choice.message);
  }
}

function observeOpenAiProviderDeltaShape(summary, delta) {
  if (!delta || typeof delta !== "object") return;
  sampleKeys(summary.deltaKeySamples, delta);
  if (typeof delta.content === "string" && delta.content.length > 0) {
    summary.delta.contentChunks += 1;
    summary.delta.contentChars += delta.content.length;
  }
  if (typeof delta.reasoning_content === "string" && delta.reasoning_content.length > 0) {
    summary.delta.reasoningChunks += 1;
    summary.delta.reasoningChars += delta.reasoning_content.length;
  }
  if (Array.isArray(delta.tool_calls)) {
    summary.delta.toolCallChunks += 1;
    summary.delta.toolCallItems += delta.tool_calls.length;
    for (let fallbackIndex = 0; fallbackIndex < delta.tool_calls.length; fallbackIndex += 1) {
      const call = delta.tool_calls[fallbackIndex];
      if (!call || typeof call !== "object") continue;
      if (typeof call.id === "string" && call.id.length > 0) summary.delta.toolCallIdDeltas += 1;
      if (typeof call.type === "string" && call.type.length > 0) summary.delta.toolCallTypeDeltas += 1;
      const index = Number.isFinite(call.index) ? call.index : fallbackIndex;
      sampleValue(summary.delta.toolCallIndexes, index);
      const fn = call.function;
      if (fn && typeof fn === "object") {
        if (typeof fn.name === "string" && fn.name.length > 0) {
          summary.delta.toolCallNameDeltas += 1;
          sampleValue(summary.delta.toolNameRefs, redactedStreamHash(fn.name));
        }
        if (typeof fn.arguments === "string" && fn.arguments.length > 0) {
          summary.delta.toolCallArgumentDeltas += 1;
          summary.delta.toolCallArgumentChars += fn.arguments.length;
          const key = String(index);
          summary._deltaToolArgumentBuffers[key] = `${summary._deltaToolArgumentBuffers[key] ?? ""}${fn.arguments}`;
        }
      }
    }
  }
  if (delta.function_call && typeof delta.function_call === "object") {
    summary.delta.functionCallChunks += 1;
    if (typeof delta.function_call.name === "string" && delta.function_call.name.length > 0) {
      summary.delta.functionCallNameDeltas += 1;
      sampleValue(summary.delta.toolNameRefs, redactedStreamHash(delta.function_call.name));
    }
    if (typeof delta.function_call.arguments === "string" && delta.function_call.arguments.length > 0) {
      summary.delta.functionCallArgumentDeltas += 1;
      summary.delta.functionCallArgumentChars += delta.function_call.arguments.length;
      summary._deltaFunctionArgumentBuffer += delta.function_call.arguments;
    }
  }
}

function observeOpenAiProviderMessageShape(summary, message) {
  if (!message || typeof message !== "object") return;
  sampleKeys(summary.messageKeySamples, message);
  if (typeof message.content === "string" && message.content.length > 0) {
    summary.message.contentFrames += 1;
    summary.message.contentChars += message.content.length;
  }
  if (Array.isArray(message.tool_calls)) {
    summary.message.toolCallFrames += 1;
    summary.message.toolCallItems += message.tool_calls.length;
    for (const call of message.tool_calls) {
      const fn = call?.function;
      if (!fn || typeof fn !== "object") continue;
      if (typeof fn.name === "string" && fn.name.length > 0) {
        summary.message.toolCallNameCount += 1;
        sampleValue(summary.message.toolNameRefs, redactedStreamHash(fn.name));
      }
      if (typeof fn.arguments === "string" && fn.arguments.length > 0) {
        summary.message.toolCallArgumentChars += fn.arguments.length;
        summary._messageToolArguments.push(fn.arguments);
      }
    }
  }
  if (message.function_call && typeof message.function_call === "object") {
    summary.message.functionCallFrames += 1;
    if (typeof message.function_call.name === "string" && message.function_call.name.length > 0) {
      summary.message.functionCallNamePresent = true;
      sampleValue(summary.message.toolNameRefs, redactedStreamHash(message.function_call.name));
    }
    if (typeof message.function_call.arguments === "string" && message.function_call.arguments.length > 0) {
      summary.message.functionCallArgumentChars += message.function_call.arguments.length;
      summary._messageFunctionArgument += message.function_call.arguments;
    }
  }
}

function finalizeOpenAiProviderStreamShape(summary, { framesForwarded, finishReason }) {
  const deltaToolArgumentBuffers = Object.values(summary._deltaToolArgumentBuffers ?? {});
  const messageToolArguments = summary._messageToolArguments ?? [];
  const result = {
    ...summary,
    framesForwarded,
    finishReason,
    deltaToolArgumentBuffers: summarizeJsonArgumentBuffers(deltaToolArgumentBuffers),
    deltaFunctionArgumentBuffer: summarizeJsonArgumentBuffers([summary._deltaFunctionArgumentBuffer].filter(Boolean)),
    messageToolArguments: summarizeJsonArgumentBuffers(messageToolArguments),
    messageFunctionArgument: summarizeJsonArgumentBuffers([summary._messageFunctionArgument].filter(Boolean)),
    evidenceRefs: ["model_provider_stream_shape_summary"],
  };
  delete result._deltaToolArgumentBuffers;
  delete result._deltaFunctionArgumentBuffer;
  delete result._messageToolArguments;
  delete result._messageFunctionArgument;
  return result;
}

function summarizeJsonArgumentBuffers(buffers) {
  let validJson = 0;
  let invalidJson = 0;
  let empty = 0;
  let totalChars = 0;
  const hashes = [];
  for (const buffer of buffers) {
    const text = typeof buffer === "string" ? buffer : "";
    if (!text.trim()) {
      empty += 1;
      continue;
    }
    totalChars += text.length;
    sampleValue(hashes, redactedStreamHash(text));
    try {
      JSON.parse(text);
      validJson += 1;
    } catch {
      invalidJson += 1;
    }
  }
  return { buffers: buffers.length, validJson, invalidJson, empty, totalChars, argumentHashes: hashes };
}

function sampleKeys(target, value) {
  if (!value || typeof value !== "object") return;
  sampleValue(target, Object.keys(value).sort().join(","));
}

function sampleValue(target, value) {
  if (target.length >= STREAM_SHAPE_SAMPLE_LIMIT) return;
  if (!target.includes(value)) target.push(value);
}

function countValue(target, value) {
  if (typeof value !== "string" || value.length === 0) return;
  target[value] = (target[value] ?? 0) + 1;
}

function redactedStreamHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

export async function writeOpenAiProviderChatCompletionStream(request, response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaChatCompletionStream(request, response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_chat_completions_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const forwardDelayMs = providerStreamForwardDelayMs();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const streamShape = createOpenAiProviderStreamShapeSummary();
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  request.on("aborted", onClose);
  request.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        for (const payload of dataPayloadsFromSseBlock(frame)) {
          if (payload === "[DONE]") continue;
          const parsed = parseJsonMaybe(payload);
          observeOpenAiProviderStreamShape(streamShape, parsed);
          const delta =
            parsed?.choices?.[0]?.delta?.content ??
            parsed?.choices?.[0]?.delta?.reasoning_content;
          if (typeof delta === "string") outputText += delta;
          if (parsed?.usage) providerUsage = parsed.usage;
          if (parsed?.timings) providerUsage = usageFromProviderTimings(parsed.timings, providerUsage);
          const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
          if (nextFinishReason) finishReason = nextFinishReason;
          try {
            response.write(`data: ${payload}\n\n`);
          } catch {
            markCanceled();
            break;
          }
          written += 1;
          if (forwardDelayMs > 0) await delay(forwardDelayMs);
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      for (const payload of dataPayloadsFromSseBlock(frame)) {
        if (payload === "[DONE]") continue;
        const parsed = parseJsonMaybe(payload);
        observeOpenAiProviderStreamShape(streamShape, parsed);
        const delta =
          parsed?.choices?.[0]?.delta?.content ??
          parsed?.choices?.[0]?.delta?.reasoning_content;
        if (typeof delta === "string") outputText += delta;
        if (parsed?.usage) providerUsage = parsed.usage;
        if (parsed?.timings) providerUsage = usageFromProviderTimings(parsed.timings, providerUsage);
        const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
        if (nextFinishReason) finishReason = nextFinishReason;
        response.write(`data: ${payload}\n\n`);
        written += 1;
        if (forwardDelayMs > 0) await delay(forwardDelayMs);
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    mounts.appendOperation?.(
      "model.provider_stream_shape_summary",
      finalizeOpenAiProviderStreamShape(streamShape, { framesForwarded: written, finishReason }),
    );
    const metadata = {
      id: `chatcmpl_${crypto.randomUUID()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: invocation.model,
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
      usage: completionReceipt.details?.tokenCount ?? providerUsage ?? null,
      finish_reason: finishReason,
      choices: [{ index: 0, delta: {}, finish_reason: null }],
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`data: ${JSON.stringify(metadata)}\n\n`);
      response.write("data: [DONE]\n\n");
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    request.off("aborted", onClose);
    request.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

export async function writeOllamaChatCompletionStream(request, response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_chat_completions_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const forwardDelayMs = providerStreamForwardDelayMs();
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    provider_stream: "native",
  };
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  request.on("aborted", onClose);
  request.on("close", onClose);
  try {
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
    written += 1;
    if (forwardDelayMs > 0) await delay(forwardDelayMs);
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: delta }, finish_reason: null }] })}\n\n`,
          );
          written += 1;
          if (forwardDelayMs > 0) await delay(forwardDelayMs);
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    response.write(
      `data: ${JSON.stringify({
        ...base,
        stream_receipt_id: completionReceipt.id,
        usage: completionReceipt.details?.tokenCount ?? providerUsage ?? null,
        choices: [{ index: 0, delta: {}, finish_reason: finishReason }],
      })}\n\n`,
    );
    response.write("data: [DONE]\n\n");
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    request.off("aborted", onClose);
    request.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

export async function writeOpenAiProviderResponseStream(response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaResponseStream(response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_responses_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsedPayloads = responseStreamPayloads(frame);
        for (const payload of parsedPayloads) {
          if (payload.raw === "[DONE]") continue;
          if (payload.delta) outputText += payload.delta;
          if (!outputText && payload.completionText) outputText = payload.completionText;
          if (payload.usage) providerUsage = payload.usage;
          if (payload.finishReason) finishReason = payload.finishReason;
        }
        try {
          response.write(`${frame}\n\n`);
        } catch {
          markCanceled();
          break;
        }
        written += 1;
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      const parsedPayloads = responseStreamPayloads(frame);
      if (parsedPayloads.every((payload) => payload.raw === "[DONE]")) continue;
      for (const payload of parsedPayloads) {
        if (payload.raw === "[DONE]") continue;
        if (payload.delta) outputText += payload.delta;
        if (!outputText && payload.completionText) outputText = payload.completionText;
        if (payload.usage) providerUsage = payload.usage;
        if (payload.finishReason) finishReason = payload.finishReason;
      }
      response.write(`${frame}\n\n`);
      written += 1;
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const metadata = {
      type: "response.ioi.receipt",
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
      route_id: invocation.route.id,
      model: invocation.model,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`event: response.ioi.receipt\ndata: ${JSON.stringify(metadata)}\n\n`);
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

export async function writeOllamaResponseStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_responses_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const responseId = invocation.responseId ?? `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    previous_response_id: invocation.previousResponseId ?? null,
    provider_stream: "native",
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    response.write(`event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: baseResponse })}\n\n`);
    response.write(`event: response.output_item.added\ndata: ${JSON.stringify({ type: "response.output_item.added", output_index: 0, item: outputItem })}\n\n`);
    response.write(
      `event: response.content_part.added\ndata: ${JSON.stringify({
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      })}\n\n`,
    );
    written += 3;
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `event: response.output_text.delta\ndata: ${JSON.stringify({
              type: "response.output_text.delta",
              item_id: outputItemId,
              output_index: 0,
              content_index: 0,
              delta,
            })}\n\n`,
          );
          written += 1;
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const completedOutputItem = {
      ...outputItem,
      status: "completed",
      content: [{ type: "output_text", text: outputText }],
    };
    const completedResponse = {
      ...baseResponse,
      status: "completed",
      output: [completedOutputItem],
      output_text: outputText,
      usage: providerUsage,
      stream_receipt_id: completionReceipt.id,
    };
    response.write(
      `event: response.content_part.done\ndata: ${JSON.stringify({
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: outputText },
      })}\n\n`,
    );
    response.write(`event: response.output_item.done\ndata: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: completedOutputItem })}\n\n`);
    response.write(`event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: completedResponse })}\n\n`);
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

export async function writeOpenAiResponseStream(response, invocation, mounts) {
  const responseId = invocation.responseId ?? `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    previous_response_id: invocation.previousResponseId ?? null,
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  const completedOutputItem = {
    ...outputItem,
    status: "completed",
    content: [{ type: "output_text", text: invocation.outputText }],
  };
  const completedResponse = {
    ...baseResponse,
    status: "completed",
    output: [completedOutputItem],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
  const events = [
    { event: "response.created", data: { type: "response.created", response: baseResponse } },
    {
      event: "response.output_item.added",
      data: { type: "response.output_item.added", output_index: 0, item: outputItem },
    },
    {
      event: "response.content_part.added",
      data: {
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "response.output_text.delta",
      data: {
        type: "response.output_text.delta",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        delta: chunk,
      },
    })),
    {
      event: "response.content_part.done",
      data: {
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: invocation.outputText },
      },
    },
    {
      event: "response.output_item.done",
      data: { type: "response.output_item.done", output_index: 0, item: completedOutputItem },
    },
    { event: "response.completed", data: { type: "response.completed", response: completedResponse } },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_responses",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

export async function writeModelSseFrames({ response, invocation, mounts, streamKind, frames }) {
  let completed = false;
  let canceled = false;
  const onClose = () => {
    if (completed || canceled) return;
    canceled = true;
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  let written = 0;
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.on("close", onClose);
  try {
    for (const frame of frames) {
      if (canceled || response.destroyed || response.writableEnded) break;
      response.write(frame);
      written += 1;
      await delay(streamFrameDelayMs());
    }
    if (!canceled && !response.destroyed && !response.writableEnded) {
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
  }
}

export function recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten }) {
  mounts.receipt("model_invocation_stream_canceled", {
    summary: `${streamKind} stream canceled for ${invocation.model}.`,
    redaction: "redacted",
    evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
    details: {
      streamKind,
      invocationReceiptId: invocation.receipt.id,
      routeId: invocation.route.id,
      selectedModel: invocation.model,
      endpointId: invocation.endpoint.id,
      providerId: invocation.endpoint.providerId,
      instanceId: invocation.instance.id,
      backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
      selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
      streamSource: invocation.receipt.details?.streamSource ?? null,
      providerResponseKind: invocation.providerResponseKind ?? invocation.receipt.details?.providerResponseKind ?? null,
      backendEvidenceRefs: invocation.receipt.details?.backendEvidenceRefs ?? [],
      toolReceiptIds: invocation.toolReceiptIds ?? [],
      framesWritten,
      status: "aborted",
      reason: "client_disconnect",
    },
  });
}

export function streamFrameDelayMs() {
  const configured = Number(process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS ?? "");
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 5;
}

export function providerStreamForwardDelayMs() {
  const configured = Number(process.env.IOI_PROVIDER_SSE_FRAME_DELAY_MS ?? "");
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 0;
}

export function takeSseFrameBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.filter(Boolean), remainder };
}

export function takeLineBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.map((part) => part.trim()).filter(Boolean), remainder };
}

export function dataPayloadsFromSseBlock(block) {
  const payload = String(block)
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.replace(/^data:\s?/, ""))
    .join("\n");
  return payload ? [payload] : [];
}

export function responseStreamPayloads(block) {
  return dataPayloadsFromSseBlock(block).map((raw) => {
    if (raw === "[DONE]") return { raw };
    const parsed = parseJsonMaybe(raw);
    return {
      raw,
      parsed,
      delta: typeof parsed?.delta === "string" && parsed?.type === "response.output_text.delta" ? parsed.delta : "",
      completionText: typeof parsed?.response?.output_text === "string" ? parsed.response.output_text : "",
      usage: parsed?.response?.usage ?? parsed?.usage ?? null,
      finishReason: parsed?.response?.status ?? parsed?.status ?? parsed?.type ?? null,
    };
  });
}

export function ollamaStreamDelta(payload) {
  if (!payload || typeof payload !== "object") return "";
  return String(payload.delta ?? payload.message?.content ?? payload.response ?? "");
}

export function ollamaUsage(payload) {
  const promptTokens = Number(payload?.prompt_eval_count ?? 0) || 0;
  const completionTokens = Number(payload?.eval_count ?? 0) || 0;
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

export function usageFromProviderTimings(timings = {}, previousUsage = null) {
  if (!timings || typeof timings !== "object") return previousUsage;
  const promptTokens = Number(timings.prompt_n ?? previousUsage?.prompt_tokens ?? previousUsage?.input_tokens ?? 0) || 0;
  const completionTokens =
    Number(timings.predicted_n ?? previousUsage?.completion_tokens ?? previousUsage?.output_tokens ?? 0) || 0;
  const usage = {
    ...(previousUsage && typeof previousUsage === "object" ? previousUsage : {}),
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: Number(previousUsage?.total_tokens ?? promptTokens + completionTokens) || promptTokens + completionTokens,
  };
  const tokensPerSecond = Number(timings.predicted_per_second);
  const promptMs = Number(timings.prompt_ms);
  const completionMs = Number(timings.predicted_ms);
  if (Number.isFinite(tokensPerSecond)) usage.tokens_per_second = tokensPerSecond;
  if (Number.isFinite(promptMs)) usage.prompt_ms = promptMs;
  if (Number.isFinite(completionMs)) usage.completion_ms = completionMs;
  if (Number.isFinite(promptMs) || Number.isFinite(completionMs)) {
    usage.elapsed_ms = (Number.isFinite(promptMs) ? promptMs : 0) + (Number.isFinite(completionMs) ? completionMs : 0);
  }
  return usage;
}

export function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function nativeInvocationResponse(invocation) {
  return {
    id: `model_invocation_${crypto.randomUUID()}`,
    object: "ioi.model_invocation",
    model: invocation.model,
    route_id: invocation.route.id,
    endpoint_id: invocation.endpoint.id,
    instance_id: invocation.instance.id,
    backend_id: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    receipt_id: invocation.receipt.id,
    route_receipt_id: invocation.routeReceipt?.id ?? null,
    route_decision: invocation.routeReceipt?.details?.modelRouteDecision ?? null,
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
}

export function nativeEmbeddingResponse(invocation, body = {}) {
  return {
    ...nativeInvocationResponse(invocation),
    embeddings: openAiEmbedding(invocation, body).data,
  };
}
