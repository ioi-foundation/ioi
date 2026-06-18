function bridgeUrl() {
  return process.env.IOI_CODE_EDITOR_ADAPTER_BRIDGE_URL || null;
}

module.exports = {
  bridgeUrl,
};
