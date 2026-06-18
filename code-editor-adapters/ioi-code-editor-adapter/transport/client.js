function transportUrl() {
  return process.env.IOI_CODE_EDITOR_ADAPTER_TRANSPORT_URL || null;
}

module.exports = {
  transportUrl,
};
