function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

module.exports = {
  firstArray,
  stringValue,
};
