function e(e, n, r) {
  let i = t(n),
    a = r ?? (typeof e == `string` ? `text/plain;charset=utf-8` : `application/octet-stream`),
    o;
  o = e instanceof Blob ? (r ? e.slice(0, e.size, r) : e) : new Blob([e], { type: a });
  let s = URL.createObjectURL(o),
    c = document.createElement(`a`);
  ((c.href = s),
    (c.download = i),
    (c.rel = `noopener`),
    document.body.appendChild(c),
    c.click(),
    document.body.removeChild(c),
    setTimeout(() => URL.revokeObjectURL(s), 0));
}
function t(e) {
  let t = (e.split(/[\\/]/).pop() ?? ``).replace(/[\x00-\x1f<>:"/\\|?*]+/g, `_`).trim();
  return t.length > 0 ? t : `download`;
}
export { e as t };
