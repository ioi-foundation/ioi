import { Du as e, _t as t, gt as n, ht as r, mt as i, pt as a, v_ as o } from "./vendor-DAwbZtf0.js";
function s(e, t) {
  if (!t) return [];
  let n = e.toLowerCase(),
    r = t.toLowerCase(),
    i = [],
    a = 0;
  for (let e of r) {
    let t = n.indexOf(e, a);
    if (t === -1) return [];
    (i.push(t), (a = t + 1));
  }
  return i;
}
var c = o(),
  l = ({ text: e, query: t, className: n }) => {
    let r = s(e, t);
    if (r.length === 0) return (0, c.jsx)(`span`, { className: n, children: e });
    let i = new Set(r),
      a = [],
      o = ``,
      l = !1;
    for (let t = 0; t < e.length; t++) {
      let n = i.has(t);
      t === 0
        ? ((l = n), (o = e[t]))
        : n === l
          ? (o += e[t])
          : (a.push({ text: o, highlighted: l }), (o = e[t]), (l = n));
    }
    return (
      o && a.push({ text: o, highlighted: l }),
      (0, c.jsx)(`span`, {
        className: n,
        children: a.map((e, t) =>
          e.highlighted
            ? (0, c.jsx)(`span`, { className: `font-bold text-content-brand`, children: e.text }, t)
            : (0, c.jsx)(`span`, { children: e.text }, t),
        ),
      })
    );
  },
  u = t,
  d = a,
  f = i,
  p = n,
  m = r,
  h = e,
  g = {
    ts: u,
    tsx: u,
    js: u,
    jsx: u,
    mjs: u,
    cjs: u,
    go: u,
    py: u,
    rs: u,
    c: u,
    cpp: u,
    h: u,
    hpp: u,
    rb: u,
    swift: u,
    kt: u,
    kts: u,
    cs: u,
    php: u,
    lua: u,
    r: u,
    scala: u,
    zig: u,
    hs: u,
    ex: u,
    exs: u,
    erl: u,
    clj: u,
    v: u,
    sol: u,
    java: u,
    sh: u,
    bash: u,
    zsh: u,
    fish: u,
    ps1: u,
    sql: u,
    pl: u,
    pm: u,
    dart: u,
    vue: u,
    svelte: u,
    json: u,
    jsonc: u,
    json5: u,
    yaml: u,
    yml: u,
    toml: u,
    xml: u,
    html: u,
    htm: u,
    css: u,
    scss: u,
    less: u,
    sass: u,
    svg: u,
    graphql: u,
    gql: u,
    proto: u,
    env: u,
    ini: u,
    cfg: u,
    conf: u,
    properties: u,
    gitignore: u,
    gitattributes: u,
    editorconfig: u,
    prettierrc: u,
    eslintrc: u,
    babelrc: u,
    npmrc: u,
    nvmrc: u,
    dockerignore: u,
    hcl: u,
    tf: u,
    tfvars: u,
    nix: u,
    md: d,
    mdx: d,
    rst: d,
    png: f,
    jpg: f,
    jpeg: f,
    gif: f,
    webp: f,
    ico: f,
    bmp: f,
    tiff: f,
    avif: f,
    pdf: p,
    doc: p,
    docx: p,
    xls: p,
    xlsx: p,
    ppt: p,
    pptx: p,
    odt: p,
    ods: p,
    zip: m,
    tar: m,
    gz: m,
    tgz: m,
    bz2: m,
    xz: m,
    rar: m,
    "7z": m,
    jar: m,
    war: m,
  },
  _ = {
    dockerfile: u,
    makefile: u,
    justfile: u,
    rakefile: u,
    gemfile: u,
    vagrantfile: u,
    procfile: u,
    cmakelists: u,
    "docker-compose.yml": u,
    "docker-compose.yaml": u,
  };
function v(e) {
  let t = (e.split(`/`).pop() ?? e).toLowerCase(),
    n = _[t];
  if (n) return n;
  let r = t.lastIndexOf(`.`);
  if (r > 0) {
    let e = _[t.slice(0, r)];
    if (e) return e;
    let n = g[t.slice(r + 1)];
    if (n) return n;
  }
  return h;
}
export { l as n, v as t };
