function e(e, t) {
  return e
    ? t
      ? new URL(e).pathname.replace(/\.git$/, ``).replace(/\//, ``)
      : e.replace(/https?:\/\//, ``).replace(/\.git$/, ``)
    : `No URL`;
}
export { e as t };
