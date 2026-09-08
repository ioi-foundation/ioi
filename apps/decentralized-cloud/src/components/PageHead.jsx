import { groupLabel } from "../logic/surfaces.mjs";

// THE PAGE HEADER — one shape on every surface.
//
// A console's pages open the same way, and a reader learns the shape once: the crumb
// (the rail group this page sits in, in the rail's own word), the heading, one line
// of lede, and on the right whatever the page keeps at hand — a route chip, a
// principal, a read line. Before this component every surface drew its own opening,
// and they differed by a few pixels and a few words each, which is the difference
// between a product and a set of pages.
//
// `title` is the h1 unless `as` says otherwise (the whole catalogue's h1 is its
// hero's statement, so its own heading is an h2). `meta` is the route-and-read line
// in the mono face; `aside` is the right-hand block. Nothing here is a claim: the
// eyebrow is the registry's word, and the rest is what the surface hands in.
export default function PageHead({ surface, crumb, title, lede, meta, aside, as = "h1", id }) {
  const H = as;
  return (
    <header className="page-head">
      <div className="page-head-main">
        {crumb ? <p className="meta page-crumb">{crumb}</p> : <div className="eyebrow">{groupLabel(surface)}</div>}
        <H id={id} className="page-title">{title}</H>
        {lede && <p className="prose page-lede">{lede}</p>}
        {meta && <p className="meta page-meta">{meta}</p>}
      </div>
      {aside && <div className="page-head-aside">{aside}</div>}
    </header>
  );
}
