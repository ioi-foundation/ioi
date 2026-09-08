import { IconArrow } from "./Icons.jsx";

// THE HOME WIDGET — the card shape a console home is made of.
//
// A bold title with a small "Info" link beside it (it opens the surface that holds
// the whole set, which is what a reader wants from "info" here), an outlined action
// pill on the right, the body, and a centred footer link. The read line — route,
// time, duration — sits under the footer in the meta face, so no figure stands
// without its source; it is the one thing this widget has that the reference does
// not, and it is the point of the product.
export default function Widget({ id, title, count, info, action, footer, read, span = 1, children }) {
  return (
    <section className={`widget widget-span-${span}`} aria-labelledby={`${id}-title`}>
      <header className="widget-bar">
        <h2 id={`${id}-title`} className="widget-title">
          {title}{typeof count === "number" ? <span className="widget-count"> ({count})</span> : null}
          {info && <a className="widget-info" href={info}>Info</a>}
        </h2>
        {action && <a className="pill" href={action.href}>{action.label}</a>}
      </header>
      <div className="widget-body">{children}</div>
      {(footer || read) && (
        <footer className="widget-foot">
          {footer && <a className="widget-foot-link" href={footer.href}>{footer.label} <IconArrow /></a>}
          {read && <p className="meta widget-read">{read}</p>}
        </footer>
      )}
    </section>
  );
}
