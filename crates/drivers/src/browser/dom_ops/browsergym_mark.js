(async () => {
    const tagsToMark = "standard_html";
    const htmlTags = new Set([
        "a", "abbr", "acronym", "address", "applet", "area", "article", "aside", "audio",
        "b", "base", "basefont", "bdi", "bdo", "big", "blockquote", "body", "br", "button",
        "canvas", "caption", "center", "cite", "code", "col", "colgroup", "data", "datalist",
        "dd", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "em", "embed",
        "fieldset", "figcaption", "figure", "font", "footer", "form", "frame", "frameset",
        "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i",
        "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main",
        "map", "mark", "menu", "meta", "meter", "nav", "noframes", "noscript", "object",
        "ol", "optgroup", "option", "output", "p", "param", "picture", "pre", "progress",
        "q", "rp", "rt", "ruby", "s", "samp", "script", "search", "section", "select",
        "small", "source", "span", "strike", "strong", "style", "sub", "summary", "sup",
        "svg", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead",
        "time", "title", "tr", "track", "tt", "u", "ul", "var", "video", "wbr"
    ]);
    const setOfMarksTags = new Set([
        "input", "textarea", "select", "button", "a", "iframe", "video", "li", "td", "option"
    ]);

    function pushBidToAttribute(bid, elem, attr) {
        let originalContent = "";
        if (elem.hasAttribute(attr)) {
            originalContent = elem.getAttribute(attr);
        }
        elem.setAttribute(attr, `browsergym_id_${bid} ${originalContent}`);
    }

    function elementFromPointDeep(doc, x, y) {
        let currentDoc = doc;
        let lastElem = null;
        let elem = null;
        do {
            lastElem = elem;
            elem = currentDoc.elementFromPoint(x, y);
            currentDoc = elem && elem.shadowRoot ? elem.shadowRoot : null;
        } while (currentDoc && elem !== lastElem);
        return elem;
    }

    function whoCapturesCenterClick(element) {
        const rect = element.getBoundingClientRect();
        const x = (rect.left + rect.right) / 2;
        const y = (rect.top + rect.bottom) / 2;
        const elementAtCenter = elementFromPointDeep(element.ownerDocument, x, y);
        if (!elementAtCenter) {
            return "nobody";
        } else if (elementAtCenter === element) {
            return "self";
        } else if (element.contains(elementAtCenter)) {
            return "child";
        } else {
            return "non-descendant";
        }
    }

    async function until(predicate, timeout, interval = 40) {
        return new Promise((resolve, reject) => {
            const start = Date.now();
            if (predicate()) {
                resolve();
                return;
            }
            const timer = setInterval(() => {
                if (predicate()) {
                    clearInterval(timer);
                    resolve();
                } else if (Date.now() - start > timeout) {
                    clearInterval(timer);
                    reject(new Error("timeout"));
                }
            }, interval);
        });
    }

    class IFrameIdGenerator {
        constructor(chars = "abcdefghijklmnopqrstuvwxyz") {
            this._chars = chars;
            this._prefix = "";
            this._next = 0;
        }

        next() {
            const char = this._chars[this._next++];
            if (this._next >= this._chars.length) {
                this._next = 0;
                this._prefix = `${this._prefix}${this._chars[0].toUpperCase()}`;
            }
            return `${this._prefix}${char}`;
        }
    }

    async function markDocument(doc, parentBid) {
        const warnings = [];
        const view = doc.defaultView;
        if (!view) {
            return warnings;
        }

        let browsergymFirstVisit = false;
        if (!("browsergym_elem_counter" in view)) {
            view.browsergym_elem_counter = 0;
            view.browsergym_frame_id_generator = new IFrameIdGenerator();
            browsergymFirstVisit = true;
        }

        const elemsToBeVisited = new Set();
        const observer = new view.IntersectionObserver(
            entries => {
                entries.forEach(entry => {
                    const elem = entry.target;
                    elem.setAttribute("browsergym_visibility_ratio", Math.round(entry.intersectionRatio * 100) / 100);
                    elemsToBeVisited.delete(elem);
                });
            },
            {
                threshold: [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
            }
        );

        const allBids = new Set();
        let elements = Array.from(doc.querySelectorAll("*"));
        const somButtons = [];

        let i = 0;
        while (i < elements.length) {
            const elem = elements[i];
            if (elem.shadowRoot !== null) {
                elements = new Array(
                    ...Array.prototype.slice.call(elements, 0, i + 1),
                    ...Array.from(elem.shadowRoot.querySelectorAll("*")),
                    ...Array.prototype.slice.call(elements, i + 1)
                );
            }
            i++;

            switch (tagsToMark) {
                case "all":
                    break;
                case "standard_html":
                    if (!elem.tagName || !htmlTags.has(elem.tagName.toLowerCase())) {
                        continue;
                    }
                    break;
                default:
                    throw new Error(`Invalid tags_to_mark: ${JSON.stringify(tagsToMark)}`);
            }

            elem.setAttribute("browsergym_visibility_ratio", "0");
            elemsToBeVisited.add(elem);
            observer.observe(elem);

            if (typeof elem.value !== "undefined") {
                elem.setAttribute("value", elem.value);
            }
            if (typeof elem.checked !== "undefined") {
                if (elem.checked === true) {
                    elem.setAttribute("checked", "");
                } else {
                    elem.removeAttribute("checked");
                }
            }

            let elemGlobalBid = null;
            if (elem.hasAttribute("bid")) {
                if (browsergymFirstVisit) {
                    throw new Error(`Attribute bid already used in element ${elem.outerHTML}`);
                }
                elemGlobalBid = elem.getAttribute("bid");
                if (allBids.has(elemGlobalBid)) {
                    elemGlobalBid = null;
                }
            }
            if (elemGlobalBid === null) {
                let elemLocalId = null;
                if (["iframe", "frame"].includes(elem.tagName.toLowerCase())) {
                    elemLocalId = `${view.browsergym_frame_id_generator.next()}`;
                } else {
                    elemLocalId = `${view.browsergym_elem_counter++}`;
                }
                elemGlobalBid = parentBid === "" ? `${elemLocalId}` : `${parentBid}${elemLocalId}`;
                elem.setAttribute("bid", elemGlobalBid);
            }
            allBids.add(elemGlobalBid);

            pushBidToAttribute(elemGlobalBid, elem, "aria-roledescription");
            pushBidToAttribute(elemGlobalBid, elem, "aria-description");

            elem.setAttribute("browsergym_set_of_marks", "0");
            if (["self", "child"].includes(whoCapturesCenterClick(elem))) {
                if (
                    setOfMarksTags.has(elem.tagName.toLowerCase()) ||
                    elem.onclick != null ||
                    view.getComputedStyle(elem).cursor === "pointer"
                ) {
                    const rect = elem.getBoundingClientRect();
                    const area = (rect.right - rect.left) * (rect.bottom - rect.top);
                    if (area >= 20) {
                        if (somButtons.every(button => !button.contains(elem))) {
                            let parent = elem.parentElement;
                            const parentIsShadowSpanWrapper = (
                                parent &&
                                parent.tagName.toLowerCase() === "span" &&
                                parent.children.length === 1 &&
                                parent.getAttribute("role") &&
                                parent.getAttribute("browsergym_set_of_marks") === "1"
                            );
                            if (!parentIsShadowSpanWrapper) {
                                elem.setAttribute("browsergym_set_of_marks", "1");
                                if (elem.matches("button, a, input[type=\"button\"], div[role=\"button\"]")) {
                                    somButtons.push(elem);
                                }
                                while (parent) {
                                    if (parent.getAttribute("browsergym_set_of_marks") === "1") {
                                        parent.setAttribute("browsergym_set_of_marks", "0");
                                    }
                                    parent = parent.parentElement;
                                }
                            }
                        }
                    }
                }
            }

            if (elem.tagName && ["iframe", "frame"].includes(elem.tagName.toLowerCase())) {
                try {
                    const childDoc = elem.contentDocument;
                    if (childDoc && childDoc.documentElement) {
                        const childWarnings = await markDocument(childDoc, elemGlobalBid);
                        warnings.push(...childWarnings);
                    }
                } catch (_err) {
                    // Cross-origin or sandboxed frame; AXTree extraction will still see it.
                }
            }
        }

        try {
            await until(() => elemsToBeVisited.size === 0, 1000);
        } catch (_err) {
            warnings.push("Frame marking: not all elements were visited by the intersection observer within 1000 ms");
        }
        observer.disconnect();
        return warnings;
    }

    return markDocument(document, "");
})()
