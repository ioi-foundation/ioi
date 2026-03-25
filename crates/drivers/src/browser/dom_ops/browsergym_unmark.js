(() => {
    function popBidFromAttribute(elem, attr) {
        const bidRegex = /^browsergym_id[^\s]*\s/;
        if (elem.hasAttribute(attr)) {
            const content = elem.getAttribute(attr);
            const originalContent = content.replace(bidRegex, "");
            if (originalContent) {
                elem.setAttribute(attr, originalContent);
            } else {
                elem.removeAttribute(attr);
            }
        }
    }

    function cleanupDocument(doc) {
        let elements = Array.from(doc.querySelectorAll("*"));
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

            popBidFromAttribute(elem, "aria-description");
            popBidFromAttribute(elem, "aria-roledescription");

            if (elem.tagName && ["iframe", "frame"].includes(elem.tagName.toLowerCase())) {
                try {
                    const childDoc = elem.contentDocument;
                    if (childDoc && childDoc.documentElement) {
                        cleanupDocument(childDoc);
                    }
                } catch (_err) {
                    // Cross-origin or sandboxed frame.
                }
            }
        }
    }

    cleanupDocument(document);
    return true;
})()
