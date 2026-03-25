(() => {
    function deepActiveElement(root) {
        if (!root || !root.activeElement) {
            return null;
        }
        const activeElement = root.activeElement;
        if (activeElement.shadowRoot) {
            return deepActiveElement(activeElement.shadowRoot) || activeElement;
        }
        return activeElement;
    }

    function findFocusedBid(win) {
        if (!win || !win.document) {
            return "";
        }

        const activeElement = deepActiveElement(win.document);
        if (!activeElement) {
            return "";
        }

        try {
            if (activeElement.tagName && /^(iframe|frame)$/i.test(activeElement.tagName) && activeElement.contentWindow) {
                const childBid = findFocusedBid(activeElement.contentWindow);
                if (childBid) {
                    return childBid;
                }
            }
        } catch (_err) {
            // Cross-origin frame focus cannot be inspected from this context.
        }

        try {
            return activeElement.getAttribute("bid") || "";
        } catch (_err) {
            return "";
        }
    }

    return findFocusedBid(window);
})()
