import React from "react";
import { createRoot } from "react-dom/client";
import "./design-system/styles.css";
import "./site/responsive.css";
import "./global.css";

window.React = React;

const PRODUCT_ROUTES = {
  "/hv-app": "app",
  "/hv-web": "web",
  "/hv-cli": "cli",
  "/hv-sdk": "sdk",
  "/hv-adk": "adk",
  "/hv-odk": "odk",
  "/hv-mcp": "mcp",
  "/hv-os": "os",
  "/hv-embodied": "embodied",
};

const PAGE_ROUTES = {
  "/platform": {
    active: "Platform",
    load: async () => {
      await import("./site/ProductData.jsx");
      await import("./site/PlatformApp.jsx");
      await import("./site/Platform.jsx");
      return window.HvPage;
    },
  },
  "/solutions": {
    active: "Solutions",
    load: async () => {
      await import("./site/Solutions.jsx");
      return window.HvPage;
    },
  },
  "/developers": {
    active: "Developers",
    load: async () => {
      await import("./site/Developers.jsx");
      return window.HvPage;
    },
  },
  "/pricing": {
    active: "Pricing",
    load: async () => {
      await import("./site/Pricing.jsx");
      return window.HvPage;
    },
  },
  "/background-work": {
    active: "Solutions",
    load: async () => {
      await import("./site/BackgroundWork.jsx");
      return window.HvPage;
    },
  },
  "/automations-fleets": {
    active: "Solutions",
    load: async () => {
      await import("./site/AutomationsFleets.jsx");
      return window.HvPage;
    },
  },
  "/code-modernization": {
    active: "Solutions",
    load: async () => {
      await import("./site/CodeModernization.jsx");
      return window.HvPage;
    },
  },
  "/code-review": {
    active: "Solutions",
    load: async () => {
      await import("./site/CodeReview.jsx");
      return window.HvPage;
    },
  },
  "/runtime-security": {
    active: "Solutions",
    load: async () => {
      await import("./site/RuntimeSecurity.jsx");
      return window.HvPage;
    },
  },
  "/worker-training": {
    active: "Solutions",
    load: async () => {
      await import("./site/WorkerTraining.jsx");
      return window.HvPage;
    },
  },
};

const pageCache = new Map();

function normalizePath(pathname) {
  let path = pathname.replace(/\/+$/, "") || "/";
  path = path.replace(/\.html$/, "");
  return path === "/index" ? "/" : path;
}

function linkToPath(href) {
  try {
    const url = new URL(href, window.location.href);
    if (url.origin !== window.location.origin) return null;
    if (url.hash && url.pathname === window.location.pathname) return null;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

async function loadFoundation() {
  await import("./design-system/_ds_bundle.js");
  await import("./site/HvDots.jsx");
  await import("./site/HvDepthField.jsx");
  await import("./site/HvOcta.jsx");
  await import("./site/HvDiagrams.jsx");
  await import("./site/RevealDiagram.jsx");
  await import("./site/WorkersMotion.jsx");
  await import("./site/Chrome.jsx");
}

function withChrome(Body, active) {
  return function ChromeRoute() {
    return (
      <>
        <window.HvHeader active={active} />
        <Body />
        <window.HvFooter />
      </>
    );
  };
}

async function loadHome() {
  await import("./site/HomeSections.jsx");
  return withChrome(window.HvHome, undefined);
}

async function loadDocs() {
  await import("./site/Docs.jsx");
  return window.HvDocs;
}

async function loadProduct(slug) {
  window.HV_CURRENT_SLUG = slug;
  await import("./site/ProductData.jsx");
  await import("./site/ProductPage.jsx");
  return withChrome(window.HvPage, "Platform");
}

async function loadRoute(pathname) {
  await loadFoundation();
  const path = normalizePath(pathname);

  if (path === "/") return loadHome();
  if (path === "/docs") return loadDocs();

  const productSlug = PRODUCT_ROUTES[path];
  if (productSlug) return loadProduct(productSlug);

  const pageRoute = PAGE_ROUTES[path];
  if (pageRoute) {
    if (!pageCache.has(path)) {
      const Body = await pageRoute.load();
      pageCache.set(path, withChrome(Body, pageRoute.active));
    }
    return pageCache.get(path);
  }

  return loadHome();
}

function HypervisorWebApp() {
  const [path, setPath] = React.useState(() => window.location.pathname);
  const [Route, setRoute] = React.useState(null);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    const onClick = (event) => {
      const anchor = event.target.closest?.("a[href]");
      if (!anchor || anchor.target || event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }

      const next = linkToPath(anchor.getAttribute("href"));
      if (!next) return;

      event.preventDefault();
      window.history.pushState({}, "", next);
      setPath(window.location.pathname);
      if (window.location.hash) {
        requestAnimationFrame(() => document.querySelector(window.location.hash)?.scrollIntoView());
      } else {
        window.scrollTo({ top: 0 });
      }
    };

    window.addEventListener("popstate", onPop);
    document.addEventListener("click", onClick);
    return () => {
      window.removeEventListener("popstate", onPop);
      document.removeEventListener("click", onClick);
    };
  }, []);

  React.useEffect(() => {
    let active = true;
    setError(null);

    loadRoute(path)
      .then((RouteComponent) => {
        if (active) setRoute(() => RouteComponent);
      })
      .catch((routeError) => {
        console.error(routeError);
        if (active) setError(routeError);
      });

    return () => {
      active = false;
    };
  }, [path]);

  if (error) {
    return <div className="hypervisor-web-error">Hypervisor Web failed to load this route.</div>;
  }

  if (!Route) {
    return <div className="hypervisor-web-loading">Loading Hypervisor Web...</div>;
  }

  return <Route />;
}

createRoot(document.getElementById("root")).render(<HypervisorWebApp />);
