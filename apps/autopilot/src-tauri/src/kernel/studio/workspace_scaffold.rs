use crate::models::StudioArtifactMaterializationFileWrite;
use std::fs;
use std::path::{Path, PathBuf};
use tauri::AppHandle;

pub(super) fn workspace_root_for(app: &AppHandle, studio_session_id: &str) -> PathBuf {
    crate::autopilot_data_dir_for(app)
        .join("studio-artifacts")
        .join(studio_session_id)
        .join("workspace")
}

pub(super) fn package_name_for_title(title: &str) -> String {
    let mut slug = title
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "studio-artifact".to_string()
    } else if slug.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        format!("studio-{}", slug)
    } else {
        slug
    }
}

pub(super) struct ScaffoldResult {
    pub(super) file_writes: Vec<StudioArtifactMaterializationFileWrite>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StudioScaffoldRecipe {
    ReactVite,
    StaticHtmlVite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StudioStaticHtmlArchetype {
    SportEditorial,
    MinimalAgency,
    HospitalityRetreat,
    ProductLaunch,
}

impl StudioScaffoldRecipe {
    pub(super) fn id(self) -> &'static str {
        match self {
            Self::ReactVite => "react-vite",
            Self::StaticHtmlVite => "vite-static-html",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ReactVite => "react-vite",
            Self::StaticHtmlVite => "vite-static-html",
        }
    }

    pub(super) fn entry_document(self) -> &'static str {
        match self {
            Self::ReactVite => "src/App.tsx",
            Self::StaticHtmlVite => "index.html",
        }
    }
}

impl StudioStaticHtmlArchetype {
    fn id(self) -> &'static str {
        match self {
            Self::SportEditorial => "sport-editorial",
            Self::MinimalAgency => "minimal-agency",
            Self::HospitalityRetreat => "hospitality-retreat",
            Self::ProductLaunch => "product-launch",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::SportEditorial => "Sport editorial",
            Self::MinimalAgency => "Minimal agency",
            Self::HospitalityRetreat => "Hospitality retreat",
            Self::ProductLaunch => "Product launch",
        }
    }
}

pub(super) fn mutation_scope_for_recipe(root: &Path, recipe: StudioScaffoldRecipe) -> Vec<String> {
    let mut scope = vec![
        root.to_string_lossy().to_string(),
        "package.json".to_string(),
    ];
    match recipe {
        StudioScaffoldRecipe::ReactVite => {
            scope.extend(
                ["src", "vite.config.ts", "index.html"]
                    .iter()
                    .map(|path| (*path).to_string()),
            );
        }
        StudioScaffoldRecipe::StaticHtmlVite => {
            scope.extend(
                ["index.html", "styles.css", "script.js"]
                    .iter()
                    .map(|path| (*path).to_string()),
            );
        }
    }
    scope
}

pub(super) fn scaffold_workspace(
    recipe: StudioScaffoldRecipe,
    static_html_archetype: Option<StudioStaticHtmlArchetype>,
    root: &Path,
    title: &str,
    package_name: &str,
) -> Result<ScaffoldResult, String> {
    if root.exists() {
        fs::remove_dir_all(root).map_err(|error| {
            format!(
                "Failed to replace existing workspace root '{}': {}",
                root.display(),
                error
            )
        })?;
    }

    let files = template_files_for_recipe(recipe, static_html_archetype, title, package_name);
    let mut file_writes = Vec::new();
    for (relative_path, content) in files {
        let path = root.join(&relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create '{}': {}", parent.display(), error))?;
        }
        fs::write(&path, content.as_bytes())
            .map_err(|error| format!("Failed to write '{}': {}", path.display(), error))?;
        file_writes.push(StudioArtifactMaterializationFileWrite {
            path: relative_path,
            kind: "write".to_string(),
            content_preview: Some(content.lines().take(3).collect::<Vec<_>>().join(" ")),
        });
    }

    Ok(ScaffoldResult { file_writes })
}

fn template_files_for_recipe(
    recipe: StudioScaffoldRecipe,
    static_html_archetype: Option<StudioStaticHtmlArchetype>,
    title: &str,
    package_name: &str,
) -> Vec<(String, String)> {
    match recipe {
        StudioScaffoldRecipe::ReactVite => react_vite_template_files(title, package_name),
        StudioScaffoldRecipe::StaticHtmlVite => {
            static_html_template_files(title, package_name, static_html_archetype)
        }
    }
}

fn react_vite_template_files(title: &str, package_name: &str) -> Vec<(String, String)> {
    vec![
        (
            "package.json".to_string(),
            format!(
                "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{\n    \"dev\": \"vite\",\n    \"build\": \"tsc -b && vite build\",\n    \"preview\": \"vite preview\"\n  }},\n  \"dependencies\": {{\n    \"react\": \"^18.3.1\",\n    \"react-dom\": \"^18.3.1\"\n  }},\n  \"devDependencies\": {{\n    \"@types/react\": \"^18.3.18\",\n    \"@types/react-dom\": \"^18.3.5\",\n    \"@vitejs/plugin-react\": \"^4.3.4\",\n    \"typescript\": \"^5.6.2\",\n    \"vite\": \"^6.0.5\"\n  }}\n}}\n"
            ),
        ),
        (
            "tsconfig.json".to_string(),
            "{\n  \"files\": [],\n  \"references\": [\n    { \"path\": \"./tsconfig.app.json\" },\n    { \"path\": \"./tsconfig.node.json\" }\n  ]\n}\n"
                .to_string(),
        ),
        (
            "tsconfig.app.json".to_string(),
            "{\n  \"compilerOptions\": {\n    \"target\": \"ES2020\",\n    \"useDefineForClassFields\": true,\n    \"lib\": [\"ES2020\", \"DOM\", \"DOM.Iterable\"],\n    \"allowJs\": false,\n    \"skipLibCheck\": true,\n    \"esModuleInterop\": true,\n    \"allowSyntheticDefaultImports\": true,\n    \"strict\": true,\n    \"forceConsistentCasingInFileNames\": true,\n    \"module\": \"ESNext\",\n    \"moduleResolution\": \"Node\",\n    \"resolveJsonModule\": true,\n    \"isolatedModules\": true,\n    \"noEmit\": true,\n    \"jsx\": \"react-jsx\"\n  },\n  \"include\": [\"src\"],\n  \"exclude\": [\"src/**/*.test.*\"]\n}\n"
                .to_string(),
        ),
        (
            "tsconfig.node.json".to_string(),
            "{\n  \"compilerOptions\": {\n    \"composite\": true,\n    \"skipLibCheck\": true,\n    \"module\": \"ESNext\",\n    \"moduleResolution\": \"Node\",\n    \"allowSyntheticDefaultImports\": true\n  },\n  \"include\": [\"vite.config.ts\"]\n}\n"
                .to_string(),
        ),
        (
            "vite.config.ts".to_string(),
            "import { defineConfig } from 'vite'\nimport react from '@vitejs/plugin-react'\n\nexport default defineConfig({\n  plugins: [react()],\n})\n".to_string(),
        ),
        (
            "index.html".to_string(),
            format!(
                "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"UTF-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n    <title>{title}</title>\n  </head>\n  <body>\n    <div id=\"root\"></div>\n    <script type=\"module\" src=\"/src/main.tsx\"></script>\n  </body>\n</html>\n"
            ),
        ),
        (
            "src/main.tsx".to_string(),
            "import React from 'react'\nimport ReactDOM from 'react-dom/client'\nimport App from './App'\nimport './index.css'\n\nReactDOM.createRoot(document.getElementById('root')!).render(\n  <React.StrictMode>\n    <App />\n  </React.StrictMode>,\n)\n".to_string(),
        ),
        (
            "src/App.tsx".to_string(),
            format!(
                "import './App.css'\n\nexport default function App() {{\n  return (\n    <main className=\"shell\">\n      <section className=\"hero\">\n        <p className=\"eyebrow\">Studio artifact</p>\n        <h1>{title}</h1>\n        <p className=\"copy\">\n          A deterministic react-vite starter created under kernel supervision so Studio can move straight into a real implementation workspace.\n        </p>\n      </section>\n\n      <section className=\"grid\">\n        <article>\n          <h2>Preview first</h2>\n          <p>When preview is healthy, Studio can lead with the live surface instead of a raw file tree.</p>\n        </article>\n        <article>\n          <h2>Code when needed</h2>\n          <p>The workspace remains an embedded subsystem that opens only when the artifact needs implementation depth.</p>\n        </article>\n        <article>\n          <h2>Receipts included</h2>\n          <p>Scaffold, install, build, and preview verification each capture their own receipt trail.</p>\n        </article>\n      </section>\n    </main>\n  )\n}}\n"
            ),
        ),
        (
            "src/App.css".to_string(),
            ".shell {\n  min-height: 100vh;\n  padding: 4rem clamp(1.5rem, 4vw, 4rem);\n  background: radial-gradient(circle at top left, rgba(85, 120, 255, 0.18), transparent 24%), #0b1020;\n  color: #f4f7fb;\n  font-family: Inter, system-ui, sans-serif;\n}\n\n.hero {\n  max-width: 52rem;\n  display: grid;\n  gap: 1rem;\n}\n\n.eyebrow {\n  margin: 0;\n  text-transform: uppercase;\n  letter-spacing: 0.18em;\n  font-size: 0.75rem;\n  color: rgba(244, 247, 251, 0.72);\n}\n\nh1 {\n  margin: 0;\n  font-size: clamp(2.8rem, 6vw, 5rem);\n  line-height: 0.96;\n}\n\n.copy {\n  margin: 0;\n  max-width: 42rem;\n  color: rgba(244, 247, 251, 0.8);\n  font-size: 1.05rem;\n}\n\n.grid {\n  margin-top: 3rem;\n  display: grid;\n  gap: 1rem;\n  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));\n}\n\n.grid article {\n  padding: 1.25rem;\n  border: 1px solid rgba(244, 247, 251, 0.12);\n  border-radius: 1rem;\n  background: rgba(14, 21, 40, 0.72);\n}\n\n.grid h2 {\n  margin: 0 0 0.5rem;\n  font-size: 1.05rem;\n}\n\n.grid p {\n  margin: 0;\n  color: rgba(244, 247, 251, 0.74);\n  line-height: 1.55;\n}\n".to_string(),
        ),
        (
            "src/index.css".to_string(),
            ":root {\n  color-scheme: dark;\n  font-family: Inter, system-ui, sans-serif;\n  line-height: 1.5;\n  font-weight: 400;\n  background: #0b1020;\n  color: #f4f7fb;\n  font-synthesis: none;\n  text-rendering: optimizeLegibility;\n  -webkit-font-smoothing: antialiased;\n  -moz-osx-font-smoothing: grayscale;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml, body, #root {\n  margin: 0;\n  min-height: 100%;\n}\n\nbody {\n  min-width: 320px;\n}\n".to_string(),
        ),
    ]
}

struct StaticHtmlTemplate {
    html: String,
    styles: String,
    script: String,
}

pub(super) fn static_html_template_files(
    title: &str,
    package_name: &str,
    archetype: Option<StudioStaticHtmlArchetype>,
) -> Vec<(String, String)> {
    let archetype = archetype.unwrap_or(StudioStaticHtmlArchetype::MinimalAgency);
    let brand = themed_brand_for_static_html(title, archetype);
    let template = static_html_template(archetype, &brand, title);

    vec![
        (
            "package.json".to_string(),
            format!(
                "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{\n    \"dev\": \"vite\",\n    \"build\": \"vite build\",\n    \"preview\": \"vite preview\"\n  }},\n  \"devDependencies\": {{\n    \"vite\": \"^6.0.5\"\n  }}\n}}\n"
            ),
        ),
        ("index.html".to_string(), template.html),
        ("styles.css".to_string(), template.styles),
        ("script.js".to_string(), template.script),
    ]
}

pub(super) fn parse_static_html_archetype_id(id: &str) -> Option<StudioStaticHtmlArchetype> {
    match id {
        "sport-editorial" => Some(StudioStaticHtmlArchetype::SportEditorial),
        "minimal-agency" => Some(StudioStaticHtmlArchetype::MinimalAgency),
        "hospitality-retreat" => Some(StudioStaticHtmlArchetype::HospitalityRetreat),
        "product-launch" => Some(StudioStaticHtmlArchetype::ProductLaunch),
        _ => None,
    }
}

fn themed_brand_for_static_html(title: &str, archetype: StudioStaticHtmlArchetype) -> String {
    let seed = title.bytes().fold(0u64, |acc, byte| {
        acc.wrapping_mul(16777619).wrapping_add(byte as u64)
    });
    let options: &[&str] = match archetype {
        StudioStaticHtmlArchetype::SportEditorial => {
            &["VOLÉE CLUB", "Baseline House", "Matchline Court"]
        }
        StudioStaticHtmlArchetype::MinimalAgency => {
            &["Northline Atelier", "Meridian Office", "Field Assembly"]
        }
        StudioStaticHtmlArchetype::HospitalityRetreat => {
            &["Dune House", "Solmar Retreat", "Cedar Coast"]
        }
        StudioStaticHtmlArchetype::ProductLaunch => &["Signal OS", "Orbit Stack", "Array One"],
    };

    options[(seed as usize) % options.len()].to_string()
}

fn static_html_template(
    archetype: StudioStaticHtmlArchetype,
    brand: &str,
    title: &str,
) -> StaticHtmlTemplate {
    let (html, styles) = match archetype {
        StudioStaticHtmlArchetype::SportEditorial => (
            r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="__TITLE__" />
    <title>__BRAND__</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body class="theme-sport-editorial">
    <div class="page-shell">
      <header class="site-header">
        <div class="brand-mark">
          <span class="brand-ball"></span>
          <span>__BRAND__</span>
        </div>
        <nav class="site-nav" aria-label="Primary">
          <a href="#collections">Collections</a>
          <a href="#technology">Technology</a>
          <a href="#athletes">Athletes</a>
          <a href="#visit">Visit</a>
        </nav>
        <a class="site-cta" href="#visit">Book a session</a>
      </header>
      <main>
        <section class="hero">
          <div class="hero-copy" data-reveal>
            <p class="eyebrow">Season 2026 collection</p>
            <h1>Every point<br /><span>earned.</span></h1>
            <p class="lead">A premium club landing page with match-night energy, performance storytelling, and a direct path from atmosphere to booking.</p>
            <div class="hero-actions">
              <a class="button is-primary" href="#collections">Explore collection</a>
              <a class="button" href="#technology">Our technology</a>
            </div>
          </div>
          <div class="hero-visual" aria-hidden="true">
            <div class="orbital-ring ring-one"></div>
            <div class="orbital-ring ring-two"></div>
            <div class="orbital-ring ring-three"></div>
            <div class="court-card" data-reveal>
              <p>Match-day systems</p>
              <strong>Carbon rackets. Smart analytics. Club hospitality.</strong>
            </div>
          </div>
        </section>
        <section class="stat-bar" data-reveal>
          <article><strong>12</strong><span>Indoor courts</span></article>
          <article><strong>94%</strong><span>Member retention</span></article>
          <article><strong>4.9</strong><span>Match-day rating</span></article>
        </section>
        <section class="feature-grid" id="collections">
          <article class="feature-card" data-reveal>
            <p class="eyebrow">Collection</p>
            <h2>Editorial storefront energy</h2>
            <p>Luxury-sport visuals, kinetic highlights, and hero-led copy that makes the page feel campaign-ready on the first pass.</p>
          </article>
          <article class="feature-card" data-reveal>
            <p class="eyebrow">Programs</p>
            <h2>High-performance coaching</h2>
            <p>Private training, junior academies, and event programming organized around competitive development.</p>
          </article>
          <article class="feature-card" data-reveal>
            <p class="eyebrow">Events</p>
            <h2>Night sessions with cinematic contrast</h2>
            <p>Launch nights, sponsor matches, and member experiences framed like a premium campaign instead of a brochure.</p>
          </article>
        </section>
        <section class="technology" id="technology">
          <div class="technology-copy" data-reveal>
            <p class="eyebrow">Technology</p>
            <h2>Built around the rhythm of the court.</h2>
            <p>Animated court geometry, metrics, and responsive sections give the page an intentional athletic pulse without drowning the core story.</p>
          </div>
          <div class="technology-panel" data-reveal>
            <div class="court-diagram">
              <span></span><span></span><span></span><span></span>
            </div>
            <ul>
              <li><strong>Trajectory overlays</strong><span>Responsive editorial motion</span></li>
              <li><strong>Club booking CTA</strong><span>Built for conversion above the fold</span></li>
              <li><strong>Booking-first journey</strong><span>Move from hero to reservation without friction</span></li>
            </ul>
          </div>
        </section>
        <section class="testimonials" id="athletes">
          <article data-reveal>
            <p>"The page already feels like a campaign launch, not a placeholder waiting to become one."</p>
            <span>Operations lead, premium racquet club</span>
          </article>
          <article data-reveal>
            <p>"The hierarchy is sharp, the motion feels intentional, and the club story lands in a single glance."</p>
            <span>Creative director, performance brand</span>
          </article>
        </section>
        <section class="closing-banner" id="visit" data-reveal>
          <div>
            <p class="eyebrow">Visit the club</p>
            <h2>Launch a landing page that already looks match-ready.</h2>
          </div>
          <a class="button is-primary" href="mailto:hello@example.com">Book a walkthrough</a>
        </section>
      </main>
    </div>
    <script type="module" src="/script.js"></script>
  </body>
</html>"##,
            r#"*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #090909;
  --bg-2: #111111;
  --text: #f3ecdf;
  --muted: rgba(243, 236, 223, 0.72);
  --line: rgba(185, 255, 0, 0.14);
  --accent: #b8ff1a;
  --shadow: 0 24px 80px rgba(0, 0, 0, 0.42);
  color-scheme: dark;
}
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-width: 320px;
  background:
    radial-gradient(circle at 12% 16%, rgba(184, 255, 26, 0.12), transparent 22%),
    radial-gradient(circle at 85% 18%, rgba(255, 255, 255, 0.05), transparent 18%),
    linear-gradient(180deg, #090909 0%, #0f0f0f 100%);
  color: var(--text);
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
  background-size: 120px 120px;
  mask-image: radial-gradient(circle at center, black, transparent 78%);
}
.page-shell { width: min(1200px, calc(100vw - 40px)); margin: 0 auto; padding: 24px 0 80px; }
.site-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 12px 0 18px;
  border-bottom: 1px solid var(--line);
}
.brand-mark {
  display: inline-flex;
  align-items: center;
  gap: 14px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.brand-ball {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 2px solid var(--accent);
  box-shadow: inset 0 0 0 5px rgba(184, 255, 26, 0.14);
}
.site-nav { display: flex; gap: 28px; }
.site-nav a, .site-cta, .button { color: inherit; text-decoration: none; }
.site-nav a {
  color: var(--muted);
  font-size: 0.92rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.site-cta, .button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 999px;
  border: 1px solid rgba(243, 236, 223, 0.16);
  padding: 0.95rem 1.4rem;
  font-weight: 600;
  transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
}
.site-cta, .button.is-primary { background: var(--accent); color: #101010; border-color: var(--accent); }
.button:hover, .site-cta:hover, .site-nav a:hover { transform: translateY(-1px); }
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(320px, 0.95fr);
  gap: 36px;
  padding: 72px 0 44px;
  min-height: 70vh;
  align-items: center;
}
.hero-copy { max-width: 640px; }
.eyebrow {
  margin: 0 0 18px;
  color: var(--accent);
  font-size: 0.84rem;
  font-weight: 700;
  letter-spacing: 0.34em;
  text-transform: uppercase;
}
h1, h2 { margin: 0; font-family: Georgia, "Times New Roman", serif; letter-spacing: -0.04em; }
.hero h1 { font-size: clamp(3.4rem, 8vw, 6.8rem); line-height: 0.92; }
.hero h1 span { color: var(--accent); font-style: italic; }
.lead { margin: 24px 0 0; max-width: 560px; color: var(--muted); font-size: 1.15rem; line-height: 1.75; }
.hero-actions { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 30px; }
.hero-visual { position: relative; min-height: 520px; }
.orbital-ring { position: absolute; inset: auto 0 0 auto; border-radius: 50%; border: 1px solid rgba(184, 255, 26, 0.08); }
.ring-one { width: 520px; height: 520px; top: 0; right: 0; }
.ring-two { width: 410px; height: 410px; top: 54px; right: 55px; }
.ring-three { width: 290px; height: 290px; top: 115px; right: 116px; }
.court-card, .feature-card, .technology-panel, .testimonials article, .stat-bar, .closing-banner {
  background: linear-gradient(180deg, rgba(20, 20, 20, 0.98), rgba(12, 12, 12, 0.9));
  border: 1px solid rgba(243, 236, 223, 0.08);
  box-shadow: var(--shadow);
}
.court-card { position: absolute; left: 10%; bottom: 8%; width: min(340px, 80%); padding: 24px; border-radius: 28px; }
.court-card p, .feature-card p, .technology-copy p, .technology-panel li span, .testimonials span, .closing-banner p { color: var(--muted); }
.court-card strong, .feature-card h2, .technology-copy h2, .closing-banner h2 { display: block; margin-top: 8px; font-size: clamp(1.4rem, 2vw, 2.6rem); line-height: 1.04; }
.stat-bar { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; margin: 8px 0 28px; border-radius: 26px; overflow: hidden; }
.stat-bar article { padding: 26px; background: rgba(10, 10, 10, 0.9); }
.stat-bar strong { display: block; margin-bottom: 6px; font-size: clamp(2rem, 4vw, 3rem); color: var(--accent); }
.feature-grid, .testimonials { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 20px; margin-top: 32px; }
.feature-card, .testimonials article { border-radius: 26px; padding: 26px; }
.technology { display: grid; grid-template-columns: minmax(0, 1fr) minmax(340px, 0.9fr); gap: 28px; margin-top: 32px; align-items: stretch; }
.technology-panel { border-radius: 28px; padding: 28px; }
.court-diagram { position: relative; height: 220px; margin-bottom: 22px; border-radius: 26px; border: 1px solid rgba(184, 255, 26, 0.12); overflow: hidden; }
.court-diagram::before, .court-diagram::after, .court-diagram span { content: ""; position: absolute; inset: 0; }
.court-diagram::before { inset: 16px; border: 1px solid rgba(243, 236, 223, 0.18); }
.court-diagram::after { left: 50%; width: 1px; background: rgba(243, 236, 223, 0.18); transform: translateX(-50%); }
.court-diagram span:nth-child(1) { inset: 16px auto 16px 50%; width: 1px; background: rgba(243,236,223,0.18); transform: translateX(-50%); }
.court-diagram span:nth-child(2) { inset: 50% 16px auto 16px; height: 1px; background: rgba(243,236,223,0.18); transform: translateY(-50%); }
.court-diagram span:nth-child(3) { inset: 16px 28% 16px 28%; border-left: 1px solid rgba(243,236,223,0.18); border-right: 1px solid rgba(243,236,223,0.18); }
.court-diagram span:nth-child(4) { width: 18px; height: 18px; inset: 50% auto auto 50%; transform: translate(-50%, -50%); border-radius: 50%; background: var(--accent); box-shadow: 0 0 0 10px rgba(184,255,26,0.16); }
.technology-panel ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
.technology-panel li { display: flex; justify-content: space-between; gap: 18px; padding-top: 16px; border-top: 1px solid rgba(243, 236, 223, 0.08); }
.technology-panel strong { max-width: 220px; }
.closing-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 28px 32px;
  border-radius: 28px;
  margin-top: 32px;
}
@media (max-width: 1100px) {
  .hero, .technology, .feature-grid, .testimonials { grid-template-columns: 1fr; }
  .hero-visual { min-height: 420px; }
}
@media (max-width: 820px) {
  .page-shell { width: min(100vw - 24px, 1200px); padding-top: 16px; }
  .site-header, .closing-banner, .stat-bar { grid-template-columns: 1fr; display: grid; }
  .site-nav { flex-wrap: wrap; gap: 14px 18px; }
  .hero { padding-top: 44px; }
  .court-card { position: relative; left: auto; bottom: auto; width: 100%; margin-top: 240px; }
}"#,
        ),
        StudioStaticHtmlArchetype::MinimalAgency => (
            r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="__TITLE__" />
    <title>__BRAND__</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body class="theme-minimal-agency">
    <div class="agency-shell">
      <header class="agency-header">
        <span class="agency-brand">__BRAND__</span>
        <nav aria-label="Primary">
          <a href="#services">Services</a>
          <a href="#approach">Approach</a>
          <a href="#contact">Contact</a>
        </nav>
      </header>
      <main>
        <section class="agency-hero">
          <div class="agency-hero-copy" data-reveal>
            <p class="agency-kicker">Independent studio practice</p>
            <h1>Clear positioning,<br />strong first impression.</h1>
            <p>__BRAND__ turns a service brief into a confident landing page with editorial pacing, disciplined hierarchy, and one clean call to action.</p>
            <div class="agency-actions">
              <a class="agency-button is-solid" href="#contact">Start a project</a>
              <a class="agency-button" href="#services">See the structure</a>
            </div>
          </div>
          <aside class="agency-manifest" data-reveal>
            <span>Scope</span>
            <strong>Hero, offer, proof, detail, final CTA.</strong>
            <p>The artifact lands as a real HTML workspace and can keep evolving in preview or code without pretending the work is only a note card.</p>
          </aside>
        </section>
        <section class="agency-strip" id="services" data-reveal>
          <div>
            <span>01</span>
            <h2>Offer design</h2>
            <p>Lead with the promise before the process.</p>
          </div>
          <div>
            <span>02</span>
            <h2>Editorial pacing</h2>
            <p>Let the page read like one calm argument.</p>
          </div>
          <div>
            <span>03</span>
            <h2>Conversion close</h2>
            <p>Move from proof to action without extra chrome.</p>
          </div>
        </section>
        <section class="agency-columns" id="approach">
          <div class="agency-statement" data-reveal>
            <p class="agency-kicker">Approach</p>
            <h2>One dominant idea per section, no filler.</h2>
            <p>Instead of a stack of generic cards, the layout uses strong type, divided columns, and quiet spacing to keep the offer legible in seconds.</p>
          </div>
          <div class="agency-list" data-reveal>
            <article>
              <strong>Brand framing</strong>
              <p>Set the voice, the promise, and the audience in the first viewport.</p>
            </article>
            <article>
              <strong>Selective proof</strong>
              <p>Use three precise sections instead of a dashboard of interchangeable boxes.</p>
            </article>
            <article>
              <strong>Launch ready</strong>
              <p>Hand the page straight into preview, code, and refinement without changing surfaces.</p>
            </article>
          </div>
        </section>
        <section class="agency-cta" id="contact" data-reveal>
          <p class="agency-kicker">Contact</p>
          <div>
            <h2>Make the next launch page feel authored, not assembled.</h2>
            <a class="agency-button is-solid" href="mailto:hello@example.com">Book a working session</a>
          </div>
        </section>
      </main>
    </div>
    <script type="module" src="/script.js"></script>
  </body>
</html>"##,
            r#"*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #f4efe7;
  --surface: rgba(255, 255, 255, 0.72);
  --text: #121212;
  --muted: rgba(18, 18, 18, 0.66);
  --line: rgba(18, 18, 18, 0.12);
  --accent: #3558ff;
  color-scheme: light;
}
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-width: 320px;
  background:
    radial-gradient(circle at top left, rgba(53, 88, 255, 0.08), transparent 28%),
    linear-gradient(180deg, #f7f2eb 0%, #f1ebe3 100%);
  color: var(--text);
  font-family: "Inter", "Segoe UI", Arial, sans-serif;
}
.agency-shell { width: min(1240px, calc(100vw - 48px)); margin: 0 auto; padding: 28px 0 72px; }
.agency-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--line);
}
.agency-brand { font-weight: 700; letter-spacing: -0.04em; font-size: 1.12rem; }
.agency-header nav { display: flex; gap: 22px; }
.agency-header a, .agency-button { text-decoration: none; color: inherit; }
.agency-header a { color: var(--muted); font-size: 0.95rem; }
.agency-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(260px, 0.55fr);
  gap: 28px;
  min-height: calc(100vh - 180px);
  align-items: end;
  padding: 54px 0 48px;
}
.agency-kicker {
  margin: 0 0 18px;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.24em;
  color: var(--muted);
}
.agency-hero h1, .agency-statement h2, .agency-cta h2 {
  margin: 0;
  font-family: "Georgia", serif;
  font-weight: 600;
  letter-spacing: -0.05em;
  line-height: 0.92;
}
.agency-hero h1 { font-size: clamp(3.8rem, 8vw, 7.2rem); max-width: 10ch; }
.agency-hero p { max-width: 48ch; margin: 24px 0 0; color: var(--muted); font-size: 1.1rem; line-height: 1.7; }
.agency-actions { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 30px; }
.agency-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 48px;
  padding: 0 18px;
  border-radius: 999px;
  border: 1px solid var(--line);
  transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
}
.agency-button.is-solid { background: var(--text); color: white; border-color: var(--text); }
.agency-button:hover { transform: translateY(-1px); }
.agency-manifest {
  align-self: stretch;
  display: grid;
  gap: 14px;
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: 24px;
  background: var(--surface);
  backdrop-filter: blur(12px);
}
.agency-manifest span { color: var(--muted); text-transform: uppercase; letter-spacing: 0.22em; font-size: 0.72rem; }
.agency-manifest strong { font-size: 1.5rem; line-height: 1.08; }
.agency-manifest p { margin: 0; color: var(--muted); line-height: 1.65; }
.agency-strip {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 22px;
  padding: 22px 0 30px;
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}
.agency-strip div { padding-right: 10px; }
.agency-strip span { display: block; margin-bottom: 20px; color: var(--muted); font-size: 0.82rem; }
.agency-strip h2 { margin: 0 0 10px; font-size: 1.4rem; letter-spacing: -0.04em; }
.agency-strip p { margin: 0; color: var(--muted); line-height: 1.6; }
.agency-columns {
  display: grid;
  grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr);
  gap: 30px;
  padding: 54px 0;
}
.agency-statement h2 { font-size: clamp(2.4rem, 5vw, 4.4rem); max-width: 11ch; }
.agency-statement p { max-width: 46ch; margin: 20px 0 0; color: var(--muted); line-height: 1.7; }
.agency-list {
  display: grid;
  gap: 18px;
}
.agency-list article {
  padding-top: 18px;
  border-top: 1px solid var(--line);
}
.agency-list strong { display: block; font-size: 1.05rem; }
.agency-list p { margin: 8px 0 0; color: var(--muted); line-height: 1.65; }
.agency-cta {
  display: grid;
  gap: 18px;
  padding-top: 34px;
  border-top: 1px solid var(--line);
}
.agency-cta > div {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
}
.agency-cta h2 { font-size: clamp(2.4rem, 5vw, 4rem); max-width: 12ch; }
@media (max-width: 980px) {
  .agency-hero, .agency-strip, .agency-columns, .agency-cta > div { grid-template-columns: 1fr; display: grid; }
}
@media (max-width: 760px) {
  .agency-shell { width: min(100vw - 24px, 1240px); }
  .agency-header { flex-direction: column; align-items: flex-start; }
  .agency-header nav { flex-wrap: wrap; }
}"#,
        ),
        StudioStaticHtmlArchetype::HospitalityRetreat => (
            r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="__TITLE__" />
    <title>__BRAND__</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body class="theme-hospitality-retreat">
    <div class="retreat-shell">
      <header class="retreat-header">
        <span class="retreat-brand">__BRAND__</span>
        <nav aria-label="Primary">
          <a href="#stay">Stay</a>
          <a href="#rituals">Rituals</a>
          <a href="#visit">Visit</a>
        </nav>
      </header>
      <main>
        <section class="retreat-hero">
          <div class="retreat-hero-copy" data-reveal>
            <p class="retreat-kicker">Desert quiet, coastal light</p>
            <h1>Stay somewhere that feels slower on purpose.</h1>
            <p>__BRAND__ is framed as a boutique retreat with a warm editorial hero, a booking-minded flow, and enough atmosphere to feel like a destination before the first photograph arrives.</p>
            <a class="retreat-button" href="#visit">Plan your stay</a>
          </div>
          <aside class="retreat-booking" data-reveal>
            <span>Weekend escape</span>
            <strong>Three-night reset with private dining, courtyard suites, and a sunrise wellness ritual.</strong>
            <a href="mailto:hello@example.com">Reserve dates</a>
          </aside>
        </section>
        <section class="retreat-grid" id="stay">
          <article data-reveal>
            <p class="retreat-kicker">Suites</p>
            <h2>Textured rooms with soft morning light.</h2>
            <p>Use a calm palette, oversized type, and layered surfaces so the page reads like a destination brochure without looking generic.</p>
          </article>
          <article data-reveal>
            <p class="retreat-kicker">Dining</p>
            <h2>Seasonal menus, courtyard service, long evenings.</h2>
            <p>Keep the copy spare and the pacing slow enough that each section feels like part of the stay.</p>
          </article>
        </section>
        <section class="retreat-rituals" id="rituals">
          <div class="retreat-image-block" data-reveal></div>
          <div class="retreat-ritual-copy" data-reveal>
            <p class="retreat-kicker">Rituals</p>
            <h2>Recovery, movement, and the sound of an open courtyard.</h2>
            <ul>
              <li><strong>Dawn sessions</strong><span>Open-air mobility and guided breathwork</span></li>
              <li><strong>Kitchen table service</strong><span>Slow dinners with a local produce menu</span></li>
              <li><strong>Private terraces</strong><span>Quiet corners built for late-afternoon light</span></li>
            </ul>
          </div>
        </section>
        <section class="retreat-cta" id="visit" data-reveal>
          <div>
            <p class="retreat-kicker">Visit</p>
            <h2>Make the site feel like the first night of the stay.</h2>
          </div>
          <a class="retreat-button" href="mailto:hello@example.com">Request availability</a>
        </section>
      </main>
    </div>
    <script type="module" src="/script.js"></script>
  </body>
</html>"##,
            r#"*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #efe4d6;
  --sand: #d6b693;
  --cream: #faf5ed;
  --ink: #2e241d;
  --muted: rgba(46, 36, 29, 0.68);
  --line: rgba(46, 36, 29, 0.14);
  color-scheme: light;
}
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-width: 320px;
  background:
    radial-gradient(circle at 20% 10%, rgba(214, 182, 147, 0.34), transparent 26%),
    linear-gradient(180deg, #f7efe5 0%, #eee0cf 100%);
  color: var(--ink);
  font-family: "Inter", "Segoe UI", Arial, sans-serif;
}
.retreat-shell { width: min(1240px, calc(100vw - 40px)); margin: 0 auto; padding: 24px 0 72px; }
.retreat-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding-bottom: 18px;
}
.retreat-brand {
  font-family: "Georgia", serif;
  font-size: 1.38rem;
  letter-spacing: -0.04em;
}
.retreat-header nav { display: flex; gap: 22px; }
.retreat-header a, .retreat-button { color: inherit; text-decoration: none; }
.retreat-header a { color: var(--muted); }
.retreat-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(280px, 0.7fr);
  gap: 24px;
  min-height: calc(100vh - 170px);
  padding: 34px 0 28px;
}
.retreat-hero-copy {
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
  padding: clamp(28px, 5vw, 52px);
  border-radius: 34px;
  min-height: 620px;
  background:
    linear-gradient(180deg, rgba(20, 15, 12, 0.08), rgba(20, 15, 12, 0.26)),
    radial-gradient(circle at top, rgba(255,255,255,0.22), transparent 32%),
    linear-gradient(135deg, #d1ae84, #8d6a4c);
  color: #fff8f0;
  box-shadow: 0 28px 80px rgba(99, 68, 44, 0.18);
}
.retreat-kicker {
  margin: 0 0 18px;
  text-transform: uppercase;
  letter-spacing: 0.24em;
  font-size: 0.74rem;
  opacity: 0.76;
}
.retreat-hero-copy h1, .retreat-grid h2, .retreat-ritual-copy h2, .retreat-cta h2 {
  margin: 0;
  font-family: "Georgia", serif;
  font-weight: 600;
  letter-spacing: -0.05em;
  line-height: 0.94;
}
.retreat-hero-copy h1 { font-size: clamp(3.6rem, 7vw, 6.4rem); max-width: 10ch; }
.retreat-hero-copy p:last-of-type { margin: 22px 0 0; max-width: 42ch; line-height: 1.75; color: rgba(255, 248, 240, 0.84); }
.retreat-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-top: 28px;
  min-height: 48px;
  padding: 0 18px;
  border-radius: 999px;
  background: rgba(255, 248, 240, 0.92);
  color: var(--ink);
  width: fit-content;
}
.retreat-booking {
  align-self: end;
  display: grid;
  gap: 12px;
  padding: 24px;
  border-radius: 28px;
  background: rgba(250, 245, 237, 0.74);
  border: 1px solid rgba(255,255,255,0.48);
  backdrop-filter: blur(14px);
  box-shadow: 0 22px 60px rgba(99, 68, 44, 0.12);
}
.retreat-booking span { color: var(--muted); text-transform: uppercase; letter-spacing: 0.2em; font-size: 0.72rem; }
.retreat-booking strong { font-size: 1.3rem; line-height: 1.18; }
.retreat-booking a { color: var(--ink); text-decoration: none; font-weight: 600; }
.retreat-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 22px;
  margin-top: 26px;
}
.retreat-grid article, .retreat-cta {
  padding: 28px;
  border-radius: 28px;
  background: rgba(250, 245, 237, 0.74);
  border: 1px solid rgba(46, 36, 29, 0.08);
}
.retreat-grid p:last-of-type { color: var(--muted); line-height: 1.7; }
.retreat-rituals {
  display: grid;
  grid-template-columns: minmax(280px, 0.78fr) minmax(0, 1.22fr);
  gap: 24px;
  margin-top: 26px;
}
.retreat-image-block {
  min-height: 420px;
  border-radius: 28px;
  background:
    radial-gradient(circle at 50% 35%, rgba(255,255,255,0.22), transparent 18%),
    linear-gradient(160deg, rgba(255,255,255,0.18), rgba(0,0,0,0.1)),
    linear-gradient(180deg, #d7b892 0%, #a57b59 100%);
}
.retreat-ritual-copy {
  padding: 20px 8px 20px 10px;
}
.retreat-ritual-copy h2 { font-size: clamp(2.5rem, 5vw, 4rem); max-width: 11ch; }
.retreat-ritual-copy ul { list-style: none; margin: 26px 0 0; padding: 0; display: grid; gap: 16px; }
.retreat-ritual-copy li { padding-top: 16px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; gap: 18px; }
.retreat-ritual-copy span { color: var(--muted); max-width: 18ch; }
.retreat-cta {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-top: 26px;
}
.retreat-cta h2 { font-size: clamp(2.2rem, 5vw, 3.6rem); max-width: 11ch; }
@media (max-width: 980px) {
  .retreat-hero, .retreat-grid, .retreat-rituals, .retreat-cta { grid-template-columns: 1fr; display: grid; }
}
@media (max-width: 760px) {
  .retreat-shell { width: min(100vw - 24px, 1240px); }
  .retreat-header { flex-direction: column; align-items: flex-start; }
  .retreat-header nav { flex-wrap: wrap; }
}"#,
        ),
        StudioStaticHtmlArchetype::ProductLaunch => (
            r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="__TITLE__" />
    <title>__BRAND__</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body class="theme-product-launch">
    <div class="launch-shell">
      <header class="launch-header">
        <span class="launch-brand">__BRAND__</span>
        <nav aria-label="Primary">
          <a href="#features">Features</a>
          <a href="#rollout">Rollout</a>
          <a href="#waitlist">Waitlist</a>
        </nav>
        <a class="launch-chip" href="#waitlist">Join beta</a>
      </header>
      <main>
        <section class="launch-hero">
          <div class="launch-copy" data-reveal>
            <p class="launch-kicker">New release / product system</p>
            <h1>Ship the launch page before the product deck gets stale.</h1>
            <p>__BRAND__ frames a technology release as a focused narrative: one strong promise, a product shell preview, clear feature sequencing, and a tight waitlist close.</p>
            <div class="launch-actions">
              <a class="launch-button is-primary" href="#waitlist">Request access</a>
              <a class="launch-button" href="#features">See the system</a>
            </div>
          </div>
          <div class="launch-product-shell" data-reveal>
            <div class="launch-product-top">
              <span>Realtime workspace</span>
              <span>v1.0</span>
            </div>
            <div class="launch-product-grid">
              <article><strong>72%</strong><span>Faster launch prep</span></article>
              <article><strong>3 lanes</strong><span>Preview, code, release</span></article>
              <article><strong>Live</strong><span>Receipts, state, delivery</span></article>
            </div>
          </div>
        </section>
        <section class="launch-band" id="features" data-reveal>
          <article>
            <span>Signal</span>
            <strong>One primary message, not a screen full of noise.</strong>
          </article>
          <article>
            <span>System</span>
            <strong>Feature sequencing that reads like a launch story, not a spec dump.</strong>
          </article>
          <article>
            <span>Close</span>
            <strong>A waitlist CTA that arrives when the user is ready to act.</strong>
          </article>
        </section>
        <section class="launch-layout" id="rollout">
          <div class="launch-panel" data-reveal>
            <p class="launch-kicker">Feature stack</p>
            <h2>Move from promise to proof in three deliberate sections.</h2>
            <p>The layout avoids the usual feature-card mosaic and instead uses one dominant visual plane, one product shell, and one orderly rollout narrative.</p>
          </div>
          <div class="launch-list" data-reveal>
            <article>
              <strong>Realtime readiness</strong>
              <p>Surface the product shell early so the page feels like a release, not a mock announcement.</p>
            </article>
            <article>
              <strong>Operational proof</strong>
              <p>Use measured metrics and one clear sequence of benefits instead of generic dashboard clutter.</p>
            </article>
            <article>
              <strong>Controlled CTA</strong>
              <p>Close with a single join flow that matches the tone of the rest of the launch.</p>
            </article>
          </div>
        </section>
        <section class="launch-footer" id="waitlist" data-reveal>
          <div>
            <p class="launch-kicker">Waitlist</p>
            <h2>Release the page while the product energy is still fresh.</h2>
          </div>
          <a class="launch-button is-primary" href="mailto:hello@example.com">Join the beta</a>
        </section>
      </main>
    </div>
    <script type="module" src="/script.js"></script>
  </body>
</html>"##,
            r#"*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #090d16;
  --bg-2: #12192b;
  --surface: rgba(18, 25, 43, 0.74);
  --text: #edf2ff;
  --muted: rgba(237, 242, 255, 0.7);
  --line: rgba(255, 255, 255, 0.12);
  --accent: #7f8dff;
  --accent-2: #58f7d1;
  color-scheme: dark;
}
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-width: 320px;
  background:
    radial-gradient(circle at top left, rgba(127, 141, 255, 0.22), transparent 26%),
    radial-gradient(circle at 70% 20%, rgba(88, 247, 209, 0.12), transparent 18%),
    linear-gradient(180deg, #0a0e18 0%, #101726 100%);
  color: var(--text);
  font-family: "Inter", "Segoe UI", Arial, sans-serif;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px);
  background-size: 96px 96px;
  mask-image: radial-gradient(circle at center, black, transparent 84%);
}
.launch-shell { width: min(1240px, calc(100vw - 40px)); margin: 0 auto; padding: 24px 0 72px; }
.launch-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding-bottom: 18px;
}
.launch-brand { font-weight: 700; letter-spacing: -0.04em; font-size: 1.1rem; }
.launch-header nav { display: flex; gap: 22px; }
.launch-header a, .launch-button, .launch-chip { color: inherit; text-decoration: none; }
.launch-header nav a { color: var(--muted); }
.launch-chip, .launch-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 0 18px;
  border-radius: 999px;
  border: 1px solid var(--line);
}
.launch-chip { background: rgba(255,255,255,0.04); }
.launch-button.is-primary, .launch-chip:hover {
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: #06101d;
  border-color: transparent;
}
.launch-hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 0.92fr);
  gap: 28px;
  min-height: calc(100vh - 180px);
  align-items: center;
}
.launch-kicker {
  margin: 0 0 18px;
  text-transform: uppercase;
  letter-spacing: 0.24em;
  font-size: 0.74rem;
  color: var(--muted);
}
.launch-copy h1, .launch-panel h2, .launch-footer h2 {
  margin: 0;
  font-size: clamp(3.2rem, 7vw, 6rem);
  line-height: 0.94;
  letter-spacing: -0.05em;
}
.launch-copy p:last-of-type { margin: 22px 0 0; max-width: 46ch; color: var(--muted); line-height: 1.72; font-size: 1.05rem; }
.launch-actions { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 28px; }
.launch-product-shell {
  padding: 24px;
  border-radius: 28px;
  border: 1px solid rgba(255,255,255,0.1);
  background: linear-gradient(180deg, rgba(18, 25, 43, 0.92), rgba(10, 14, 24, 0.82));
  box-shadow: 0 32px 90px rgba(4, 8, 14, 0.42);
}
.launch-product-top {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  color: var(--muted);
  font-size: 0.88rem;
}
.launch-product-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-top: 60px;
}
.launch-product-grid article {
  padding: 18px;
  border-radius: 22px;
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
}
.launch-product-grid strong { display: block; font-size: 1.8rem; margin-bottom: 10px; }
.launch-product-grid span { color: var(--muted); }
.launch-band {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 18px;
  margin-top: 20px;
}
.launch-band article, .launch-panel, .launch-footer {
  padding: 24px;
  border-radius: 24px;
  background: var(--surface);
  border: 1px solid rgba(255,255,255,0.08);
  backdrop-filter: blur(16px);
}
.launch-band span { display: block; margin-bottom: 16px; color: var(--accent-2); text-transform: uppercase; letter-spacing: 0.22em; font-size: 0.72rem; }
.launch-band strong { font-size: 1.15rem; line-height: 1.3; }
.launch-layout {
  display: grid;
  grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr);
  gap: 24px;
  margin-top: 24px;
}
.launch-panel h2 { font-size: clamp(2.2rem, 4vw, 3.6rem); max-width: 10ch; }
.launch-panel p:last-of-type { margin: 20px 0 0; color: var(--muted); line-height: 1.72; }
.launch-list { display: grid; gap: 16px; }
.launch-list article {
  padding-top: 16px;
  border-top: 1px solid rgba(255,255,255,0.08);
}
.launch-list strong { display: block; font-size: 1.06rem; }
.launch-list p { margin: 8px 0 0; color: var(--muted); line-height: 1.66; }
.launch-footer {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 22px;
  margin-top: 24px;
}
.launch-footer h2 { font-size: clamp(2.2rem, 5vw, 3.8rem); max-width: 12ch; }
@media (max-width: 980px) {
  .launch-hero, .launch-band, .launch-layout, .launch-footer, .launch-product-grid { grid-template-columns: 1fr; display: grid; }
}
@media (max-width: 760px) {
  .launch-shell { width: min(100vw - 24px, 1240px); }
  .launch-header { flex-direction: column; align-items: flex-start; }
  .launch-header nav { flex-wrap: wrap; }
}"#,
        ),
    };

    let html = html.replace("__BRAND__", brand).replace("__TITLE__", title);
    let styles = format!(
        "{}\n[data-reveal] {{ opacity: 0; transform: translateY(24px); transition: opacity 500ms ease, transform 500ms ease; }}\n[data-reveal].is-visible {{ opacity: 1; transform: translateY(0); }}\n",
        styles.replace("__BRAND__", brand).replace("__TITLE__", title)
    );

    StaticHtmlTemplate {
        html,
        styles,
        script: "const reveals = document.querySelectorAll('[data-reveal]');\n\nconst observer = new IntersectionObserver((entries) => {\n  entries.forEach((entry) => {\n    if (entry.isIntersecting) {\n      entry.target.classList.add('is-visible');\n      observer.unobserve(entry.target);\n    }\n  });\n}, { threshold: 0.14 });\n\nreveals.forEach((element, index) => {\n  element.style.transitionDelay = `${Math.min(index * 70, 280)}ms`;\n  observer.observe(element);\n});\n".to_string(),
    }
}
