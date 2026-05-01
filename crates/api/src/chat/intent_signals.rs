use ioi_types::app::ChatRendererKind;
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
struct KnownSportsTarget {
    aliases: &'static [&'static str],
    canonical: &'static str,
    league: &'static str,
}

const KNOWN_SPORTS_TARGETS: &[KnownSportsTarget] = &[
    KnownSportsTarget {
        aliases: &["lakers", "los angeles lakers"],
        canonical: "Los Angeles Lakers",
        league: "nba",
    },
    KnownSportsTarget {
        aliases: &["celtics", "boston celtics"],
        canonical: "Boston Celtics",
        league: "nba",
    },
    KnownSportsTarget {
        aliases: &["warriors", "golden state warriors"],
        canonical: "Golden State Warriors",
        league: "nba",
    },
    KnownSportsTarget {
        aliases: &["knicks", "new york knicks"],
        canonical: "New York Knicks",
        league: "nba",
    },
    KnownSportsTarget {
        aliases: &["yankees", "new york yankees"],
        canonical: "New York Yankees",
        league: "mlb",
    },
    KnownSportsTarget {
        aliases: &["dodgers", "los angeles dodgers"],
        canonical: "Los Angeles Dodgers",
        league: "mlb",
    },
    KnownSportsTarget {
        aliases: &["chiefs", "kansas city chiefs"],
        canonical: "Kansas City Chiefs",
        league: "nfl",
    },
    KnownSportsTarget {
        aliases: &["cowboys", "dallas cowboys"],
        canonical: "Dallas Cowboys",
        league: "nfl",
    },
    KnownSportsTarget {
        aliases: &["packers", "green bay packers"],
        canonical: "Green Bay Packers",
        league: "nfl",
    },
    KnownSportsTarget {
        aliases: &["steelers", "pittsburgh steelers"],
        canonical: "Pittsburgh Steelers",
        league: "nfl",
    },
    KnownSportsTarget {
        aliases: &["eagles", "philadelphia eagles"],
        canonical: "Philadelphia Eagles",
        league: "nfl",
    },
];

#[derive(Clone, Debug)]
pub struct ChatIntentContext {
    surface: String,
    normalized: String,
    terms: Vec<String>,
}

impl ChatIntentContext {
    pub fn new(intent: &str) -> Self {
        let semantic_intent = normalize_inline_whitespace(&user_request_segment(intent));
        Self {
            surface: semantic_intent.clone(),
            normalized: normalize_inline_whitespace(&semantic_intent.to_ascii_lowercase()),
            terms: semantic_intent
                .split(|ch: char| !ch.is_alphanumeric())
                .filter(|term| !term.is_empty())
                .map(|term| term.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    pub fn contains_any_phrase(&self, phrases: &[&str]) -> bool {
        phrases
            .iter()
            .any(|phrase| self.normalized.contains(phrase))
    }

    pub fn contains_any_term(&self, candidates: &[&str]) -> bool {
        self.terms
            .iter()
            .any(|term| candidates.iter().any(|candidate| term == candidate))
    }

    pub fn requests_runtime_locality(&self) -> bool {
        self.contains_any_phrase(&[
            "near me",
            "nearby",
            "my area",
            "around here",
            "current area",
            "current location",
            "where i am",
            "close by",
        ])
    }

    pub fn requests_created_deliverable(&self) -> bool {
        const CREATION_TERMS: &[&str] = &[
            "create", "make", "build", "generate", "write", "draft", "produce", "craft", "design",
        ];

        self.contains_any_term(CREATION_TERMS)
            || self.normalized.starts_with("new ")
            || self.contains_any_term(&["artifact", "artifacts"])
            || self.contains_any_phrase(&[
                "turn it into an artifact",
                "turn it into a",
                "convert it into an artifact",
            ])
    }

    pub fn explicit_generic_artifact_signal(&self) -> bool {
        self.normalized.starts_with("artifact ")
            || self.normalized.ends_with(" artifact")
            || self.normalized.contains(" artifact ")
            || self.contains_any_phrase(&[
                "turn it into an artifact",
                "turn it into a ",
                "turn this into an artifact",
                "turn this into a ",
                "convert it into an artifact",
                "convert it into a ",
                "convert this into an artifact",
                "convert this into a ",
            ])
    }

    pub fn explicitly_declines_persistent_artifact(&self) -> bool {
        self.contains_any_phrase(&[
            "do not create an artifact",
            "don't create an artifact",
            "do not create a persistent artifact",
            "don't create a persistent artifact",
            "do not make an artifact",
            "don't make an artifact",
            "without creating an artifact",
            "without making an artifact",
            "do not materialize",
            "don't materialize",
            "non-artifact query",
            "not an artifact query",
            "no artifact",
            "no artifacts",
        ])
    }

    pub fn requests_downloadable_fileset(&self) -> bool {
        const FILE_TARGET_TERMS: &[&str] = &[
            "csv",
            "tsv",
            "xlsx",
            "json",
            "yaml",
            "yml",
            "pdf",
            "png",
            "jpg",
            "jpeg",
            "svg",
            "txt",
            "md",
            "markdown",
            "readme",
            "license",
            "changelog",
        ];
        const TRANSPORT_TERMS: &[&str] = &[
            "download",
            "downloadable",
            "export",
            "exports",
            "bundle",
            "archive",
            "package",
            "pack",
        ];
        const BUNDLE_TERMS: &[&str] = &["bundle", "archive", "package", "pack"];

        let referenced_files = self
            .terms
            .iter()
            .filter(|term| FILE_TARGET_TERMS.contains(&term.as_str()))
            .cloned()
            .collect::<BTreeSet<_>>();
        let requests_transport = self.contains_any_term(TRANSPORT_TERMS)
            || self.normalized.contains("file set")
            || self.normalized.contains("fileset");
        let requests_bundle = self.contains_any_term(BUNDLE_TERMS)
            || self.normalized.contains("file set")
            || self.normalized.contains("fileset");

        requests_transport
            && (referenced_files.len() >= 2 || (requests_bundle && !referenced_files.is_empty()))
    }

    pub fn supports_bundle_manifest_renderer(&self) -> bool {
        self.requests_downloadable_fileset()
            || self.contains_any_phrase(&[
                "bundle manifest",
                "artifact bundle",
                "report bundle",
                "compound bundle",
                "evidence bundle",
                "release bundle",
                "briefing pack",
                "report pack",
                "supporting files",
                "file set",
                "fileset",
            ])
            || self.contains_any_term(&[
                "bundle",
                "bundles",
                "manifest",
                "manifests",
                "pack",
                "packs",
                "package",
                "packages",
                "archive",
                "archives",
            ])
    }

    pub fn explicit_downloadable_export_format(&self) -> Option<&'static str> {
        let normalized = self.normalized.trim_end_matches('?').trim();
        if normalized.contains("powerpoint")
            || normalized.contains("pptx")
            || normalized.contains("slide deck")
            || normalized.contains("presentation deck")
        {
            return Some("pptx");
        }

        if normalized.contains("docx")
            || normalized.contains("word doc")
            || normalized.contains("word document")
        {
            return Some("docx");
        }

        if normalized.contains("odt")
            || normalized.contains("open document text")
            || normalized.contains("opendocument text")
            || normalized.contains("openoffice document")
        {
            return Some("odt");
        }

        if normalized.contains("xlsx")
            || normalized.contains("spreadsheet")
            || normalized.contains("workbook")
        {
            return Some("xlsx");
        }

        None
    }

    pub fn currentness_pressure(&self) -> bool {
        let has_temporal_signal = self.contains_any_term(&[
            "current",
            "latest",
            "recent",
            "today",
            "tonight",
            "now",
            "currently",
            "newest",
            "live",
        ]) || self.contains_any_phrase(&[
            "right now",
            "as of today",
            "as of now",
            "this week",
            "this month",
            "up to date",
            "up-to-date",
            "breaking news",
        ]);
        let has_question_shape = self.normalized.ends_with('?')
            || self.normalized.starts_with("who ")
            || self.normalized.starts_with("what ")
            || self.normalized.starts_with("when ")
            || self.normalized.starts_with("where ")
            || self.normalized.starts_with("is ")
            || self.normalized.starts_with("are ")
            || self.normalized.starts_with("can you tell me");

        has_temporal_signal && has_question_shape
    }

    pub fn currentness_scope_ambiguous(&self) -> bool {
        matches!(
            self.normalized.trim_end_matches('?').trim(),
            "what's happening this week"
                | "what is happening this week"
                | "what's going on this week"
                | "what is going on this week"
                | "what's happening this weekend"
                | "what is happening this weekend"
        )
    }

    pub fn workspace_grounding_required(&self) -> bool {
        if self.requests_created_deliverable() {
            return false;
        }

        let repo_context = self.contains_any_phrase(&[
            "this repo",
            "in this repo",
            "this repository",
            "in this repository",
            "current repo",
            "current repository",
            "repo root",
            "repository root",
            "this codebase",
            "in this codebase",
            "workspace root",
            "this workspace",
            "in this workspace",
        ]);
        let source_grounding = self.source_citation_grounding_required();
        let coding_plan_grounding = self.coding_plan_grounding_required();
        let runtime_lifecycle_grounding = self.runtime_lifecycle_grounding_required();
        let agent_validation_grounding = self.agent_validation_grounding_required();
        if !repo_context
            && !source_grounding
            && !coding_plan_grounding
            && !runtime_lifecycle_grounding
            && !agent_validation_grounding
        {
            return false;
        }

        self.normalized.ends_with('?')
            || self.normalized.starts_with("plan ")
            || self.normalized.starts_with("what ")
            || self.normalized.starts_with("which ")
            || self.normalized.starts_with("where ")
            || self.normalized.starts_with("explain ")
            || self.normalized.starts_with("summarize ")
            || self.normalized.starts_with("how many ")
            || self.normalized.starts_with("list ")
            || self.normalized.starts_with("show ")
            || self.normalized.starts_with("find ")
            || self.normalized.starts_with("look in ")
            || self.normalized.starts_with("read ")
            || self.normalized.starts_with("tell me ")
            || self.normalized.starts_with("using ")
            || self.normalized.starts_with("validate ")
            || self.normalized.starts_with("does ")
    }

    pub fn runtime_lifecycle_grounding_required(&self) -> bool {
        if self.requests_created_deliverable() {
            return false;
        }

        let runtime_subject = self.contains_any_phrase(&["agent runtime", "runtime event"])
            || (self.contains_any_term(&["runtime"]) && self.contains_any_term(&["event"]));
        let lifecycle_subject = self.contains_any_term(&["lifecycle", "sequence", "diagram"])
            || self.contains_any_phrase(&["event lifecycle", "sequence diagram"]);
        let diagram_shape = self.contains_any_term(&["mermaid", "diagram"])
            || self.contains_any_phrase(&["sequence diagram", "flow diagram"]);
        runtime_subject && lifecycle_subject && diagram_shape
    }

    pub fn destructive_repository_request(&self) -> bool {
        let destructive_action =
            self.contains_any_term(&[
                "delete", "remove", "erase", "wipe", "destroy", "rm", "rmdir",
            ]) || self.contains_any_phrase(&["rm -rf", "delete everything", "wipe everything"]);
        let repository_scope = self.contains_any_term(&["repo", "repository", "workspace"])
            || self.contains_any_phrase(&[
                "this repo",
                "the repo",
                "this repository",
                "the repository",
                "this workspace",
                "the workspace",
            ]);
        destructive_action && repository_scope
    }

    pub fn agent_validation_grounding_required(&self) -> bool {
        if self.requests_created_deliverable() {
            return false;
        }

        let validation_shape = self.normalized.starts_with("find ")
            || self.normalized.starts_with("validate ")
            || self.contains_any_phrase(&[
                "cheapest way to verify",
                "cheapest way to validate",
                "answer path through the harness",
            ]);
        let agent_runtime_subject = self.contains_any_term(&[
            "harness", "probe", "verify", "validate", "sources", "render", "desktop", "chat",
        ]) || self
            .contains_any_phrase(&["desktop chat", "source chips"]);
        validation_shape && agent_runtime_subject
    }

    pub fn source_citation_grounding_required(&self) -> bool {
        if self.requests_created_deliverable() {
            return false;
        }

        let asks_for_source_receipts = self.contains_any_phrase(&[
            "cite the files",
            "cite files",
            "cite sources",
            "cite the sources",
            "sources you used",
            "files you used",
            "source files",
            "using repo docs",
            "from repo docs",
            "from repository docs",
            "using repository docs",
        ]);
        if asks_for_source_receipts {
            return true;
        }

        let location_question = self.normalized.starts_with("where ")
            || self.normalized.starts_with("which file ")
            || self.normalized.starts_with("which files ")
            || self.normalized.starts_with("what file ")
            || self.normalized.starts_with("what files ");
        location_question
            && self.contains_any_term(&[
                "defined",
                "implemented",
                "declared",
                "located",
                "lives",
                "stored",
            ])
    }

    pub fn coding_plan_grounding_required(&self) -> bool {
        if self.requests_created_deliverable() {
            return false;
        }

        let no_mutation_requested = self.contains_any_phrase(&[
            "do not edit",
            "don't edit",
            "without editing",
            "without changing files",
            "no file changes",
            "no edits",
        ]);
        let planning_shape = self.normalized.starts_with("plan ")
            || self.normalized.starts_with("outline ")
            || self.normalized.starts_with("how would ")
            || self.normalized.starts_with("how should ");
        let implementation_subject = self.contains_any_term(&[
            "add",
            "implement",
            "support",
            "wire",
            "refactor",
            "fix",
            "test",
            "runtime",
        ]);

        no_mutation_requested && planning_shape && implementation_subject
    }

    pub fn tool_widget_family(&self) -> Option<&'static str> {
        if self.contains_any_term(&["weather", "forecast", "temperature", "rain", "snow"])
            || self.weather_advice_request()
        {
            return Some("weather");
        }

        if self.contains_any_term(&[
            "score",
            "scores",
            "season",
            "playoff",
            "playoffs",
            "record",
            "standings",
            "schedule",
            "game",
            "games",
            "matchup",
            "matchups",
            "nba",
            "wnba",
            "nfl",
            "nhl",
            "mlb",
            "epl",
            "ipl",
        ]) {
            return Some("sports");
        }

        if self.normalized.contains("this season")
            && self.contains_any_term(&[
                "lakers", "celtics", "warriors", "knicks", "yankees", "dodgers", "chiefs",
                "cowboys", "packers", "steelers", "eagles",
            ])
        {
            return Some("sports");
        }

        let explicit_places_phrase = self.contains_any_phrase(&[
            "near me",
            "nearby",
            "near downtown",
            "map of",
            "show on a map",
            "directions to",
            "places to",
            "coffee shop",
            "coffee shops",
        ]);
        let place_category_term = self.contains_any_term(&[
            "restaurant",
            "restaurants",
            "hotel",
            "hotels",
            "cafe",
            "cafes",
            "coffee",
            "shop",
            "shops",
            "bookstore",
            "bookstores",
            "pharmacy",
            "pharmacies",
            "grocery",
            "groceries",
            "gym",
            "gyms",
            "attraction",
            "attractions",
        ]);
        let place_lookup_action = self.contains_any_term(&[
            "find",
            "search",
            "show",
            "map",
            "directions",
            "recommend",
            "recommendation",
            "recommendations",
            "where",
            "best",
            "near",
            "nearby",
        ]) || self.places_anchor_phrase().is_some();
        if explicit_places_phrase || (place_category_term && place_lookup_action) {
            return Some("places");
        }

        let recipe_keyword_signal = self.contains_any_term(&[
            "recipe",
            "recipes",
            "ingredient",
            "ingredients",
            "serving",
            "servings",
            "serves",
        ]);
        let culinary_verb_signal = self.contains_any_phrase(&[
            "how do i make ",
            "how do i cook ",
            "how do i bake ",
            "how do i prepare ",
            "show me how to make ",
            "show me how to cook ",
            "walk me through making ",
            "walk me through cooking ",
        ]);
        let culinary_term_signal = self.contains_any_term(&[
            "carbonara",
            "pasta",
            "pizza",
            "bread",
            "cake",
            "cookie",
            "cookies",
            "risotto",
            "soup",
            "salad",
            "chicken",
            "pancakes",
            "curry",
            "omelet",
            "omelette",
            "stew",
            "sauce",
            "lasagna",
            "ramen",
            "tacos",
            "brownies",
            "muffins",
            "rice",
            "meal",
        ]);
        let serving_shape_signal = self.normalized.contains(" for ")
            && self.contains_any_term(&["people", "person", "serving", "servings", "serves"]);
        if recipe_keyword_signal
            || (culinary_verb_signal && (culinary_term_signal || serving_shape_signal))
        {
            return Some("recipe");
        }

        if self.requests_prioritization() {
            return Some("user_input");
        }

        None
    }

    pub fn explicit_visualizer_signal(&self) -> Option<&'static str> {
        if self.contains_any_phrase(&[
            "draw ",
            "diagram ",
            "flow chart",
            "flowchart",
            "mind map",
            "mindmap",
            "timeline diagram",
            "architecture diagram",
            "org chart",
            "show me a chart",
            "show me an svg",
            "show me a mermaid",
            "sequence diagram",
            "as a mermaid",
            "as mermaid",
        ]) {
            return Some("inline_visual_requested");
        }

        None
    }

    pub(crate) fn explicit_interactive_single_document_signal(&self) -> bool {
        let interactive_tool_request = self.contains_any_term(&["interactive", "adjustable"])
            || self.contains_any_phrase(&["i can adjust", "can adjust", "with sliders"]);
        interactive_tool_request
            && self.contains_any_term(&[
                "calculator",
                "calculators",
                "simulator",
                "simulators",
                "dashboard",
                "dashboards",
                "tool",
                "tools",
            ])
    }

    pub fn explicit_single_document_renderer(&self) -> Option<(ChatRendererKind, &'static str)> {
        if self.contains_any_phrase(&["pdf", "portable document format"]) {
            return Some((ChatRendererKind::PdfEmbed, "explicit_pdf_artifact"));
        }

        if self.contains_any_phrase(&["svg", "vector graphic"]) {
            return Some((ChatRendererKind::Svg, "explicit_svg_artifact"));
        }

        if self.contains_any_phrase(&["mermaid", "sequence diagram", "flow diagram"]) {
            return Some((ChatRendererKind::Mermaid, "explicit_mermaid_artifact"));
        }

        if self.contains_any_phrase(&[
            "html page",
            "html artifact",
            "landing page",
            "microsite",
            "web page",
        ]) {
            return Some((ChatRendererKind::HtmlIframe, "explicit_html_artifact"));
        }

        if self.explicit_interactive_single_document_signal() {
            return Some((
                ChatRendererKind::HtmlIframe,
                "explicit_interactive_single_document_artifact",
            ));
        }

        if self.contains_any_phrase(&["markdown", "readme", ".md"]) {
            return Some((ChatRendererKind::Markdown, "explicit_markdown_artifact"));
        }

        None
    }

    pub fn extract_weather_scopes(&self) -> Vec<String> {
        let trimmed = self.surface.trim().trim_end_matches('?').trim();
        let normalized = self.normalized.trim().trim_end_matches('?').trim();
        if let Some(index) = normalized.rfind(':') {
            let prefix = &normalized[..index];
            if prefix.contains("weather") || prefix.contains("forecast") {
                let suffix = trimmed[index + 1..].trim();
                let scopes = split_scope_list(suffix);
                if !scopes.is_empty() {
                    return scopes;
                }
            }
        }

        for marker in ["weather in ", "weather for ", "forecast for "] {
            if let Some(index) = normalized.find(marker) {
                let scope = trim_intent_suffix_case_insensitive(
                    &trimmed[index + marker.len()..],
                    &[
                        " this weekend",
                        " this week",
                        " tomorrow",
                        " tonight",
                        " today",
                        " right now",
                        " currently",
                        " now",
                    ],
                )
                .trim_matches(|ch: char| ch == '.' || ch.is_whitespace());
                let scope = scope
                    .rsplit_once(':')
                    .map(|(_, suffix)| suffix)
                    .unwrap_or(scope)
                    .trim();
                let scopes = split_scope_list(scope);
                if !scopes.is_empty() {
                    return scopes;
                }
            }
        }

        if self.weather_advice_request() {
            for marker in [" in ", " for "] {
                if let Some(index) = normalized.rfind(marker) {
                    let scope = trim_intent_suffix_case_insensitive(
                        &trimmed[index + marker.len()..],
                        &[
                            " today",
                            " tonight",
                            " tomorrow",
                            " this morning",
                            " this evening",
                            " right now",
                            " currently",
                            " now",
                        ],
                    )
                    .trim_matches(|ch: char| ch == '.' || ch.is_whitespace());
                    let scopes = split_scope_list(scope);
                    if !scopes.is_empty() {
                        return scopes;
                    }
                }
            }
        }

        Vec::new()
    }

    pub fn weather_temporal_scope(&self) -> Option<&'static str> {
        [
            ("right now", "right_now"),
            ("today", "today"),
            ("tonight", "tonight"),
            ("tomorrow", "tomorrow"),
            ("this weekend", "this_weekend"),
            ("this week", "this_week"),
            ("currently", "current"),
        ]
        .into_iter()
        .find(|(needle, _)| self.normalized.contains(needle))
        .map(|(_, label)| label)
    }

    pub fn weather_advice_request(&self) -> bool {
        let asks_weather_advice = self.contains_any_phrase(&[
            "wear a jacket",
            "need a jacket",
            "wear a coat",
            "take an umbrella",
            "bring an umbrella",
        ]);
        let asks_about_now = self.contains_any_phrase(&[
            "today",
            "tonight",
            "right now",
            "this morning",
            "this evening",
        ]);

        asks_weather_advice && asks_about_now
    }

    pub fn sports_league(&self) -> Option<&'static str> {
        if self.contains_any_term(&["nba", "basketball"]) {
            return Some("nba");
        }
        if self.contains_any_term(&["wnba"]) {
            return Some("wnba");
        }
        if self.contains_any_term(&["nfl", "football"]) {
            return Some("nfl");
        }
        if self.contains_any_term(&["nhl", "hockey"]) {
            return Some("nhl");
        }
        if self.contains_any_term(&["mlb", "baseball"]) {
            return Some("mlb");
        }
        if self.contains_any_term(&["epl", "premier", "soccer"]) {
            return Some("epl");
        }
        if self.contains_any_term(&["ipl", "cricket"]) {
            return Some("ipl");
        }

        known_sports_target(&self.normalized).map(|target| target.league)
    }

    pub fn sports_team_target(&self) -> Option<String> {
        known_sports_target(&self.normalized).map(|target| target.canonical.to_string())
    }

    pub fn sports_data_scope(&self) -> Option<&'static str> {
        if self.contains_any_term(&["standings", "standing", "record", "records"]) {
            return Some("standings");
        }
        if self.contains_any_term(&["schedule", "schedules", "next"]) {
            return Some("schedule");
        }
        if self.contains_any_term(&["score", "scores", "result", "results"]) {
            return Some("scores");
        }
        if self.contains_any_term(&["headline", "headlines", "news"]) {
            return Some("news");
        }
        None
    }

    pub fn places_anchor_phrase(&self) -> Option<String> {
        let trimmed = self.normalized.trim().trim_end_matches('?').trim();
        let normalize_anchor = |anchor: &str| {
            let mut anchor = cleaned_trailing_punctuation(anchor);
            let lowered = anchor.to_ascii_lowercase();
            let markers = [
                " and show",
                " and tell",
                " and explain",
                " and compare",
                " and rank",
                ", show",
                ", tell",
                ", explain",
                ", compare",
                ", rank",
                " show them",
                " tell me",
                " explain why",
                " which one",
                " that opens",
            ];
            if let Some(index) = markers
                .iter()
                .filter_map(|marker| lowered.find(marker))
                .min()
            {
                anchor.truncate(index);
            }
            trim_intent_suffix_case_insensitive(anchor.trim(), &markers)
                .trim()
                .to_string()
        };
        for prefix in ["near ", "around ", "by ", "close to ", "in "] {
            if let Some(anchor) = trimmed.strip_prefix(prefix) {
                let anchor = normalize_anchor(anchor);
                if !anchor.is_empty() {
                    return Some(anchor);
                }
            }
        }
        for marker in [" near ", " around ", " by ", " close to "] {
            if let Some(index) = trimmed.find(marker) {
                let anchor = normalize_anchor(&trimmed[index + marker.len()..]);
                if !anchor.is_empty() {
                    return Some(anchor);
                }
            }
        }
        for marker in [" in "] {
            if let Some(index) = trimmed.find(marker) {
                let anchor = normalize_anchor(&trimmed[index + marker.len()..]);
                if !anchor.is_empty() {
                    return Some(anchor);
                }
            }
        }
        None
    }

    pub fn places_category_label(&self) -> Option<&'static str> {
        if self.contains_any_phrase(&["coffee shop", "coffee shops"])
            || self.contains_any_term(&["coffee", "cafe", "cafes"])
        {
            return Some("coffee shops");
        }
        if self.contains_any_term(&["restaurant", "restaurants"]) {
            return Some("restaurants");
        }
        if self.contains_any_term(&["bar", "bars"]) {
            return Some("bars");
        }
        None
    }

    pub fn recipe_dish(&self) -> Option<String> {
        for prefix in [
            "recipe for ",
            "how do i make ",
            "how do i cook ",
            "how do i bake ",
            "how do i prepare ",
            "show me how to make ",
            "show me how to cook ",
            "walk me through making ",
            "walk me through cooking ",
            "make ",
            "cook ",
            "bake ",
            "prepare ",
        ] {
            if let Some(rest) = self.normalized.strip_prefix(prefix) {
                let dish = strip_recipe_suffixes(rest);
                if !dish.is_empty() {
                    return Some(title_case_phrase(&dish));
                }
            }
        }

        if self.contains_any_term(&["recipe", "recipes"]) {
            let dish_terms = self
                .terms
                .iter()
                .filter(|term| {
                    !matches!(
                        term.as_str(),
                        "recipe"
                            | "recipes"
                            | "for"
                            | "servings"
                            | "serving"
                            | "serves"
                            | "how"
                            | "do"
                            | "i"
                            | "make"
                            | "cook"
                            | "bake"
                            | "prepare"
                    )
                })
                .take(4)
                .cloned()
                .collect::<Vec<_>>();
            if !dish_terms.is_empty() {
                return Some(title_case_phrase(&dish_terms.join(" ")));
            }
        }

        None
    }

    pub fn recipe_servings(&self) -> Option<String> {
        let phrases = self.normalized.split_whitespace().collect::<Vec<_>>();
        for window in phrases.windows(2) {
            if let [left, right] = window {
                if matches!(*left, "for" | "serves" | "servings" | "serving")
                    && right.chars().all(|ch| ch.is_ascii_digit())
                {
                    return Some(right.to_string());
                }
            }
        }
        None
    }

    pub fn message_channel(&self) -> Option<&'static str> {
        if self.contains_any_term(&["email", "emails", "gmail"]) {
            return Some("email");
        }
        if self.contains_any_term(&["slack"]) {
            return Some("slack");
        }
        if self.contains_any_phrase(&["text message", "sms"]) {
            return Some("text");
        }
        if self.contains_any_term(&["message", "messages", "reply", "draft", "compose"])
            && self.contains_any_term(&["chat", "dm"])
        {
            return Some("chat");
        }
        None
    }

    pub fn message_purpose(&self) -> Option<&'static str> {
        if self.contains_any_term(&["reply", "respond"]) {
            return Some("reply");
        }
        if self.contains_any_term(&["draft", "compose", "write"]) {
            return Some("draft");
        }
        if self.contains_any_term(&["summarize", "summary"]) {
            return Some("summarize");
        }
        if self.contains_any_term(&["send"]) {
            return Some("send");
        }
        None
    }

    pub fn prefers_message_compose_surface(&self) -> bool {
        self.message_channel().is_some()
            && matches!(self.message_purpose(), Some("draft" | "reply" | "send"))
    }

    pub fn message_recipient_context(&self) -> Option<String> {
        for marker in [" to ", " for "] {
            if let Some(index) = self.normalized.find(marker) {
                let candidate = self.normalized[index + marker.len()..]
                    .split(|ch: char| matches!(ch, ',' | '?' | '!'))
                    .next()
                    .unwrap_or_default()
                    .trim();
                let candidate = candidate
                    .split(" about ")
                    .next()
                    .unwrap_or(candidate)
                    .split(" regarding ")
                    .next()
                    .unwrap_or(candidate)
                    .trim();
                if !candidate.is_empty() {
                    return Some(title_case_phrase(candidate));
                }
            }
        }
        None
    }

    pub fn explicit_prioritization_options(&self) -> bool {
        self.contains_any_phrase(&[
            "prioritize these",
            "rank these",
            "compare these",
            "between ",
            " vs ",
        ]) || self.normalized.contains(',')
            || self.normalized.contains(':')
    }

    pub fn requests_prioritization(&self) -> bool {
        self.contains_any_phrase(&[
            "help me prioritize",
            "prioritize my",
            "prioritize these",
            "help me rank",
            "rank these",
            "compare these",
        ]) || self.contains_any_phrase(&[" between ", " vs "])
    }

    pub fn references_previous_conversation(&self) -> bool {
        self.contains_any_phrase(&[
            "previous conversation",
            "previous chat",
            "earlier chat",
            "recent chats",
            "recent chat",
            "past conversation",
        ])
    }

    pub fn references_memory_context(&self) -> bool {
        self.contains_any_phrase(&[
            "remember about me",
            "my preferences",
            "what do you know about me",
            "memory",
            "saved preference",
        ]) || self.contains_any_term(&["remember", "preferences"])
    }
}

fn normalize_inline_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn user_request_segment(value: &str) -> &str {
    let lowered = value.to_ascii_lowercase();
    let Some(index) = lowered.rfind("[user request]") else {
        return value;
    };
    value[index + "[user request]".len()..].trim_matches(|ch: char| ch == ':' || ch.is_whitespace())
}

fn trim_intent_suffix_case_insensitive<'a>(value: &'a str, suffixes: &[&str]) -> &'a str {
    let trimmed = value.trim();
    let lowered = trimmed.to_ascii_lowercase();
    for suffix in suffixes {
        if lowered.ends_with(suffix) {
            let next_len = trimmed.len().saturating_sub(suffix.len());
            return trimmed[..next_len].trim();
        }
    }
    trimmed
}

fn split_scope_list(value: &str) -> Vec<String> {
    if value.contains(',') || value.contains(" and ") {
        return value
            .replace(" and ", ",")
            .split(',')
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(str::to_string)
            .collect();
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Vec::new()
    } else {
        vec![trimmed.to_string()]
    }
}

fn cleaned_trailing_punctuation(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '?' | '.' | '!' | ','))
        .trim()
        .to_string()
}

fn known_sports_target(normalized: &str) -> Option<KnownSportsTarget> {
    KNOWN_SPORTS_TARGETS.iter().copied().find(|target| {
        target
            .aliases
            .iter()
            .any(|alias| normalized.contains(alias))
    })
}

fn strip_recipe_suffixes(value: &str) -> String {
    let mut dish = value
        .split(" for ")
        .next()
        .unwrap_or(value)
        .split(" serving ")
        .next()
        .unwrap_or(value)
        .split(" servings ")
        .next()
        .unwrap_or(value)
        .split(" serves ")
        .next()
        .unwrap_or(value)
        .trim()
        .to_string();
    while dish.ends_with('?') || dish.ends_with('.') || dish.ends_with('!') {
        dish.pop();
    }
    dish.trim().to_string()
}

fn title_case_phrase(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
