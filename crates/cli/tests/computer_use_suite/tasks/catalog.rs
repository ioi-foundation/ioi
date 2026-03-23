use anyhow::{anyhow, Context, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

const SOURCE_ENV_KEYS: &[&str] = &[
    "COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR",
    "MINIWOB_SOURCE_DIR",
];
const DEFAULT_CATALOG_SURVEY_MAX_STEPS: u32 = 14;
const DEFAULT_CATALOG_SURVEY_TIMEOUT_SECONDS: u64 = 20;

pub fn cases(source_dir: Option<&Path>) -> Result<Vec<ComputerUseCase>> {
    let html_root = discover_html_root(source_dir)?;
    let task_dir = html_root.join("miniwob");
    let mut env_ids = fs::read_dir(&task_dir)
        .with_context(|| format!("read MiniWoB task directory '{}'", task_dir.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("html") {
                return None;
            }
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    env_ids.sort();

    Ok(env_ids
        .into_iter()
        .map(|env_id| case_for_env_id(&env_id))
        .collect())
}

fn discover_html_root(source_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(root) = source_dir {
        return probe_html_root(root).with_context(|| {
            format!(
                "resolve MiniWoB html root from configured source '{}'",
                root.display()
            )
        });
    }

    for key in SOURCE_ENV_KEYS {
        if let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) {
            let candidate = PathBuf::from(value);
            return probe_html_root(&candidate).with_context(|| {
                format!(
                    "resolve MiniWoB html root from {}='{}'",
                    key,
                    candidate.display()
                )
            });
        }
    }

    Err(anyhow!(
        "MiniWoB source dir is required for task_set=catalog; set COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR"
    ))
}

fn probe_html_root(candidate: &Path) -> Result<PathBuf> {
    let candidate = candidate
        .canonicalize()
        .with_context(|| format!("canonicalize '{}'", candidate.display()))?;
    for probe in [
        candidate.clone(),
        candidate.join("html"),
        candidate.join("miniwob").join("html"),
    ] {
        if (probe.join("core").join("core.js")).is_file() && probe.join("miniwob").is_dir() {
            return Ok(probe);
        }
    }
    Err(anyhow!(
        "'{}' does not contain a MiniWoB html root",
        candidate.display()
    ))
}

fn case_for_env_id(env_id: &str) -> ComputerUseCase {
    if let Some(case) = known_case(env_id) {
        return case;
    }

    ComputerUseCase {
        id: format!("miniwob_catalog_{}", sanitize_env_id(env_id)),
        env_id: env_id.to_string(),
        seed: survey_seed(env_id),
        task_set: TaskSet::Catalog,
        max_steps: DEFAULT_CATALOG_SURVEY_MAX_STEPS,
        timeout_seconds: DEFAULT_CATALOG_SURVEY_TIMEOUT_SECONDS,
        allowed_tool_profile: AllowedToolProfile::BrowserCore,
        expected_reward_floor: 1.0,
        expected_pass: true,
        local_judge: LocalJudge::MiniwobReward,
        recipe: RecipeId::SurveyOnly,
    }
}

fn known_case(env_id: &str) -> Option<ComputerUseCase> {
    let (recipe, allowed_tool_profile, max_steps, timeout_seconds, expected_reward_floor, seed) =
        match env_id {
            "click-button" => (
                RecipeId::ClickButton,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                101,
            ),
            "click-link" => (
                RecipeId::ClickLink,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                102,
            ),
            "enter-text" => (
                RecipeId::EnterText,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                103,
            ),
            "focus-text" => (
                RecipeId::FocusText,
                AllowedToolProfile::BrowserCore,
                6,
                20,
                1.0,
                104,
            ),
            "choose-list" => (
                RecipeId::ChooseList,
                AllowedToolProfile::BrowserCoreWithSelect,
                10,
                20,
                1.0,
                105,
            ),
            "click-tab" | "click-tab-2" | "click-tab-2-easy" | "click-tab-2-medium"
            | "click-tab-2-hard" => (
                RecipeId::ClickTab,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "use-autocomplete" | "use-autocomplete-nodelay" => (
                RecipeId::UseAutocomplete,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                107,
            ),
            "scroll-text-2" => (
                RecipeId::ScrollText2,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                108,
            ),
            "click-option" => (
                RecipeId::ClickOption,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                201,
            ),
            "click-checkboxes" | "click-checkboxes-soft" | "click-checkboxes-large" => (
                RecipeId::ClickCheckboxes,
                AllowedToolProfile::BrowserCore,
                16,
                20,
                0.5,
                survey_seed(env_id),
            ),
            "click-checkboxes-transfer" => (
                RecipeId::ClickCheckboxesTransfer,
                AllowedToolProfile::BrowserCore,
                16,
                20,
                0.5,
                203,
            ),
            "enter-password" => (
                RecipeId::EnterPassword,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                204,
            ),
            "login-user" => (
                RecipeId::LoginUser,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                205,
            ),
            "focus-text-2" => (
                RecipeId::FocusText2,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                206,
            ),
            "enter-text-2" => (
                RecipeId::EnterText2,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                207,
            ),
            "click-button-sequence" => (
                RecipeId::ClickButtonSequence,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                208,
            ),
            "click-collapsible" | "click-collapsible-nodelay" => (
                RecipeId::ClickCollapsible,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "click-collapsible-2" | "click-collapsible-2-nodelay" => (
                RecipeId::ClickCollapsible2,
                AllowedToolProfile::BrowserCore,
                16,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "search-engine" => (
                RecipeId::SearchEngine,
                AllowedToolProfile::BrowserCore,
                18,
                25,
                1.0,
                302,
            ),
            "form-sequence" => (
                RecipeId::FormSequence,
                AllowedToolProfile::BrowserCore,
                18,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "form-sequence-2" => (
                RecipeId::FormSequence2,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "form-sequence-3" => (
                RecipeId::FormSequence3,
                AllowedToolProfile::BrowserCoreWithSelect,
                12,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "login-user-popup" => (
                RecipeId::LoginUserPopup,
                AllowedToolProfile::BrowserCore,
                16,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "text-editor" => (
                RecipeId::TextEditor,
                AllowedToolProfile::BrowserCoreWithSelectionClipboard,
                16,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "simple-arithmetic" => (
                RecipeId::SimpleArithmetic,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "simple-algebra" => (
                RecipeId::SimpleAlgebra,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "odd-or-even" => (
                RecipeId::OddOrEven,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "guess-number" => (
                RecipeId::GuessNumber,
                AllowedToolProfile::BrowserCore,
                16,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "count-sides" => (
                RecipeId::CountSides,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "find-greatest" => (
                RecipeId::FindGreatest,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "find-word" => (
                RecipeId::FindWord,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "read-table" => (
                RecipeId::ReadTable,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "read-table-2" => (
                RecipeId::ReadTable2,
                AllowedToolProfile::BrowserCore,
                14,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "phone-book" => (
                RecipeId::PhoneBook,
                AllowedToolProfile::BrowserCore,
                18,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "social-media" => (
                RecipeId::SocialMedia,
                AllowedToolProfile::BrowserCore,
                18,
                25,
                1.0,
                survey_seed(env_id),
            ),
            "social-media-all" => (
                RecipeId::SocialMediaAll,
                AllowedToolProfile::BrowserCore,
                24,
                30,
                1.0,
                survey_seed(env_id),
            ),
            "social-media-some" => (
                RecipeId::SocialMediaSome,
                AllowedToolProfile::BrowserCore,
                24,
                30,
                1.0,
                survey_seed(env_id),
            ),
            "email-inbox"
            | "email-inbox-delete"
            | "email-inbox-forward-nl"
            | "email-inbox-forward-nl-turk"
            | "email-inbox-forward"
            | "email-inbox-important"
            | "email-inbox-nl-turk"
            | "email-inbox-reply"
            | "email-inbox-noscroll"
            | "email-inbox-star-reply" => (
                RecipeId::EmailInbox,
                AllowedToolProfile::BrowserCore,
                20,
                30,
                1.0,
                survey_seed(env_id),
            ),
            "stock-market" => (
                RecipeId::StockMarket,
                AllowedToolProfile::BrowserCore,
                30,
                35,
                1.0,
                survey_seed(env_id),
            ),
            "visual-addition" => (
                RecipeId::VisualAddition,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "identify-shape" => (
                RecipeId::IdentifyShape,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "count-shape" => (
                RecipeId::CountShape,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "find-midpoint" => (
                RecipeId::FindMidpoint,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "unicode-test" => (
                RecipeId::ClickButton,
                AllowedToolProfile::BrowserCore,
                8,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "hover-shape" => (
                RecipeId::HoverShape,
                AllowedToolProfile::BrowserCore,
                12,
                20,
                0.0,
                survey_seed(env_id),
            ),
            "drag-items" => (
                RecipeId::DragItems,
                AllowedToolProfile::BrowserCore,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "highlight-text" | "highlight-text-2" => (
                RecipeId::HighlightText,
                AllowedToolProfile::BrowserCoreWithSelectionClipboard,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            "copy-paste" | "copy-paste-2" => (
                RecipeId::CopyPaste,
                AllowedToolProfile::BrowserCoreWithSelectionClipboard,
                10,
                20,
                1.0,
                survey_seed(env_id),
            ),
            _ => return None,
        };

    Some(ComputerUseCase {
        id: format!("miniwob_catalog_{}", sanitize_env_id(env_id)),
        env_id: env_id.to_string(),
        seed,
        task_set: TaskSet::Catalog,
        max_steps,
        timeout_seconds,
        allowed_tool_profile,
        expected_reward_floor,
        expected_pass: true,
        local_judge: match recipe {
            RecipeId::HoverShape => LocalJudge::HoverShapeReceipts,
            _ => LocalJudge::MiniwobReward,
        },
        recipe,
    })
}

fn sanitize_env_id(env_id: &str) -> String {
    env_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn survey_seed(env_id: &str) -> u64 {
    env_id.bytes().fold(9_000_u64, |acc, byte| {
        acc.wrapping_mul(33).wrapping_add(byte as u64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn catalog_discovery_maps_known_aliases_and_unknown_tasks() -> Result<()> {
        let temp = tempdir()?;
        let html_root = temp.path().join("miniwob").join("html");
        fs::create_dir_all(html_root.join("core"))?;
        fs::create_dir_all(html_root.join("miniwob"))?;
        fs::write(html_root.join("core").join("core.js"), b"// core")?;
        fs::write(
            html_root.join("miniwob").join("click-button.html"),
            b"<html></html>",
        )?;
        fs::write(
            html_root
                .join("miniwob")
                .join("click-collapsible-nodelay.html"),
            b"<html></html>",
        )?;
        fs::write(
            html_root.join("miniwob").join("hover-shape.html"),
            b"<html></html>",
        )?;
        fs::write(
            html_root.join("miniwob").join("ascending-numbers.html"),
            b"<html></html>",
        )?;

        let cases = cases(Some(temp.path()))?;
        let by_env = cases
            .into_iter()
            .map(|case| (case.env_id.clone(), case))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(by_env["click-button"].recipe, RecipeId::ClickButton);
        assert_eq!(
            by_env["click-collapsible-nodelay"].recipe,
            RecipeId::ClickCollapsible
        );
        assert_eq!(by_env["hover-shape"].recipe, RecipeId::HoverShape);
        assert_eq!(by_env["ascending-numbers"].recipe, RecipeId::SurveyOnly);
        assert_eq!(
            by_env["ascending-numbers"].max_steps,
            DEFAULT_CATALOG_SURVEY_MAX_STEPS
        );
        Ok(())
    }
}
