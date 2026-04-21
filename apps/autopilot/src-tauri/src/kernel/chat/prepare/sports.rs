use ioi_api::runtime_harness::ChatIntentContext;
use serde::Deserialize;

#[derive(Clone, Copy)]
struct SportsTeamTarget {
    aliases: &'static [&'static str],
    display_name: &'static str,
    sport_path: &'static str,
    team_id: &'static str,
}

const SPORTS_TEAM_TARGETS: &[SportsTeamTarget] = &[
    SportsTeamTarget {
        aliases: &["lakers", "los angeles lakers"],
        display_name: "Los Angeles Lakers",
        sport_path: "basketball/nba",
        team_id: "13",
    },
    SportsTeamTarget {
        aliases: &["celtics", "boston celtics"],
        display_name: "Boston Celtics",
        sport_path: "basketball/nba",
        team_id: "2",
    },
    SportsTeamTarget {
        aliases: &["warriors", "golden state warriors"],
        display_name: "Golden State Warriors",
        sport_path: "basketball/nba",
        team_id: "9",
    },
    SportsTeamTarget {
        aliases: &["knicks", "new york knicks"],
        display_name: "New York Knicks",
        sport_path: "basketball/nba",
        team_id: "18",
    },
    SportsTeamTarget {
        aliases: &["yankees", "new york yankees"],
        display_name: "New York Yankees",
        sport_path: "baseball/mlb",
        team_id: "10",
    },
    SportsTeamTarget {
        aliases: &["dodgers", "los angeles dodgers"],
        display_name: "Los Angeles Dodgers",
        sport_path: "baseball/mlb",
        team_id: "19",
    },
    SportsTeamTarget {
        aliases: &["chiefs", "kansas city chiefs"],
        display_name: "Kansas City Chiefs",
        sport_path: "football/nfl",
        team_id: "12",
    },
    SportsTeamTarget {
        aliases: &["cowboys", "dallas cowboys"],
        display_name: "Dallas Cowboys",
        sport_path: "football/nfl",
        team_id: "6",
    },
    SportsTeamTarget {
        aliases: &["packers", "green bay packers"],
        display_name: "Green Bay Packers",
        sport_path: "football/nfl",
        team_id: "9",
    },
    SportsTeamTarget {
        aliases: &["steelers", "pittsburgh steelers"],
        display_name: "Pittsburgh Steelers",
        sport_path: "football/nfl",
        team_id: "23",
    },
    SportsTeamTarget {
        aliases: &["eagles", "philadelphia eagles"],
        display_name: "Philadelphia Eagles",
        sport_path: "football/nfl",
        team_id: "21",
    },
];

#[derive(Deserialize)]
struct EspnTeamEnvelope {
    team: EspnTeamSummary,
}

#[derive(Deserialize)]
struct EspnTeamSummary {
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(rename = "standingSummary", default)]
    standing_summary: Option<String>,
    #[serde(default)]
    record: Option<EspnRecord>,
    #[serde(rename = "nextEvent", default)]
    next_event: Vec<EspnEvent>,
}

#[derive(Deserialize)]
struct EspnRecord {
    #[serde(default)]
    items: Vec<EspnRecordItem>,
}

#[derive(Deserialize)]
struct EspnRecordItem {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Deserialize)]
struct EspnEvent {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct EspnNewsEnvelope {
    #[serde(default)]
    articles: Vec<EspnNewsArticle>,
}

#[derive(Deserialize)]
struct EspnNewsArticle {
    #[serde(default)]
    headline: Option<String>,
}

fn sports_team_target_for_intent(intent: &str) -> Option<SportsTeamTarget> {
    let lowered = ChatIntentContext::new(intent)
        .sports_team_target()
        .map(|target| target.to_ascii_lowercase())
        .unwrap_or_else(|| intent.to_ascii_lowercase());
    SPORTS_TEAM_TARGETS
        .iter()
        .copied()
        .find(|target| target.aliases.iter().any(|alias| lowered.contains(alias)))
}

fn record_summary_for_description(record: &EspnRecord, description: &str) -> Option<String> {
    record.items.iter().find_map(|item| {
        let item_description = item.description.as_deref()?.trim();
        if item_description.eq_ignore_ascii_case(description) {
            item.summary
                .as_deref()
                .map(str::trim)
                .filter(|summary| !summary.is_empty())
                .map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

pub(super) fn fetch_sports_tool_widget_reply(intent: &str) -> Result<String, String> {
    let team = sports_team_target_for_intent(intent).ok_or_else(|| {
        "Chat could not determine which team to use for the sports request.".to_string()
    })?;
    let client = super::places::chat_surface_http_client()?;

    let team_url = format!(
        "https://site.api.espn.com/apis/site/v2/sports/{}/teams/{}",
        team.sport_path, team.team_id
    );
    let team_data = client
        .get(&team_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| format!("Chat sports surface could not fetch team data: {error}"))?
        .json::<EspnTeamEnvelope>()
        .map_err(|error| format!("Chat sports surface could not read team data: {error}"))?;

    let news_url = format!(
        "https://site.api.espn.com/apis/site/v2/sports/{}/news?team={}",
        team.sport_path, team.team_id
    );
    let news_data = client
        .get(&news_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| format!("Chat sports surface could not fetch team headlines: {error}"))?
        .json::<EspnNewsEnvelope>()
        .map_err(|error| format!("Chat sports surface could not read team headlines: {error}"))?;

    let team_summary = team_data.team;
    let team_name = team_summary
        .display_name
        .as_deref()
        .unwrap_or(team.display_name);
    let overall = team_summary
        .record
        .as_ref()
        .and_then(|record| record_summary_for_description(record, "Overall Record"))
        .unwrap_or_else(|| "their current record was unavailable".to_string());
    let standing = team_summary
        .standing_summary
        .as_deref()
        .unwrap_or("their current standing was unavailable");
    let mut lines = vec![format!(
        "{team_name} are {overall} and ESPN currently lists them as {standing}."
    )];

    if let Some(record) = team_summary.record.as_ref() {
        let home = record_summary_for_description(record, "Home Record");
        let away = record_summary_for_description(record, "Away Record");
        if home.is_some() || away.is_some() {
            lines.push(format!(
                "Split: {} at home and {} away.",
                home.unwrap_or_else(|| "record unavailable".to_string()),
                away.unwrap_or_else(|| "record unavailable".to_string())
            ));
        }
    }

    if let Some(next_event) = team_summary
        .next_event
        .iter()
        .find_map(|event| event.name.as_deref())
    {
        lines.push(format!("Next listed game: {next_event}."));
    }

    let headlines = news_data
        .articles
        .iter()
        .filter_map(|article| article.headline.as_deref())
        .take(3)
        .collect::<Vec<_>>();
    if !headlines.is_empty() {
        lines.push("Recent headlines:".to_string());
        for headline in headlines {
            lines.push(format!("- {headline}"));
        }
    }

    Ok(lines.join("\n"))
}
