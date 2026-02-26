mod multiply_247_by_38;
mod open_calculator_app;
mod set_timer_15_minutes;
mod take_a_screenshot_of_my_desktop;
mod top_news_headlines;
mod weather_right_now;
mod what_time_is_it;

use super::types::QueryCase;

pub fn all_cases() -> Vec<QueryCase> {
    let mut cases = vec![
        what_time_is_it::case(),
        weather_right_now::case(),
        open_calculator_app::case(),
        set_timer_15_minutes::case(),
        take_a_screenshot_of_my_desktop::case(),
        multiply_247_by_38::case(),
        top_news_headlines::case(),
    ];

    if let Ok(only_case) = std::env::var("CAPABILITIES_ONLY_CASE") {
        let wanted = only_case.trim().to_ascii_lowercase();
        if !wanted.is_empty() {
            cases.retain(|case| case.id.eq_ignore_ascii_case(&wanted));
        }
    }

    cases
}
