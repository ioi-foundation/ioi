mod create_a_new_folder_on_my_desktop_called_project_some_number;
mod download_and_install_vlc_media_player;
mod find_all_pdf_files_on_my_computer_modified_in_the_last_week;
mod multiply_247_by_38;
mod open_calculator_app;
mod read_me_the_last_email_i_received;
mod rename_every_file_in_my_downloads_folder_to_lowercase;
mod set_timer_15_minutes;
mod take_a_screenshot_of_my_desktop;
mod top_news_headlines;
mod weather_right_now;
mod what_time_is_it;
mod whats_the_current_price_of_bitcoin;

use super::types::QueryCase;

pub fn all_cases() -> Vec<QueryCase> {
    let mut cases = vec![
        what_time_is_it::case(),
        weather_right_now::case(),
        whats_the_current_price_of_bitcoin::case(),
        open_calculator_app::case(),
        set_timer_15_minutes::case(),
        create_a_new_folder_on_my_desktop_called_project_some_number::case(),
        download_and_install_vlc_media_player::case(),
        find_all_pdf_files_on_my_computer_modified_in_the_last_week::case(),
        rename_every_file_in_my_downloads_folder_to_lowercase::case(),
        take_a_screenshot_of_my_desktop::case(),
        read_me_the_last_email_i_received::case(),
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
