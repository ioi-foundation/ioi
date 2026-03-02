mod check_which_apps_are_using_the_most_memory_right_now_and_list_them;
mod compress_the_projects_folder_into_a_zip_file_and_put_it_on_my_desktop;
mod create_a_new_folder_on_my_desktop_called_project_some_number;
mod download_and_install_vlc_media_player;
mod find_all_pdf_files_on_my_computer_modified_in_the_last_week;
mod move_all_png_files_from_downloads_into_a_new_folder_called_images;
mod multiply_247_by_38;
mod open_calculator_app;
mod read_me_the_last_email_i_received;
mod rename_every_file_in_my_downloads_folder_to_lowercase;
mod set_timer_15_minutes;
mod summarize_the_contents_of_the_most_recent_document_in_my_documents_folder;
mod take_a_screenshot_of_my_desktop;
mod top_news_headlines;
mod uninstall_spotify_and_remove_its_leftover_config_files;
mod weather_right_now;
mod what_time_is_it;
mod whats_the_current_price_of_bitcoin;

use super::types::QueryCase;

pub fn all_cases() -> Vec<QueryCase> {
    let mut cases = vec![
        what_time_is_it::case(),
        weather_right_now::case(),
        whats_the_current_price_of_bitcoin::case(),
        check_which_apps_are_using_the_most_memory_right_now_and_list_them::case(),
        open_calculator_app::case(),
        set_timer_15_minutes::case(),
        compress_the_projects_folder_into_a_zip_file_and_put_it_on_my_desktop::case(),
        create_a_new_folder_on_my_desktop_called_project_some_number::case(),
        download_and_install_vlc_media_player::case(),
        download_and_install_vlc_media_player::case_unseeded(),
        find_all_pdf_files_on_my_computer_modified_in_the_last_week::case(),
        move_all_png_files_from_downloads_into_a_new_folder_called_images::case(),
        rename_every_file_in_my_downloads_folder_to_lowercase::case(),
        summarize_the_contents_of_the_most_recent_document_in_my_documents_folder::case(),
        uninstall_spotify_and_remove_its_leftover_config_files::case(),
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
