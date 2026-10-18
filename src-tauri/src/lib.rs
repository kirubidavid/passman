mod commands;
mod crypto;
mod models;
mod persistence;
mod totp;

use models::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::export_backup,
            commands::import_backup,
            commands::change_master_password,
            commands::authenticated_reset_vault,
            commands::recovery_reset_vault,
            commands::list_entries,
            commands::set_vault_preferences,
            commands::get_entry,
            commands::get_entry_password,
            commands::get_totp_code,
            commands::set_totp_secret,
            commands::remove_totp_secret,
            commands::save_entry,
            commands::delete_entry,
            commands::generate_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running Passman");
}
