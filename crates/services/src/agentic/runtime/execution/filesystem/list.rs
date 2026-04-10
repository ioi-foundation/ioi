use std::fs;
use std::path::Path;

pub(super) fn list_directory_entries(path: &Path) -> Result<Vec<(String, &'static str)>, String> {
    let entries =
        fs::read_dir(path).map_err(|e| format!("Failed to list {}: {}", path.display(), e))?;

    let mut list = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let type_char = if entry.path().is_dir() { "D" } else { "F" };
        list.push((name, type_char));
    }

    // Deterministic output order prevents flaky tool responses across platforms/filesystems.
    list.sort_by(|(name_a, kind_a), (name_b, kind_b)| {
        name_a.cmp(name_b).then_with(|| kind_a.cmp(kind_b))
    });
    Ok(list)
}
