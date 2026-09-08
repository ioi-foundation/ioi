// Test-only snapshots of store bytes. These are fixture containers, never member
// state, journal records, or recovery authority. Directory restores are confined
// to flat files/empty staging directories previously captured by this helper.
const TEST_DIRECTORY_MAGIC: &[u8; 8] = b"AFTTESTD";

fn read_test_store(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let path = path.as_ref();
    if !path.is_dir() {
        return std::fs::read(path);
    }
    let mut entries = Vec::<(String, bool, Vec<u8>)>::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
        let kind = entry.file_type()?;
        let (directory, bytes) = if kind.is_file() {
            (false, std::fs::read(entry.path())?)
        } else if kind.is_dir() && std::fs::read_dir(entry.path())?.next().is_none() {
            (true, Vec::new())
        } else {
            return Err(std::io::ErrorKind::InvalidData.into());
        };
        entries.push((name, directory, bytes));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut result = TEST_DIRECTORY_MAGIC.to_vec();
    result.extend(codec::to_bytes_canonical(&entries).map_err(std::io::Error::other)?);
    Ok(result)
}

fn write_test_store(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    let contents = contents.as_ref();
    if !path.is_dir() {
        return std::fs::write(path, contents);
    }
    let encoded = contents.strip_prefix(TEST_DIRECTORY_MAGIC).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "directory fixture snapshot required; a legacy state blob is not a journal",
        )
    })?;
    let entries: Vec<(String, bool, Vec<u8>)> =
        codec::from_bytes_canonical(encoded).map_err(std::io::Error::other)?;
    let mut names = BTreeSet::new();
    for (name, directory, bytes) in &entries {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
            || !names.insert(name)
            || (*directory && !bytes.is_empty())
        {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    // Validate the existing flat fixture before touching any entry.
    read_test_store(path)?;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    for (name, directory, bytes) in entries {
        if directory {
            std::fs::create_dir(path.join(name))?;
        } else {
            std::fs::write(path.join(name), bytes)?;
        }
    }
    Ok(())
}
