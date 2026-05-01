fn csv_escape_cell(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_header_columns(body: &str) -> Vec<String> {
    body.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| {
            line.split(',')
                .map(|column| column.trim().trim_matches('"'))
                .filter(|column| !column.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["record".to_string(), "detail".to_string()])
}

fn csv_body_looks_complete(body: &str) -> bool {
    let lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    lines.len() >= 3
        && lines.first().is_some_and(|line| line.contains(','))
        && lines.iter().skip(1).all(|line| line.contains(','))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadBundleExportFormat {
    Csv,
    Docx,
    Odt,
    Xlsx,
    Pptx,
    Json,
    Markdown,
    Text,
}

fn infer_download_bundle_export_format_from_text(
    value: &str,
) -> Option<DownloadBundleExportFormat> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("powerpoint") || lower.contains("pptx") || lower.contains("slide deck") {
        return Some(DownloadBundleExportFormat::Pptx);
    }
    if lower.contains("word doc")
        || lower.contains("word document")
        || lower.contains(".docx")
        || lower.contains(" docx")
    {
        return Some(DownloadBundleExportFormat::Docx);
    }
    if lower.contains("open document")
        || lower.contains("openoffice document")
        || lower.contains("odt")
        || lower.contains(".odt")
    {
        return Some(DownloadBundleExportFormat::Odt);
    }
    if lower.contains("spreadsheet")
        || lower.contains("workbook")
        || lower.contains(".xlsx")
        || lower.contains(" xlsx")
    {
        return Some(DownloadBundleExportFormat::Xlsx);
    }
    if lower.contains(".csv") || lower.contains(" csv") {
        return Some(DownloadBundleExportFormat::Csv);
    }
    if lower.contains(".json") || lower.contains(" json") {
        return Some(DownloadBundleExportFormat::Json);
    }
    if lower.contains(".md") || lower.contains(" markdown") {
        return Some(DownloadBundleExportFormat::Markdown);
    }
    if lower.contains(".txt") || lower.contains(" text file") {
        return Some(DownloadBundleExportFormat::Text);
    }
    None
}

pub(crate) fn infer_download_bundle_export_format_from_path_and_mime(
    path: &str,
    mime: &str,
) -> Option<DownloadBundleExportFormat> {
    let lower_path = path.to_ascii_lowercase();
    let lower_mime = mime.to_ascii_lowercase();
    if lower_path.ends_with(".csv") || lower_mime == "text/csv" {
        return Some(DownloadBundleExportFormat::Csv);
    }
    if lower_path.ends_with(".docx")
        || lower_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    {
        return Some(DownloadBundleExportFormat::Docx);
    }
    if lower_path.ends_with(".odt") || lower_mime == "application/vnd.oasis.opendocument.text" {
        return Some(DownloadBundleExportFormat::Odt);
    }
    if lower_path.ends_with(".xlsx")
        || lower_mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    {
        return Some(DownloadBundleExportFormat::Xlsx);
    }
    if lower_path.ends_with(".pptx")
        || lower_mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    {
        return Some(DownloadBundleExportFormat::Pptx);
    }
    if lower_path.ends_with(".json") || lower_mime == "application/json" {
        return Some(DownloadBundleExportFormat::Json);
    }
    if lower_path.ends_with(".md") || lower_mime == "text/markdown" {
        return Some(DownloadBundleExportFormat::Markdown);
    }
    if lower_path.ends_with(".txt") || lower_mime == "text/plain" {
        return Some(DownloadBundleExportFormat::Text);
    }
    None
}

fn infer_download_bundle_export_format(
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
    brief: Option<&ChatArtifactBrief>,
    intent: Option<&str>,
) -> DownloadBundleExportFormat {
    if let Some(intent) = intent.and_then(infer_download_bundle_export_format_from_text) {
        return intent;
    }
    for (path, mime) in file_hints {
        if is_download_bundle_readme_file(path, mime) {
            continue;
        }
        if let Some(format) = infer_download_bundle_export_format_from_path_and_mime(path, mime) {
            return format;
        }
    }
    if let Some(brief) = brief {
        if let Some(format) = infer_download_bundle_export_format_from_text(&brief.artifact_thesis)
        {
            return format;
        }
        if let Some(format) = infer_download_bundle_export_format_from_text(&brief.subject_domain) {
            return format;
        }
    }
    if let Some(format) = infer_download_bundle_export_format_from_text(summary) {
        return format;
    }
    for note in notes {
        if let Some(format) = infer_download_bundle_export_format_from_text(note) {
            return format;
        }
    }
    DownloadBundleExportFormat::Csv
}

pub(crate) fn download_bundle_export_format_label(
    format: DownloadBundleExportFormat,
) -> &'static str {
    match format {
        DownloadBundleExportFormat::Csv => "CSV export",
        DownloadBundleExportFormat::Docx => "Word document export",
        DownloadBundleExportFormat::Odt => "OpenDocument text export",
        DownloadBundleExportFormat::Xlsx => "spreadsheet export",
        DownloadBundleExportFormat::Pptx => "presentation export",
        DownloadBundleExportFormat::Json => "JSON export",
        DownloadBundleExportFormat::Markdown => "Markdown export",
        DownloadBundleExportFormat::Text => "text export",
    }
}

fn slugify_download_bundle_subject(value: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !slug.is_empty() {
            slug.push('-');
            last_dash = true;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "download".to_string()
    } else {
        slug
    }
}

fn default_download_bundle_export_path(
    format: DownloadBundleExportFormat,
    subject: &str,
) -> String {
    let slug = slugify_download_bundle_subject(subject);
    match format {
        DownloadBundleExportFormat::Csv => format!("exports/{slug}.csv"),
        DownloadBundleExportFormat::Docx => format!("exports/{slug}.docx"),
        DownloadBundleExportFormat::Odt => format!("exports/{slug}.odt"),
        DownloadBundleExportFormat::Xlsx => format!("exports/{slug}.xlsx"),
        DownloadBundleExportFormat::Pptx => format!("exports/{slug}.pptx"),
        DownloadBundleExportFormat::Json => format!("exports/{slug}.json"),
        DownloadBundleExportFormat::Markdown => format!("exports/{slug}.md"),
        DownloadBundleExportFormat::Text => format!("exports/{slug}.txt"),
    }
}

fn default_download_bundle_export_mime(format: DownloadBundleExportFormat) -> &'static str {
    match format {
        DownloadBundleExportFormat::Csv => "text/csv",
        DownloadBundleExportFormat::Docx => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        DownloadBundleExportFormat::Odt => "application/vnd.oasis.opendocument.text",
        DownloadBundleExportFormat::Xlsx => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        DownloadBundleExportFormat::Pptx => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        DownloadBundleExportFormat::Json => "application/json",
        DownloadBundleExportFormat::Markdown => "text/markdown",
        DownloadBundleExportFormat::Text => "text/plain",
    }
}

fn download_bundle_export_encoding(
    format: DownloadBundleExportFormat,
) -> ChatGeneratedArtifactEncoding {
    match format {
        DownloadBundleExportFormat::Docx
        | DownloadBundleExportFormat::Odt
        | DownloadBundleExportFormat::Xlsx
        | DownloadBundleExportFormat::Pptx => ChatGeneratedArtifactEncoding::Base64,
        DownloadBundleExportFormat::Csv
        | DownloadBundleExportFormat::Json
        | DownloadBundleExportFormat::Markdown
        | DownloadBundleExportFormat::Text => ChatGeneratedArtifactEncoding::Utf8,
    }
}

fn xml_escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn zip_entry_names_from_base64(body: &str) -> Option<BTreeSet<String>> {
    let bytes = STANDARD.decode(body.trim()).ok()?;
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).ok()?;
    let mut entries = BTreeSet::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).ok()?;
        entries.insert(file.name().to_string());
    }
    Some(entries)
}

fn zip_body_contains_entries(body: &str, required_entries: &[&str]) -> bool {
    let Some(entries) = zip_entry_names_from_base64(body) else {
        return false;
    };
    required_entries
        .iter()
        .all(|entry| entries.contains(*entry))
}

fn zip_bytes_from_entries(entries: Vec<(String, Vec<u8>, CompressionMethod)>) -> Option<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    for (path, bytes, method) in entries {
        writer
            .start_file(path, FileOptions::default().compression_method(method))
            .ok()?;
        writer.write_all(&bytes).ok()?;
    }
    let cursor = writer.finish().ok()?;
    Some(cursor.into_inner())
}

fn office_core_properties_xml(title: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\
<dc:title>{}</dc:title>\
<dc:creator>Chat</dc:creator>\
<cp:lastModifiedBy>Chat</cp:lastModifiedBy>\
<dcterms:created xsi:type=\"dcterms:W3CDTF\">2026-04-15T00:00:00Z</dcterms:created>\
<dcterms:modified xsi:type=\"dcterms:W3CDTF\">2026-04-15T00:00:00Z</dcterms:modified>\
</cp:coreProperties>",
        xml_escape_text(title)
    )
}

fn office_app_properties_xml(application: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">\
<Application>{}</Application>\
</Properties>",
        xml_escape_text(application)
    )
}

fn docx_document_xml_from_lines(lines: &[String]) -> String {
    let paragraphs = lines
        .iter()
        .map(|line| {
            format!(
                "<w:p><w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                xml_escape_text(line)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:document xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:o=\"urn:schemas-microsoft-com:office:office\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" mc:Ignorable=\"w14 wp14\">\
<w:body>{}<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/><w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\" w:header=\"708\" w:footer=\"708\" w:gutter=\"0\"/></w:sectPr></w:body>\
</w:document>",
        paragraphs
    )
}

fn docx_styles_xml() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\"/></w:style>\
</w:styles>"
}

fn synthesize_docx_package_bytes(title: &str, body: &str) -> Option<Vec<u8>> {
    let lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    zip_bytes_from_entries(vec![
        (
            "[Content_Types].xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "_rels/.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/core.xml".to_string(),
            office_core_properties_xml(title).into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/app.xml".to_string(),
            office_app_properties_xml("Chat").into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "word/document.xml".to_string(),
            docx_document_xml_from_lines(&lines).into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "word/styles.xml".to_string(),
            docx_styles_xml().as_bytes().to_vec(),
            CompressionMethod::Deflated,
        ),
    ])
}

fn odt_content_xml_from_lines(title: &str, lines: &[String]) -> String {
    let paragraphs = lines
        .iter()
        .map(|line| format!("<text:p>{}</text:p>", xml_escape_text(line)))
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<office:document-content xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" office:version=\"1.2\">\
<office:body><office:text><text:h text:outline-level=\"1\">{}</text:h>{}</office:text></office:body>\
</office:document-content>",
        xml_escape_text(title),
        paragraphs
    )
}

fn synthesize_odt_package_bytes(title: &str, body: &str) -> Option<Vec<u8>> {
    let lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    zip_bytes_from_entries(vec![
        (
            "mimetype".to_string(),
            b"application/vnd.oasis.opendocument.text".to_vec(),
            CompressionMethod::Stored,
        ),
        (
            "content.xml".to_string(),
            odt_content_xml_from_lines(title, &lines).into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "styles.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8"?><office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.2"><office:styles/></office:document-styles>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "meta.xml".to_string(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><office:document-meta xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" office:version=\"1.2\"><office:meta><dc:title>{}</dc:title></office:meta></office:document-meta>",
                xml_escape_text(title)
            )
            .into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "settings.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8"?><office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.2"><office:settings/></office:document-settings>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "META-INF/manifest.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2"><manifest:file-entry manifest:media-type="application/vnd.oasis.opendocument.text" manifest:full-path="/"/><manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/><manifest:file-entry manifest:media-type="text/xml" manifest:full-path="styles.xml"/><manifest:file-entry manifest:media-type="text/xml" manifest:full-path="meta.xml"/><manifest:file-entry manifest:media-type="text/xml" manifest:full-path="settings.xml"/></manifest:manifest>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
    ])
}

fn xlsx_inline_string_cell(reference: &str, value: &str) -> String {
    format!(
        "<c r=\"{reference}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
        xml_escape_text(value)
    )
}

fn xlsx_number_cell(reference: &str, value: i32) -> String {
    format!("<c r=\"{reference}\"><v>{value}</v></c>")
}

fn xlsx_formula_cell(reference: &str, formula: &str) -> String {
    format!(
        "<c r=\"{reference}\"><f>{}</f><v>0</v></c>",
        xml_escape_text(formula)
    )
}

fn xlsx_row(index: usize, cells: Vec<String>) -> String {
    format!("<row r=\"{index}\">{}</row>", cells.join(""))
}

fn synthesize_xlsx_package_bytes(
    title: &str,
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> Option<Vec<u8>> {
    let focus = download_bundle_focus_points(summary, notes, brief);
    let metric_a = focus
        .first()
        .cloned()
        .unwrap_or_else(|| "Primary metric".to_string());
    let metric_b = focus
        .get(1)
        .cloned()
        .unwrap_or_else(|| "Secondary metric".to_string());
    let metric_c = focus
        .get(2)
        .cloned()
        .unwrap_or_else(|| "Operator note".to_string());
    let overview_rows = [
        xlsx_row(
            1,
            vec![
                xlsx_inline_string_cell("A1", "Metric"),
                xlsx_inline_string_cell("B1", "Q1"),
                xlsx_inline_string_cell("C1", "Q2"),
                xlsx_inline_string_cell("D1", "Q3"),
                xlsx_inline_string_cell("E1", "Q4"),
                xlsx_inline_string_cell("F1", "Annual Total"),
            ],
        ),
        xlsx_row(
            2,
            vec![
                xlsx_inline_string_cell("A2", &metric_a),
                xlsx_number_cell("B2", 72),
                xlsx_number_cell("C2", 76),
                xlsx_number_cell("D2", 81),
                xlsx_number_cell("E2", 84),
                xlsx_formula_cell("F2", "SUM(B2:E2)"),
            ],
        ),
        xlsx_row(
            3,
            vec![
                xlsx_inline_string_cell("A3", &metric_b),
                xlsx_number_cell("B3", 64),
                xlsx_number_cell("C3", 68),
                xlsx_number_cell("D3", 70),
                xlsx_number_cell("E3", 75),
                xlsx_formula_cell("F3", "SUM(B3:E3)"),
            ],
        ),
        xlsx_row(
            4,
            vec![
                xlsx_inline_string_cell("A4", &metric_c),
                xlsx_number_cell("B4", 58),
                xlsx_number_cell("C4", 61),
                xlsx_number_cell("D4", 66),
                xlsx_number_cell("E4", 69),
                xlsx_formula_cell("F4", "SUM(B4:E4)"),
            ],
        ),
    ]
    .join("");
    let note_lines = std::iter::once(summary.trim().to_string())
        .chain(notes.iter().map(|note| note.trim().to_string()))
        .filter(|line| !line.is_empty())
        .take(6)
        .collect::<Vec<_>>();
    let notes_rows = std::iter::once(xlsx_row(
        1,
        vec![
            xlsx_inline_string_cell("A1", "Section"),
            xlsx_inline_string_cell("B1", "Detail"),
        ],
    ))
    .chain(note_lines.iter().enumerate().map(|(index, line)| {
        xlsx_row(
            index + 2,
            vec![
                xlsx_inline_string_cell(&format!("A{}", index + 2), &format!("Note {}", index + 1)),
                xlsx_inline_string_cell(&format!("B{}", index + 2), line),
            ],
        )
    }))
    .collect::<Vec<_>>()
    .join("");
    let overview_sheet = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>{}</sheetData></worksheet>",
        overview_rows
    );
    let notes_sheet = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>{}</sheetData></worksheet>",
        notes_rows
    );
    zip_bytes_from_entries(vec![
        (
            "[Content_Types].xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "_rels/.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/core.xml".to_string(),
            office_core_properties_xml(title).into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/app.xml".to_string(),
            office_app_properties_xml("Chat").into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "xl/workbook.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Overview" sheetId="1" r:id="rId1"/><sheet name="Notes" sheetId="2" r:id="rId2"/></sheets></workbook>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "xl/_rels/workbook.xml.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "xl/styles.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="1"><font><sz val="11"/><name val="Aptos"/></font></fonts><fills count="1"><fill><patternFill patternType="none"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs></styleSheet>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "xl/worksheets/sheet1.xml".to_string(),
            overview_sheet.into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "xl/worksheets/sheet2.xml".to_string(),
            notes_sheet.into_bytes(),
            CompressionMethod::Deflated,
        ),
    ])
}

fn pptx_slide_xml(title: &str, bullets: &[String]) -> String {
    let title_text = format!(
        "<a:p><a:r><a:rPr lang=\"en-US\" sz=\"2800\" b=\"1\"/><a:t>{}</a:t></a:r></a:p>",
        xml_escape_text(title)
    );
    let body_text = bullets
        .iter()
        .map(|bullet| {
            format!(
                "<a:p><a:pPr lvl=\"0\"/><a:r><a:rPr lang=\"en-US\" sz=\"1800\"/><a:t>{}</a:t></a:r></a:p>",
                xml_escape_text(bullet)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>\
<p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"Title 1\"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"685800\" y=\"457200\"/><a:ext cx=\"7772400\" cy=\"914400\"/></a:xfrm></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/>{}</p:txBody></p:sp>\
<p:sp><p:nvSpPr><p:cNvPr id=\"3\" name=\"Content Placeholder 2\"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"685800\" y=\"1600200\"/><a:ext cx=\"7772400\" cy=\"4114800\"/></a:xfrm></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/>{}</p:txBody></p:sp>\
</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>",
        title_text,
        body_text
    )
}

fn synthesize_pptx_package_bytes(title: &str, body: &str) -> Option<Vec<u8>> {
    let mut slides = Vec::<(String, Vec<String>)>::new();
    let mut current_title: Option<String> = None;
    let mut current_bullets = Vec::<String>::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(rest) = line.strip_prefix("Slide ") {
            if let Some((_, title_part)) = rest.split_once(':') {
                if let Some(previous_title) = current_title.take() {
                    slides.push((previous_title, current_bullets.clone()));
                    current_bullets.clear();
                }
                current_title = Some(title_part.trim().to_string());
                continue;
            }
        }
        let bullet = line.trim_start_matches("- ").trim().to_string();
        if !bullet.is_empty() {
            current_bullets.push(bullet);
        }
    }
    if let Some(previous_title) = current_title.take() {
        slides.push((previous_title, current_bullets));
    }
    if slides.is_empty() {
        slides.push((title.to_string(), vec!["Presentation outline".to_string()]));
    }
    let content_types_overrides = (1..=slides.len())
        .map(|index| format!("<Override PartName=\"/ppt/slides/slide{index}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>"))
        .collect::<Vec<_>>()
        .join("");
    let presentation_slide_ids = (1..=slides.len())
        .map(|index| {
            format!(
                "<p:sldId id=\"{}\" r:id=\"rId{}\"/>",
                255 + index,
                index + 1
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let presentation_rels = std::iter::once(
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"slideMasters/slideMaster1.xml\"/>".to_string(),
    )
    .chain((1..=slides.len()).map(|index| {
        format!(
            "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" Target=\"slides/slide{}.xml\"/>",
            index + 1,
            index
        )
    }))
    .collect::<Vec<_>>()
    .join("");
    let mut entries = vec![
        (
            "[Content_Types].xml".to_string(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/><Override PartName=\"/ppt/slideMasters/slideMaster1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml\"/><Override PartName=\"/ppt/slideLayouts/slideLayout1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml\"/><Override PartName=\"/ppt/theme/theme1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.theme+xml\"/><Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/><Override PartName=\"/docProps/app.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.extended-properties+xml\"/>{}</Types>",
                content_types_overrides
            )
            .into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "_rels/.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/core.xml".to_string(),
            office_core_properties_xml(title).into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "docProps/app.xml".to_string(),
            office_app_properties_xml("Chat").into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/presentation.xml".to_string(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><p:presentation xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst><p:sldIdLst>{}</p:sldIdLst><p:sldSz cx=\"9144000\" cy=\"6858000\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/></p:presentation>",
                presentation_slide_ids
            )
            .into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/_rels/presentation.xml.rels".to_string(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{}</Relationships>",
                presentation_rels
            )
            .into_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/slideMasters/slideMaster1.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld><p:clrMap accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" bg1="lt1" bg2="lt2" folHlink="folHlink" hlink="hlink" tx1="dk1" tx2="dk2"/><p:sldLayoutIdLst><p:sldLayoutId id="1" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/slideLayouts/slideLayout1.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="obj" preserve="1"><p:cSld name="Title and Content"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "ppt/theme/theme1.xml".to_string(),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Chat Theme"><a:themeElements><a:clrScheme name="Chat"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:accent1><a:srgbClr val="2563EB"/></a:accent1><a:accent2><a:srgbClr val="0F172A"/></a:accent2><a:accent3><a:srgbClr val="14B8A6"/></a:accent3><a:accent4><a:srgbClr val="F97316"/></a:accent4><a:accent5><a:srgbClr val="7C3AED"/></a:accent5><a:accent6><a:srgbClr val="DC2626"/></a:accent6><a:hlink><a:srgbClr val="2563EB"/></a:hlink><a:folHlink><a:srgbClr val="7C3AED"/></a:folHlink></a:clrScheme><a:fontScheme name="Chat"><a:majorFont><a:latin typeface="Aptos"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme><a:fmtScheme name="Chat"><a:fillStyleLst><a:solidFill><a:schemeClr val="accent1"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="accent1"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="lt1"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>"#.to_vec(),
            CompressionMethod::Deflated,
        ),
    ];
    for (index, (slide_title, bullets)) in slides.iter().enumerate() {
        let slide_number = index + 1;
        entries.push((
            format!("ppt/slides/slide{slide_number}.xml"),
            pptx_slide_xml(slide_title, bullets).into_bytes(),
            CompressionMethod::Deflated,
        ));
        entries.push((
            format!("ppt/slides/_rels/slide{slide_number}.xml.rels"),
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>"#.to_vec(),
            CompressionMethod::Deflated,
        ));
    }
    zip_bytes_from_entries(entries)
}

fn push_unique_download_bundle_focus(focus: &mut Vec<String>, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() < 4 {
        return;
    }
    if focus
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(trimmed))
    {
        return;
    }
    focus.push(trimmed.to_string());
}

fn download_bundle_focus_points(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> Vec<String> {
    let mut focus = Vec::new();
    if let Some(brief) = brief {
        for concept in &brief.required_concepts {
            push_unique_download_bundle_focus(&mut focus, concept);
        }
        for anchor in &brief.factual_anchors {
            push_unique_download_bundle_focus(&mut focus, anchor);
        }
    }
    for note in notes {
        push_unique_download_bundle_focus(&mut focus, note);
    }
    push_unique_download_bundle_focus(&mut focus, summary);
    if focus.is_empty() {
        focus.push("Executive summary".to_string());
    }
    let defaults = [
        "Executive summary",
        "Operational performance",
        "Financial outlook",
        "Next steps and risks",
    ];
    for default in defaults {
        if focus.len() >= 4 {
            break;
        }
        push_unique_download_bundle_focus(&mut focus, default);
    }
    focus.truncate(4);
    focus
}

fn download_bundle_readme_looks_complete(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.len() >= 80 && trimmed.contains("## Files") {
        return true;
    }

    trimmed.len() >= 24
        && trimmed.starts_with('#')
        && !trimmed.to_ascii_lowercase().contains("placeholder")
}

pub(crate) fn is_download_bundle_readme_file(path: &str, mime: &str) -> bool {
    path.eq_ignore_ascii_case("README.md") || mime.eq_ignore_ascii_case("text/markdown")
}

pub(crate) fn download_bundle_export_body_looks_complete(
    format: DownloadBundleExportFormat,
    body: &str,
) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }
    match format {
        DownloadBundleExportFormat::Csv => csv_body_looks_complete(trimmed),
        DownloadBundleExportFormat::Docx => {
            if zip_body_contains_entries(
                trimmed,
                &[
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "word/document.xml",
                    "word/styles.xml",
                ],
            ) {
                return true;
            }
            trimmed.len() >= 180
                && trimmed
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
                    >= 8
        }
        DownloadBundleExportFormat::Odt => zip_body_contains_entries(
            trimmed,
            &["mimetype", "content.xml", "META-INF/manifest.xml"],
        ),
        DownloadBundleExportFormat::Xlsx => {
            if zip_body_contains_entries(
                trimmed,
                &[
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "xl/workbook.xml",
                    "xl/worksheets/sheet1.xml",
                ],
            ) {
                return true;
            }
            (trimmed.contains("Sheet:")
                || trimmed.contains("Workbook:")
                || trimmed.contains("SUM("))
                && trimmed
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
                    >= 8
        }
        DownloadBundleExportFormat::Pptx => {
            if zip_body_contains_entries(
                trimmed,
                &[
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "ppt/presentation.xml",
                    "ppt/slides/slide1.xml",
                ],
            ) {
                return true;
            }
            trimmed.contains("Slide 1")
                && trimmed
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
                    >= 8
        }
        DownloadBundleExportFormat::Json => {
            serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
        }
        DownloadBundleExportFormat::Markdown | DownloadBundleExportFormat::Text => {
            trimmed.len() >= 120
        }
    }
}

fn synthesize_download_bundle_docx_body(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> String {
    let title = brief
        .map(|value| value.subject_domain.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| summary.trim());
    let audience = brief
        .map(|value| value.audience.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("stakeholders");
    let focus = download_bundle_focus_points(summary, notes, brief);
    let section_two = focus
        .get(1)
        .cloned()
        .unwrap_or_else(|| "Operational performance".to_string());
    let section_three = focus
        .get(2)
        .cloned()
        .unwrap_or_else(|| "Financial outlook".to_string());
    let closing = focus
        .get(3)
        .cloned()
        .unwrap_or_else(|| "Next steps and risks".to_string());

    format!(
        "Cover Page\n{title}\nPrepared for {audience}\n\nTable of Contents\n1. Executive Summary\n2. {section_two}\n3. {section_three}\n4. {closing}\n\nHeaders and Footers\nHeader: {title}\nFooter: Chat prepared export | Page {{n}}\n\nSection 1 Executive Summary\nThis document summarizes the current request in a structured format so the exported file reads like a review-ready Word document instead of a placeholder shell. The opening section frames the objectives, highlights the most important performance signals, and prepares the reader for the detailed sections that follow.\n\nSection 2 {section_two}\nThis section expands the strongest request-grounded theme and gives it enough body text to stand on its own. Include the key outcomes, the supporting evidence behind those outcomes, and the operational interpretation that leadership would expect to see in a quarterly update or comparable internal document.\n\nSection 3 {section_three}\nUse this section for the next layer of analysis, such as performance trends, customer or product impact, or the practical implications of the headline metrics. Keep the writing concrete, readable, and suitable for direct export.\n\nSection 4 {closing}\nClose with a concise summary of next steps, risks, or decisions that follow from the material above so the document ends with clear operator guidance rather than generic filler.\n"
    )
}

fn synthesize_download_bundle_pptx_body(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> String {
    let title = brief
        .map(|value| value.subject_domain.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| summary.trim());
    let focus = download_bundle_focus_points(summary, notes, brief);
    format!(
        "Slide 1: {title}\n- Opening title slide with the core request thesis.\n\nSlide 2: Executive summary\n- Summarize the main takeaway in two or three concise bullets.\n\nSlide 3: {}\n- Present the first major request-grounded point.\n\nSlide 4: {}\n- Present the second major point with supporting evidence.\n\nSlide 5: {}\n- Compare risks, next steps, or decision points.\n\nSpeaker notes\n- Keep each slide tightly grounded in the request and avoid decorative filler.\n",
        focus
            .first()
            .cloned()
            .unwrap_or_else(|| "Primary theme".to_string()),
        focus
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Supporting theme".to_string()),
        focus
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Risks and actions".to_string())
    )
}

fn synthesize_download_bundle_json_body(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> String {
    serde_json::json!({
        "summary": summary.trim(),
        "notes": notes,
        "focus": download_bundle_focus_points(summary, notes, brief),
    })
    .to_string()
}

fn synthesize_download_bundle_markdown_body(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> String {
    let focus = download_bundle_focus_points(summary, notes, brief);
    let mut lines = vec![format!("# {}", summary.trim())];
    lines.push(String::new());
    lines.push("## Focus".to_string());
    for item in focus.iter().take(3) {
        lines.push(format!("- {item}"));
    }
    if !notes.is_empty() {
        lines.push(String::new());
        lines.push("## Notes".to_string());
        for note in notes.iter().take(3) {
            lines.push(format!("- {}", note.trim()));
        }
    }
    lines.join("\n")
}

fn synthesize_download_bundle_text_body(
    summary: &str,
    notes: &[String],
    brief: Option<&ChatArtifactBrief>,
) -> String {
    let focus = download_bundle_focus_points(summary, notes, brief);
    format!(
        "{}\n\nKey points\n- {}\n- {}\n- {}\n",
        summary.trim(),
        focus
            .first()
            .cloned()
            .unwrap_or_else(|| "Executive summary".to_string()),
        focus
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Supporting detail".to_string()),
        focus
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Next steps".to_string())
    )
}

fn synthesize_download_bundle_export_body(
    format: DownloadBundleExportFormat,
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
    brief: Option<&ChatArtifactBrief>,
) -> (ChatGeneratedArtifactEncoding, String) {
    match format {
        DownloadBundleExportFormat::Csv => (
            ChatGeneratedArtifactEncoding::Utf8,
            synthesize_download_bundle_csv_body(summary, notes, file_hints),
        ),
        DownloadBundleExportFormat::Docx => {
            let body = synthesize_download_bundle_docx_body(summary, notes, brief);
            let title = brief
                .map(|value| value.subject_domain.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| summary.trim());
            let bytes = synthesize_docx_package_bytes(title, &body)
                .map(|value| STANDARD.encode(value))
                .unwrap_or_default();
            (ChatGeneratedArtifactEncoding::Base64, bytes)
        }
        DownloadBundleExportFormat::Odt => {
            let body = synthesize_download_bundle_docx_body(summary, notes, brief);
            let title = brief
                .map(|value| value.subject_domain.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| summary.trim());
            let bytes = synthesize_odt_package_bytes(title, &body)
                .map(|value| STANDARD.encode(value))
                .unwrap_or_default();
            (ChatGeneratedArtifactEncoding::Base64, bytes)
        }
        DownloadBundleExportFormat::Xlsx => {
            let title = brief
                .map(|value| value.subject_domain.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| summary.trim());
            let bytes = synthesize_xlsx_package_bytes(title, summary, notes, brief)
                .map(|value| STANDARD.encode(value))
                .unwrap_or_default();
            (ChatGeneratedArtifactEncoding::Base64, bytes)
        }
        DownloadBundleExportFormat::Pptx => {
            let body = synthesize_download_bundle_pptx_body(summary, notes, brief);
            let title = brief
                .map(|value| value.subject_domain.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| summary.trim());
            let bytes = synthesize_pptx_package_bytes(title, &body)
                .map(|value| STANDARD.encode(value))
                .unwrap_or_default();
            (ChatGeneratedArtifactEncoding::Base64, bytes)
        }
        DownloadBundleExportFormat::Json => (
            ChatGeneratedArtifactEncoding::Utf8,
            synthesize_download_bundle_json_body(summary, notes, brief),
        ),
        DownloadBundleExportFormat::Markdown => (
            ChatGeneratedArtifactEncoding::Utf8,
            synthesize_download_bundle_markdown_body(summary, notes, brief),
        ),
        DownloadBundleExportFormat::Text => (
            ChatGeneratedArtifactEncoding::Utf8,
            synthesize_download_bundle_text_body(summary, notes, brief),
        ),
    }
}

fn synthesize_download_bundle_csv_body(
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
) -> String {
    let mut rows = vec![("summary".to_string(), summary.trim().to_string())];

    rows.extend(
        notes
            .iter()
            .filter(|note| !note.trim().is_empty())
            .take(2)
            .enumerate()
            .map(|(index, note)| (format!("note_{}", index + 1), note.trim().to_string())),
    );

    if rows.len() < 3 {
        rows.extend(
            file_hints
                .iter()
                .filter(|(path, _)| !path.eq_ignore_ascii_case("README.md"))
                .take(3 - rows.len())
                .map(|(path, mime)| {
                    (
                        path.clone(),
                        format!("Included in the requested downloadable bundle as {mime}."),
                    )
                }),
        );
    }

    while rows.len() < 3 {
        rows.push((
            format!("item_{}", rows.len()),
            "Request-grounded bundle detail.".to_string(),
        ));
    }

    let mut lines = vec!["record,detail".to_string()];
    lines.extend(rows.into_iter().take(3).map(|(record, detail)| {
        format!("{},{}", csv_escape_cell(&record), csv_escape_cell(&detail))
    }));
    lines.join("\n")
}

fn synthesize_download_bundle_readme_body(
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
    csv_columns: Vec<String>,
) -> String {
    let heading = if summary.trim().is_empty() {
        "Download bundle"
    } else {
        summary.trim()
    };
    let mut lines = vec![
        format!("# {heading}"),
        String::new(),
        "This bundle contains the requested downloadable files and a short explanation of how to use them.".to_string(),
        String::new(),
        "## Files".to_string(),
    ];

    for (path, mime) in file_hints {
        let purpose = if path.eq_ignore_ascii_case("README.md") {
            "Bundle overview, file mapping, and CSV column notes."
        } else if path.to_ascii_lowercase().ends_with(".csv") || mime == "text/csv" {
            "Structured CSV export for the requested bundle."
        } else if let Some(format) =
            infer_download_bundle_export_format_from_path_and_mime(path, mime)
        {
            download_bundle_export_format_label(format)
        } else {
            "Requested downloadable bundle asset."
        };
        lines.push(format!("- `{path}`: {purpose}"));
    }

    if !csv_columns.is_empty() {
        lines.push(String::new());
        lines.push("## CSV columns".to_string());
        for column in csv_columns {
            let description = match column.as_str() {
                "record" => "Label for the bundle record described in the export.",
                "detail" => "Request-grounded detail for that record.",
                _ => "Request-grounded value included in the export.",
            };
            lines.push(format!("- `{column}`: {description}"));
        }
    }

    if !notes.is_empty() {
        lines.push(String::new());
        lines.push("## Notes".to_string());
        for note in notes.iter().take(3) {
            lines.push(format!("- {}", note.trim()));
        }
    }

    let export_formats = file_hints
        .iter()
        .filter_map(|(path, mime)| {
            infer_download_bundle_export_format_from_path_and_mime(path, mime)
        })
        .filter(|format| *format != DownloadBundleExportFormat::Csv)
        .collect::<Vec<_>>();
    if !export_formats.is_empty() {
        lines.push(String::new());
        lines.push("## Export details".to_string());
        for format in export_formats {
            lines.push(format!(
                "- The {} is surfaced in Chat as reviewable source content inside the download card so the authored structure can be inspected before download.",
                download_bundle_export_format_label(format)
            ));
        }
    }

    lines.join("\n")
}

#[allow(dead_code)]
pub(crate) fn synthesize_download_bundle_payload(
    intent: &str,
    brief: &ChatArtifactBrief,
) -> ChatGeneratedArtifactPayload {
    let summary_subject = if brief.subject_domain.trim().is_empty() {
        "requested deliverable"
    } else {
        brief.subject_domain.trim()
    };
    let format = infer_download_bundle_export_format(
        summary_subject,
        &brief.reference_hints,
        &[],
        Some(brief),
        Some(intent),
    );
    let summary = format!(
        "Prepared a {} bundle for {}.",
        download_bundle_export_format_label(format),
        summary_subject
    );
    let notes = vec![
        "Deterministic local bundle fallback recovered a usable download surface after materialization returned no valid payload.".to_string(),
        format!(
            "Primary export format: {}.",
            download_bundle_export_format_label(format)
        ),
    ];
    let export_path = default_download_bundle_export_path(format, summary_subject);
    let export_mime = default_download_bundle_export_mime(format).to_string();
    let mut file_hints = vec![
        (export_path.clone(), export_mime.clone()),
        ("README.md".to_string(), "text/markdown".to_string()),
    ];
    let (export_encoding, export_body) =
        synthesize_download_bundle_export_body(format, &summary, &notes, &file_hints, Some(brief));
    let readme_body = synthesize_download_bundle_readme_body(
        &summary,
        &notes,
        &file_hints,
        if format == DownloadBundleExportFormat::Csv {
            csv_header_columns(&export_body)
        } else {
            Vec::new()
        },
    );
    file_hints[0].1 = export_mime.clone();

    ChatGeneratedArtifactPayload {
        summary,
        notes,
        files: vec![
            ChatGeneratedArtifactFile {
                path: export_path,
                mime: export_mime,
                role: ChatArtifactFileRole::Export,
                renderable: false,
                downloadable: true,
                encoding: Some(export_encoding),
                body: export_body,
            },
            ChatGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: ChatArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: readme_body,
            },
        ],
    }
}

#[allow(dead_code)]
pub(crate) fn synthesize_bundle_manifest_payload(
    intent: &str,
    brief: &ChatArtifactBrief,
) -> ChatGeneratedArtifactPayload {
    let summary_subject = if brief.subject_domain.trim().is_empty() {
        "requested artifact"
    } else {
        brief.subject_domain.trim()
    };
    let summary = format!(
        "Prepared a structured artifact bundle for {}.",
        summary_subject
    );
    let mut notes = vec![
        "Deterministic local bundle-manifest fallback recovered a usable artifact surface after materialization returned no valid JSON payload.".to_string(),
    ];
    if !brief.job_to_be_done.trim().is_empty() {
        notes.push(format!("Goal: {}.", brief.job_to_be_done.trim()));
    }
    if !brief.artifact_thesis.trim().is_empty() {
        notes.push(format!("Thesis: {}.", brief.artifact_thesis.trim()));
    }

    let summary_lines = [
        format!("# {}", summary_subject),
        String::new(),
        summary.clone(),
        String::new(),
        format!("## Request"),
        if intent.trim().is_empty() {
            "No explicit request text was retained.".to_string()
        } else {
            intent.trim().to_string()
        },
        String::new(),
        "## Brief".to_string(),
        format!("Audience: {}", brief.audience.trim()),
        format!("Job to be done: {}", brief.job_to_be_done.trim()),
        format!("Artifact thesis: {}", brief.artifact_thesis.trim()),
        String::new(),
        "## Required concepts".to_string(),
        if brief.required_concepts.is_empty() {
            "- None captured.".to_string()
        } else {
            brief
                .required_concepts
                .iter()
                .map(|concept| format!("- {}", concept.trim()))
                .collect::<Vec<_>>()
                .join("\n")
        },
        String::new(),
        "## Factual anchors".to_string(),
        if brief.factual_anchors.is_empty() {
            "- None captured.".to_string()
        } else {
            brief
                .factual_anchors
                .iter()
                .map(|anchor| format!("- {}", anchor.trim()))
                .collect::<Vec<_>>()
                .join("\n")
        },
    ]
    .join("\n");

    let manifest_body = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "title": summary_subject,
        "summary": summary,
        "request": intent.trim(),
        "job_to_be_done": brief.job_to_be_done.trim(),
        "artifact_thesis": brief.artifact_thesis.trim(),
        "notes": notes,
        "files": [
            {
                "path": "artifact-summary.md",
                "role": "supporting",
                "mime": "text/markdown"
            },
            {
                "path": "README.md",
                "role": "supporting",
                "mime": "text/markdown"
            }
        ]
    }))
    .unwrap_or_else(|_| "{\"version\":1}".to_string());

    let readme_body = [
        "# Bundle contents".to_string(),
        String::new(),
        "This artifact was recovered via the deterministic local bundle-manifest fallback.".to_string(),
        "Review `artifact-summary.md` for the surfaced content summary and `bundle-manifest.json` for the structured inventory.".to_string(),
    ]
    .join("\n");

    ChatGeneratedArtifactPayload {
        summary,
        notes,
        files: vec![
            ChatGeneratedArtifactFile {
                path: "bundle-manifest.json".to_string(),
                mime: "application/json".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: manifest_body,
            },
            ChatGeneratedArtifactFile {
                path: "artifact-summary.md".to_string(),
                mime: "text/markdown".to_string(),
                role: ChatArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: summary_lines,
            },
            ChatGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: ChatArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: readme_body,
            },
        ],
    }
}
