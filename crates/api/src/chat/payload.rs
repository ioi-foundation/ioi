use super::html::*;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub fn parse_chat_generated_artifact_payload(
    raw: &str,
) -> Result<ChatGeneratedArtifactPayload, String> {
    parse_chat_generated_artifact_payload_json(raw)
        .or_else(|_| {
            let extracted = extract_first_json_object(raw).ok_or_else(|| {
                "Chat artifact materialization output missing JSON payload".to_string()
            })?;
            parse_chat_generated_artifact_payload_json(&extracted)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!(
                "Failed to parse Chat artifact materialization payload: {}",
                error
            )
        })
}

fn parse_chat_generated_artifact_payload_json(
    raw: &str,
) -> Result<ChatGeneratedArtifactPayload, serde_json::Error> {
    let mut value = serde_json::from_str::<serde_json::Value>(raw)?;
    normalize_generated_artifact_payload_value(&mut value);
    serde_json::from_value::<ChatGeneratedArtifactPayload>(value)
}

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
    trimmed.len() >= 80 && trimmed.contains("## Files")
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

fn normalize_generated_artifact_payload_value(value: &mut serde_json::Value) {
    let summary = value
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .unwrap_or("Download bundle")
        .to_string();
    let notes = value
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .map(|notes| {
            notes
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|note| !note.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let file_hints = value
        .get("files")
        .and_then(serde_json::Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|file| {
                    let map = file.as_object()?;
                    let path = map.get("path")?.as_str()?.trim();
                    let mime = map
                        .get("mime")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .trim();
                    if path.is_empty() {
                        return None;
                    }
                    Some((path.to_string(), mime.to_string()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let inferred_format =
        infer_download_bundle_export_format(&summary, &notes, &file_hints, None, None);
    let synthesized_csv = synthesize_download_bundle_csv_body(&summary, &notes, &file_hints);
    let (synthesized_export_encoding, synthesized_export_body) =
        synthesize_download_bundle_export_body(
            inferred_format,
            &summary,
            &notes,
            &file_hints,
            None,
        );
    let synthesized_readme = synthesize_download_bundle_readme_body(
        &summary,
        &notes,
        &file_hints,
        if inferred_format == DownloadBundleExportFormat::Csv {
            csv_header_columns(&synthesized_csv)
        } else {
            Vec::new()
        },
    );
    let Some(files) = value
        .get_mut("files")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };

    for file in files {
        let Some(map) = file.as_object_mut() else {
            continue;
        };

        let has_non_empty_body = map
            .get("body")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|body| !body.trim().is_empty());
        if has_non_empty_body {
            continue;
        }

        let aliased_body = ["content", "contents", "text", "data"]
            .into_iter()
            .find_map(|key| {
                map.get(key)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string)
            });

        if let Some(body) = aliased_body {
            map.insert("body".to_string(), serde_json::Value::String(body));
            continue;
        }

        let path = map
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let mime = map
            .get("mime")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let format = infer_download_bundle_export_format_from_path_and_mime(&path, &mime)
            .unwrap_or(inferred_format);
        if path == "readme.md" || mime == "text/markdown" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_readme.clone()),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String("utf8".to_string()),
            );
        } else if path.ends_with(".csv") || mime == "text/csv" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_csv.clone()),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String("utf8".to_string()),
            );
        } else if map
            .get("downloadable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || infer_download_bundle_export_format_from_path_and_mime(&path, &mime).is_some()
        {
            let encoding = match format {
                DownloadBundleExportFormat::Csv => "utf8",
                _ => match synthesized_export_encoding {
                    ChatGeneratedArtifactEncoding::Utf8 => "utf8",
                    ChatGeneratedArtifactEncoding::Base64 => "base64",
                },
            };
            map.insert(
                "body".to_string(),
                serde_json::Value::String(match format {
                    DownloadBundleExportFormat::Csv => synthesized_csv.clone(),
                    _ => synthesized_export_body.clone(),
                }),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String(encoding.to_string()),
            );
        }
    }
}

pub fn validate_generated_artifact_payload(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) -> Result<(), String> {
    if payload.summary.trim().is_empty() {
        return Err("Chat artifact materialization summary must not be empty.".to_string());
    }
    if payload.files.is_empty() {
        return Err("Chat artifact materialization must contain at least one file.".to_string());
    }
    if request.renderer == ChatRendererKind::WorkspaceSurface {
        return Err(
            "workspace_surface artifacts must be materialized through the workspace renderer path."
                .to_string(),
        );
    }

    let mut paths = HashSet::new();
    for file in &payload.files {
        if file.path.trim().is_empty() {
            return Err("Generated artifact file path must not be empty.".to_string());
        }
        if !paths.insert(file.path.clone()) {
            return Err(format!(
                "Generated artifact file path '{}' is duplicated.",
                file.path
            ));
        }
        if file.body.trim().is_empty() {
            return Err(format!(
                "Generated artifact file '{}' must not have an empty body.",
                file.path
            ));
        }
    }

    let primary_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
            )
        })
        .ok_or_else(|| {
            "Generated artifact payload must include a primary or export file.".to_string()
        })?;

    match request.renderer {
        ChatRendererKind::Markdown => {
            validate_exact_primary_file(primary_file, ".md", "text/markdown", true)?;
        }
        ChatRendererKind::HtmlIframe => {
            validate_exact_primary_file(primary_file, ".html", "text/html", true)?;
            let html = primary_file.body.as_str();
            let lower = html.to_ascii_lowercase();
            if !(lower.contains("<html") || lower.contains("<!doctype html")) {
                return Err("HTML iframe artifacts must contain an HTML document.".to_string());
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, html, &lower)
            {
                return Err(failure.to_string());
            }
            if chat_modal_first_html_enabled() {
                if let Some(failure) =
                    modal_first_html_interaction_contract_failure(request, &lower)
                {
                    return Err(failure.to_string());
                }
                return Ok(());
            }
            if !lower.contains("<main") {
                return Err("HTML iframe artifacts must contain a <main> region.".to_string());
            }
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                return Err(
                    "HTML iframe artifacts must contain at least three sectioning elements with first-paint content."
                        .to_string(),
                );
            }
            if lower.contains("alert(") {
                return Err(
                    "HTML iframe artifacts must not use alert() as the surfaced interaction."
                        .to_string(),
                );
            }
            if html_uses_external_runtime_dependency(&lower) {
                return Err(
                    "HTML iframe artifacts must not depend on external libraries or undefined globals."
                        .to_string(),
                );
            }
            if html_contains_placeholder_markers(&lower) {
                return Err(
                    "HTML iframe artifacts must not contain placeholder-grade copy, comments, or TODO markers in the surfaced artifact."
                        .to_string(),
                );
            }
            if html_has_unfocusable_rollover_marks(&lower) {
                return Err(
                    "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable."
                        .to_string(),
                );
            }
            if html_contains_placeholder_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_unlabeled_chart_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_chart_container_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_detail_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include shared detail or comparison regions must populate them on first paint."
                        .to_string(),
                );
            }
            if html_references_missing_dom_ids(&lower) {
                return Err(
                    "HTML iframe artifacts must not target missing DOM ids from their surfaced controls or scripts."
                        .to_string(),
                );
            }
            if html_interactions_are_navigation_only(&lower) {
                return Err(
                    "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log."
                        .to_string(),
                );
            }
            if html_uses_custom_font_family_without_loading(&lower) {
                return Err(
                    "HTML iframe artifacts that declare custom font families must load them with a real stylesheet or @font-face rule."
                        .to_string(),
                );
            }
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && !contains_html_interaction_hooks(&lower)
            {
                return Err(
                    "Interactive HTML iframe artifacts must contain real interactive controls or handlers."
                        .to_string(),
                );
            }
        }
        ChatRendererKind::JsxSandbox => {
            if !(primary_file.path.ends_with(".jsx") || primary_file.path.ends_with(".tsx")) {
                return Err("JSX sandbox artifacts must end with .jsx or .tsx.".to_string());
            }
            if !primary_file.renderable {
                return Err("JSX sandbox artifacts must be renderable.".to_string());
            }
            if !(primary_file.body.contains("export default")
                || primary_file.body.contains("return ("))
            {
                return Err(
                    "JSX sandbox artifacts must contain a default export or renderable component."
                        .to_string(),
                );
            }
        }
        ChatRendererKind::Svg => {
            validate_exact_primary_file(primary_file, ".svg", "image/svg+xml", true)?;
            let svg = primary_file.body.as_str();
            let lower = svg.to_ascii_lowercase();
            if !lower.contains("<svg") {
                return Err("SVG artifacts must contain an <svg element.".to_string());
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, svg, &lower)
            {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::Mermaid => {
            if !primary_file.path.ends_with(".mermaid") && !primary_file.path.ends_with(".mmd") {
                return Err("Mermaid artifacts must end with .mermaid or .mmd.".to_string());
            }
            if !primary_file.renderable {
                return Err("Mermaid artifacts must be renderable.".to_string());
            }
        }
        ChatRendererKind::PdfEmbed => {
            validate_exact_primary_file(primary_file, ".pdf", "application/pdf", true)?;
            if let Some(failure) = pdf_source_contract_failure(&primary_file.body) {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::DownloadCard => {
            if payload.files.iter().any(|file| file.renderable) {
                return Err(
                    "Download-card artifacts must not mark files as renderable.".to_string()
                );
            }
        }
        ChatRendererKind::BundleManifest => {
            if !primary_file.path.ends_with(".json") {
                return Err(
                    "Bundle-manifest artifacts must include a primary .json file.".to_string(),
                );
            }
            if serde_json::from_str::<serde_json::Value>(&primary_file.body).is_err() {
                return Err("Bundle-manifest primary file must contain valid JSON.".to_string());
            }
            if !matches!(
                request.artifact_class,
                ChatArtifactClass::CompoundBundle | ChatArtifactClass::ReportBundle
            ) {
                return Err(
                    "bundle_manifest renderer requires compound_bundle or report_bundle."
                        .to_string(),
                );
            }
        }
        ChatRendererKind::WorkspaceSurface => {}
    }

    Ok(())
}

pub(crate) fn renderer_document_completeness_failure(
    renderer: ChatRendererKind,
    document: &str,
    lower: &str,
) -> Option<&'static str> {
    match renderer {
        ChatRendererKind::HtmlIframe => html_document_completeness_failure(document, lower),
        ChatRendererKind::Svg => svg_document_completeness_failure(document, lower),
        _ => None,
    }
}

fn html_document_completeness_failure<'a>(html: &'a str, lower: &'a str) -> Option<&'static str> {
    if lower.contains("<main") && !lower.contains("</main>") {
        return Some("HTML iframe artifacts must contain a closed <main> region.");
    }
    if markup_has_trailing_unclosed_tag_fragment(html) {
        return Some(
            "HTML iframe artifacts must not end with an unfinished tag or trailing fragment.",
        );
    }
    if markup_has_unclosed_non_void_elements(
        html,
        html_is_void_tag,
        html_has_optional_closing_behavior,
        html_is_raw_text_tag,
    ) {
        return Some(
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
        );
    }
    None
}

fn svg_document_completeness_failure(svg: &str, lower: &str) -> Option<&'static str> {
    if !lower.contains("</svg>") {
        return Some("SVG artifacts must contain a closing </svg> document.");
    }
    if markup_has_trailing_unclosed_tag_fragment(svg) {
        return Some("SVG artifacts must not end with an unfinished tag or trailing fragment.");
    }
    if markup_has_unclosed_non_void_elements(
        svg,
        svg_is_void_tag,
        svg_has_optional_closing_behavior,
        svg_is_raw_text_tag,
    ) {
        return Some(
            "SVG artifacts must not close the document while SVG elements remain unclosed.",
        );
    }
    None
}

fn markup_has_trailing_unclosed_tag_fragment(source: &str) -> bool {
    let trimmed = source.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    let Some(last_gt) = trimmed.rfind('>') else {
        return true;
    };
    !trimmed[last_gt + 1..].trim().is_empty()
}

fn markup_tag_end_index(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => return Some(index),
            None => {}
        }
        index += 1;
    }
    None
}

fn markup_tag_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'_')
}

fn html_is_void_tag(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn html_has_optional_closing_behavior(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "html"
            | "head"
            | "body"
            | "p"
            | "li"
            | "dt"
            | "dd"
            | "option"
            | "optgroup"
            | "thead"
            | "tbody"
            | "tfoot"
            | "tr"
            | "td"
            | "th"
            | "colgroup"
            | "caption"
            | "rb"
            | "rt"
            | "rtc"
            | "rp"
    )
}

fn html_is_raw_text_tag(tag_name: &str) -> bool {
    matches!(tag_name, "script" | "style" | "textarea" | "title")
}

fn svg_is_void_tag(_tag_name: &str) -> bool {
    false
}

fn svg_has_optional_closing_behavior(_tag_name: &str) -> bool {
    false
}

fn svg_is_raw_text_tag(tag_name: &str) -> bool {
    matches!(tag_name, "script" | "style")
}

fn markup_has_unclosed_non_void_elements(
    source: &str,
    is_void_tag: fn(&str) -> bool,
    has_optional_closing_behavior: fn(&str) -> bool,
    is_raw_text_tag: fn(&str) -> bool,
) -> bool {
    let lower = source.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut stack = Vec::<String>::new();
    let mut index = 0usize;

    while index < bytes.len() {
        let Some(relative_lt) = lower[index..].find('<') else {
            break;
        };
        index += relative_lt;

        if lower[index..].starts_with("<!--") {
            let Some(comment_end) = lower[index + 4..].find("-->") else {
                return true;
            };
            index += 4 + comment_end + 3;
            continue;
        }

        if lower[index..].starts_with("<!") || lower[index..].starts_with("<?") {
            let Some(tag_end) = markup_tag_end_index(source, index + 2) else {
                return true;
            };
            index = tag_end + 1;
            continue;
        }

        let mut cursor = index + 1;
        let is_closing = bytes.get(cursor) == Some(&b'/');
        if is_closing {
            cursor += 1;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < bytes.len() && markup_tag_name_char(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            index += 1;
            continue;
        }

        let tag_name = &lower[name_start..cursor];
        let Some(tag_end) = markup_tag_end_index(source, cursor) else {
            return true;
        };
        let tag_fragment = lower[index..=tag_end].trim_end();
        let self_closing = tag_fragment.ends_with("/>") || tag_fragment.ends_with("?>");

        if is_closing {
            if is_void_tag(tag_name) || has_optional_closing_behavior(tag_name) {
                index = tag_end + 1;
                continue;
            }
            match stack.pop() {
                Some(open_tag) if open_tag == tag_name => {}
                Some(_) | None => return true,
            }
            index = tag_end + 1;
            continue;
        }

        if !self_closing && !is_void_tag(tag_name) && !has_optional_closing_behavior(tag_name) {
            stack.push(tag_name.to_string());
            if is_raw_text_tag(tag_name) {
                let close_pattern = format!("</{tag_name}");
                let Some(close_relative) = lower[tag_end + 1..].find(&close_pattern) else {
                    return true;
                };
                index = tag_end + 1 + close_relative;
                continue;
            }
        }

        index = tag_end + 1;
    }

    !stack.is_empty()
}

pub(crate) fn parse_and_validate_generated_artifact_payload(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    let synthesized_from_raw =
        synthesize_generated_artifact_payload_from_raw_document(raw, request);
    let parsed_payload = parse_chat_generated_artifact_payload(raw).ok();
    let mut generated = parsed_payload
        .clone()
        .or_else(|| synthesized_from_raw.clone())
        .ok_or_else(|| {
            "Failed to parse Chat artifact materialization payload: Chat artifact materialization output missing JSON payload".to_string()
        })?;

    match normalize_and_validate_generated_payload(&mut generated, raw, request) {
        Ok(payload) => Ok(payload),
        Err(primary_error) => {
            let Some(mut recovered) = synthesized_from_raw else {
                return Err(primary_error);
            };
            let recovered_matches_primary = primary_generated_artifact_file(&generated)
                .zip(primary_generated_artifact_file(&recovered))
                .is_some_and(|(existing, candidate)| {
                    existing.body.trim() == candidate.body.trim()
                        && existing.path.trim() == candidate.path.trim()
                });
            if recovered_matches_primary {
                return Err(primary_error);
            }
            normalize_and_validate_generated_payload(&mut recovered, raw, request)
                .or(Err(primary_error))
        }
    }
}

fn normalize_and_validate_generated_payload(
    payload: &mut ChatGeneratedArtifactPayload,
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    repair_primary_html_body_from_raw_output(payload, raw, request);
    normalize_generated_artifact_file_paths(payload, request);
    normalize_generated_artifact_payload(payload, request);
    if let Err(error) = validate_generated_artifact_payload(payload, request) {
        if chat_artifact_soft_validation_error(&error) {
            payload.notes.push(format!("soft validation: {error}"));
        } else {
            return Err(error);
        }
    }
    Ok(payload.clone())
}

fn primary_generated_artifact_file(
    payload: &ChatGeneratedArtifactPayload,
) -> Option<&ChatGeneratedArtifactFile> {
    payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    })
}

fn repair_primary_html_body_from_raw_output(
    payload: &mut ChatGeneratedArtifactPayload,
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    let current_body = primary_html.body.trim();
    let current_lower = current_body.to_ascii_lowercase();
    if current_lower.contains("<!doctype html") || current_lower.contains("<html") {
        return;
    }

    let Some(extracted_html) = extract_authored_html_document(raw) else {
        return;
    };
    if extracted_html.is_empty() {
        return;
    }

    primary_html.body = extracted_html;
}

pub(crate) fn synthesize_generated_artifact_payload_from_raw_document(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Option<ChatGeneratedArtifactPayload> {
    let body = extract_authored_document_body(raw, request.renderer)?;
    let mime = direct_authored_document_mime(request.renderer)?;
    Some(ChatGeneratedArtifactPayload {
        summary: direct_authored_document_summary(request.renderer).to_string(),
        notes: vec![format!(
            "normalized from raw {} output",
            direct_authored_document_label(request.renderer)
        )],
        files: vec![ChatGeneratedArtifactFile {
            path: default_generated_artifact_file_path(request.renderer, mime),
            mime: mime.to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body,
        }],
    })
}

pub(crate) fn extract_authored_html_document(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let html_start = lower
        .find("<!doctype html")
        .or_else(|| lower.find("<html"))?;
    let html_slice = trimmed.get(html_start..)?.trim();
    if html_slice.is_empty() {
        return None;
    }

    let html_lower = html_slice.to_ascii_lowercase();
    let html_end = html_lower
        .rfind("</html>")
        .map(|index| index + "</html>".len());
    let extracted = match html_end {
        Some(end) => html_slice.get(..end).unwrap_or(html_slice).trim(),
        None => html_slice,
    };
    if extracted.is_empty() {
        return None;
    }

    Some(extracted.to_string())
}

fn extract_authored_svg_document(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let svg_start = lower.find("<svg")?;
    let svg_slice = trimmed.get(svg_start..)?.trim();
    if svg_slice.is_empty() {
        return None;
    }

    let svg_lower = svg_slice.to_ascii_lowercase();
    let svg_end = svg_lower
        .rfind("</svg>")
        .map(|index| index + "</svg>".len());
    let extracted = match svg_end {
        Some(end) => svg_slice.get(..end).unwrap_or(svg_slice).trim(),
        None => svg_slice,
    };
    if extracted.is_empty() || !extracted.to_ascii_lowercase().contains("<svg") {
        return None;
    }

    Some(extracted.to_string())
}

pub(crate) fn extract_authored_document_body(
    raw: &str,
    renderer: ChatRendererKind,
) -> Option<String> {
    match renderer {
        ChatRendererKind::HtmlIframe => extract_authored_html_document(raw),
        ChatRendererKind::Svg => extract_authored_svg_document(raw),
        ChatRendererKind::Markdown => {
            extract_authored_text_document(raw, &["markdown", "md", ""])
        }
        ChatRendererKind::Mermaid => extract_authored_text_document(raw, &["mermaid", "mmd", ""]),
        ChatRendererKind::PdfEmbed => extract_authored_text_document(raw, &["text", ""]),
        _ => None,
    }
}

fn extract_authored_text_document(raw: &str, accepted_fence_labels: &[&str]) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(fenced) = extract_single_fenced_block(trimmed, accepted_fence_labels) {
        if !fenced.trim().is_empty() {
            return Some(fenced.trim().to_string());
        }
    }

    Some(trimmed.to_string())
}

fn extract_single_fenced_block(raw: &str, accepted_labels: &[&str]) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }

    let after_ticks = trimmed.strip_prefix("```")?;
    let newline_index = after_ticks.find('\n')?;
    let label = after_ticks[..newline_index].trim().to_ascii_lowercase();
    if !accepted_labels
        .iter()
        .any(|candidate| label == candidate.to_ascii_lowercase())
    {
        return None;
    }

    let rest = &after_ticks[newline_index + 1..];
    let end_index = rest.rfind("```")?;
    let trailing = rest[end_index + 3..].trim();
    if !trailing.is_empty() {
        return None;
    }

    Some(rest[..end_index].trim().to_string())
}

fn direct_authored_document_label(renderer: ChatRendererKind) -> &'static str {
    match renderer {
        ChatRendererKind::Markdown => "markdown document",
        ChatRendererKind::HtmlIframe => "html document",
        ChatRendererKind::Svg => "svg document",
        ChatRendererKind::Mermaid => "mermaid diagram",
        ChatRendererKind::PdfEmbed => "pdf source document",
        _ => "document",
    }
}

fn direct_authored_document_summary(renderer: ChatRendererKind) -> &'static str {
    match renderer {
        ChatRendererKind::Markdown => "Markdown artifact",
        ChatRendererKind::HtmlIframe => "Interactive HTML artifact",
        ChatRendererKind::Svg => "SVG artifact",
        ChatRendererKind::Mermaid => "Mermaid artifact",
        ChatRendererKind::PdfEmbed => "PDF artifact",
        _ => "Document artifact",
    }
}

fn modal_first_html_interaction_contract_failure(
    request: &ChatOutcomeArtifactRequest,
    lower: &str,
) -> Option<&'static str> {
    if request.artifact_class != ChatArtifactClass::InteractiveSingleFile {
        return None;
    }

    if !contains_html_interaction_hooks(lower) {
        return Some(
            "Interactive HTML iframe artifacts must contain real interactive controls or handlers.",
        );
    }

    let uses_native_details_toggle = lower.contains("<details") && lower.contains("<summary");
    if !uses_native_details_toggle && !html_contains_stateful_interaction_behavior(lower) {
        return Some(
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
        );
    }

    if html_interactions_are_navigation_only(lower) {
        return Some(
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
        );
    }

    None
}

fn direct_authored_document_mime(renderer: ChatRendererKind) -> Option<&'static str> {
    match renderer {
        ChatRendererKind::Markdown => Some("text/markdown"),
        ChatRendererKind::HtmlIframe => Some("text/html"),
        ChatRendererKind::Svg => Some("image/svg+xml"),
        ChatRendererKind::Mermaid => Some("text/plain"),
        ChatRendererKind::PdfEmbed => Some("application/pdf"),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_generated_artifact_payload_against_brief(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
) -> Result<(), String> {
    validate_generated_artifact_payload_against_brief_with_edit_intent(
        payload, request, brief, None,
    )
}

pub(crate) fn validate_generated_artifact_payload_against_brief_with_edit_intent(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> Result<(), String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return Ok(());
    }
    if chat_modal_first_html_enabled() {
        return Ok(());
    }

    let Some(primary_file) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    }) else {
        return Ok(());
    };
    let lower = primary_file.body.to_ascii_lowercase();
    let response_regions = count_populated_html_response_regions(&lower);
    let chart_regions = count_populated_html_chart_regions(&lower);
    let evidence_regions = count_populated_html_evidence_regions(&lower);
    let actionable_affordances = count_html_actionable_affordances(&lower);
    let required_interaction_goals = brief_required_interaction_goal_count(brief);
    let selection_scoped_patch = edit_intent.is_some_and(|intent| {
        intent.patch_existing_artifact && !intent.selected_targets.is_empty()
    });
    let has_chart_surface = chart_regions > 0
        || count_html_svg_regions(&lower) > 0
        || html_contains_empty_chart_container_regions(&lower);

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && required_interaction_goals > 0
        && brief_requires_response_region(brief)
        && response_regions == 0
    {
        return Err(
            "HTML iframe briefs with interactive query goals must include a populated response or comparison region on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && actionable_affordances < 2
    {
        return Err(
            "HTML iframe briefs that call for state switching must surface at least two actionable controls on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_contains_state_transition_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for state switching must wire controls to produce a visible on-page state change."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && evidence_regions + chart_regions < 2
    {
        return Err(
            "HTML iframe briefs that call for state switching must keep at least two evidence surfaces or authored states available on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && actionable_affordances < 3
    {
        return Err(
            "HTML iframe briefs that call for inspection detail must surface at least three actionable evidence marks or controls on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && !html_contains_rollover_detail_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for inspection detail must wire hover, focus, or equivalent handlers to update visible on-page context."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && has_chart_surface
        && required_interaction_goals >= 2
        && evidence_regions < 2
        && !selection_scoped_patch
    {
        return Err(
            "HTML iframe briefs with charted evidence must surface at least two populated evidence views on first paint."
                .to_string(),
        );
    }

    Ok(())
}

fn chat_artifact_soft_validation_error(error: &str) -> bool {
    [
        "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint.",
        "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint.",
        "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint.",
        "HTML iframe artifacts must contain at least three sectioning elements with first-paint content.",
        "Interactive HTML iframe artifacts must update on-page state or visible response context, not only scroll, jump, or log.",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

pub(crate) fn normalize_generated_artifact_payload(
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) {
    if request.renderer == ChatRendererKind::DownloadCard {
        let mut file_hints = payload
            .files
            .iter()
            .map(|file| (file.path.clone(), file.mime.clone()))
            .collect::<Vec<_>>();
        let inferred_format = infer_download_bundle_export_format(
            &payload.summary,
            &payload.notes,
            &file_hints,
            None,
            None,
        );
        if !payload
            .files
            .iter()
            .any(|file| file.path.eq_ignore_ascii_case("README.md"))
        {
            payload.files.push(ChatGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: ChatArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: String::new(),
            });
        }
        if !payload.files.iter().any(|file| {
            !is_download_bundle_readme_file(&file.path, &file.mime)
                && infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .is_some()
        }) {
            payload.files.push(ChatGeneratedArtifactFile {
                path: default_download_bundle_export_path(inferred_format, &payload.summary),
                mime: default_download_bundle_export_mime(inferred_format).to_string(),
                role: ChatArtifactFileRole::Export,
                renderable: false,
                downloadable: true,
                encoding: Some(download_bundle_export_encoding(inferred_format)),
                body: String::new(),
            });
        }

        for file in &mut payload.files {
            file.renderable = false;
            file.downloadable = true;
        }
        file_hints = payload
            .files
            .iter()
            .map(|file| (file.path.clone(), file.mime.clone()))
            .collect::<Vec<_>>();
        let synthesized_csv =
            synthesize_download_bundle_csv_body(&payload.summary, &payload.notes, &file_hints);
        let (synthesized_export_encoding, synthesized_export_body) =
            synthesize_download_bundle_export_body(
                inferred_format,
                &payload.summary,
                &payload.notes,
                &file_hints,
                None,
            );
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            let format =
                infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .unwrap_or(inferred_format);
            if !download_bundle_export_body_looks_complete(format, &file.body) {
                if path == "readme.md" || file.mime == "text/markdown" {
                    continue;
                }
                match format {
                    DownloadBundleExportFormat::Csv => {
                        file.body = synthesized_csv.clone();
                        file.encoding = Some(ChatGeneratedArtifactEncoding::Utf8);
                    }
                    _ => {
                        file.body = synthesized_export_body.clone();
                        file.encoding = Some(synthesized_export_encoding);
                    }
                }
                file.role = ChatArtifactFileRole::Export;
            }
        }

        let csv_columns = payload
            .files
            .iter()
            .find(|file| {
                file.path.to_ascii_lowercase().ends_with(".csv") || file.mime == "text/csv"
            })
            .map(|file| csv_header_columns(&file.body))
            .unwrap_or_else(|| vec!["record".to_string(), "detail".to_string()]);
        let synthesized_readme = synthesize_download_bundle_readme_body(
            &payload.summary,
            &payload.notes,
            &file_hints,
            if inferred_format == DownloadBundleExportFormat::Csv {
                csv_columns
            } else {
                Vec::new()
            },
        );
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            if (path == "readme.md" || file.mime == "text/markdown")
                && !download_bundle_readme_looks_complete(&file.body)
            {
                file.body = synthesized_readme.clone();
                file.encoding = Some(ChatGeneratedArtifactEncoding::Utf8);
                file.role = ChatArtifactFileRole::Supporting;
            }
        }
        return;
    }

    if request.renderer != ChatRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    if let Some(decoded_body) = decode_json_escaped_html_body(&primary_html.body) {
        primary_html.body = decoded_body;
    }
    if let Some(unwrapped_body) = extract_nested_primary_html_body(&primary_html.body) {
        primary_html.body = unwrapped_body;
    }
    if let Some(extracted_html) = extract_authored_html_document(&primary_html.body) {
        primary_html.body = extracted_html;
    }
    primary_html.body = strip_html_comments(&primary_html.body);
    primary_html.body = normalize_html_terminal_closure(&primary_html.body);
    primary_html.body = normalize_html_custom_font_family_fallbacks(&primary_html.body);
    primary_html.body = normalize_html_semantic_structure(&primary_html.body);
    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
        primary_html.body = normalize_html_interactions(&primary_html.body);
    }
}

fn decode_json_escaped_html_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }

    let decode_candidate = |candidate: &str| -> Option<String> {
        let decoded = serde_json::from_str::<String>(candidate).ok()?;
        let decoded_trimmed = decoded.trim();
        let decoded_lower = decoded_trimmed.to_ascii_lowercase();
        if decoded_trimmed.is_empty()
            || !(decoded_lower.contains("<html") || decoded_lower.contains("<!doctype html"))
            || decoded_trimmed == trimmed
        {
            return None;
        }
        Some(decoded_trimmed.to_string())
    };

    if trimmed.starts_with('"') {
        if let Some(decoded) = decode_candidate(trimmed) {
            return Some(decoded);
        }
    }

    if !trimmed.contains("\\n")
        && !trimmed.contains("\\t")
        && !trimmed.contains("\\r")
        && !trimmed.contains("\\\"")
        && !trimmed.contains("\\/")
    {
        return None;
    }

    decode_candidate(&format!("\"{trimmed}\""))
}

fn extract_nested_primary_html_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() || (!trimmed.starts_with('{') && !trimmed.starts_with("```")) {
        return None;
    }

    let nested_payload = parse_chat_generated_artifact_payload(trimmed).ok()?;
    let nested_primary = nested_payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    })?;
    let nested_body = nested_primary.body.trim();
    if nested_body.is_empty() || nested_body == trimmed {
        return None;
    }

    let nested_lower = nested_body.to_ascii_lowercase();
    if !(nested_lower.contains("<html") || nested_lower.contains("<!doctype html")) {
        return None;
    }

    Some(nested_body.to_string())
}

fn normalize_generated_artifact_file_paths(
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) {
    for file in &mut payload.files {
        file.mime = normalize_generated_artifact_file_mime(&file.mime);
        file.path =
            normalize_generated_artifact_file_path(&file.path, request.renderer, &file.mime);
    }
}

fn normalize_generated_artifact_file_mime(mime: &str) -> String {
    let trimmed = mime.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    let canonical = trimmed
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    match canonical.as_str() {
        "text/html" => "text/html".to_string(),
        "text/markdown" => "text/markdown".to_string(),
        "image/svg+xml" => "image/svg+xml".to_string(),
        "application/pdf" => "application/pdf".to_string(),
        _ => canonical,
    }
}

fn normalize_generated_artifact_file_path(
    path: &str,
    renderer: ChatRendererKind,
    mime: &str,
) -> String {
    let normalized = path.replace('\\', "/");
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .collect::<Vec<_>>();
    let candidate = if segments.is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        segments.join("/")
    };
    if candidate.trim().is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        candidate
    }
}

fn default_generated_artifact_file_path(renderer: ChatRendererKind, mime: &str) -> String {
    match renderer {
        ChatRendererKind::Markdown => "artifact.md".to_string(),
        ChatRendererKind::HtmlIframe => "index.html".to_string(),
        ChatRendererKind::JsxSandbox => "artifact.jsx".to_string(),
        ChatRendererKind::Svg => "artifact.svg".to_string(),
        ChatRendererKind::Mermaid => "diagram.mermaid".to_string(),
        ChatRendererKind::PdfEmbed => "artifact.pdf".to_string(),
        ChatRendererKind::BundleManifest => "bundle-manifest.json".to_string(),
        ChatRendererKind::DownloadCard => {
            if mime.eq_ignore_ascii_case("application/pdf") {
                "download.pdf".to_string()
            } else {
                "download.bin".to_string()
            }
        }
        ChatRendererKind::WorkspaceSurface => "artifact".to_string(),
    }
}

pub(crate) fn enrich_generated_artifact_payload(
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
) {
    match request.renderer {
        ChatRendererKind::Svg => {
            let Some(primary_svg) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
                ) && (file.mime == "image/svg+xml" || file.path.ends_with(".svg"))
            }) else {
                return;
            };

            primary_svg.body = ensure_svg_accessibility_metadata(&primary_svg.body, brief);
        }
        ChatRendererKind::HtmlIframe => {
            if chat_modal_first_html_enabled() {
                return;
            }
            let Some(primary_html) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
                ) && (file.mime == "text/html" || file.path.ends_with(".html"))
            }) else {
                return;
            };

            primary_html.body = ensure_html_button_accessibility_contract(&primary_html.body);
            primary_html.body = ensure_html_mapped_panels_define_referenced_ids(&primary_html.body);
            primary_html.body = ensure_html_view_switch_contract(&primary_html.body);
            primary_html.body = ensure_first_visible_mapped_view_panel(&primary_html.body);
            primary_html.body = ensure_minimum_html_shared_detail_region(&primary_html.body);
            primary_html.body = ensure_minimum_html_mapped_panel_content(&primary_html.body);
            primary_html.body =
                ensure_minimum_brief_rollover_detail_marks(&primary_html.body, brief);
            primary_html.body = ensure_minimum_html_rollover_detail_payloads(&primary_html.body);
            primary_html.body = ensure_grouped_html_rollover_detail_marks(&primary_html.body);
            primary_html.body = ensure_focusable_html_rollover_marks(&primary_html.body);
            primary_html.body = ensure_html_interaction_polish_styles(&primary_html.body);
            primary_html.body = ensure_html_rollover_detail_contract(&primary_html.body);
        }
        _ => {}
    }
}

pub(crate) fn renderer_primary_view_contract_failure(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate: &ChatGeneratedArtifactPayload,
) -> Option<&'static str> {
    let primary_file = candidate.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    })?;

    let lower = primary_file.body.to_ascii_lowercase();
    if let Some(failure) =
        renderer_document_completeness_failure(request.renderer, &primary_file.body, &lower)
    {
        return Some(failure);
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if chat_modal_first_html_enabled() {
                if let Some(failure) =
                    modal_first_html_interaction_contract_failure(request, &lower)
                {
                    return Some(failure);
                }
            }
            let response_regions = count_populated_html_response_regions(&lower);
            let evidence_surfaces = count_populated_html_evidence_regions(&lower)
                + count_populated_html_chart_regions(&lower);
            let actionable_affordances = count_html_actionable_affordances(&lower);
            let required_interaction_goals = brief_required_interaction_goal_count(brief);
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                Some("HTML sectioning regions are empty shells on first paint.")
            } else if html_contains_placeholder_markers(&lower) {
                Some("HTML still contains placeholder-grade copy or comments on first paint.")
            } else if html_interactions_are_navigation_only(&lower) {
                Some("HTML interactions are navigation-only and do not update visible response state.")
            } else if html_contains_empty_chart_container_regions(&lower) {
                Some("HTML chart containers are empty placeholder shells on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_response_region(brief)
                && response_regions == 0
            {
                Some("HTML interactive query goals do not surface a populated response region on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && actionable_affordances < 2
            {
                Some("HTML state switching does not surface enough actionable controls on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_contains_state_transition_behavior(&lower)
            {
                Some(
                    "HTML state switching does not wire controls to produce visible state changes.",
                )
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && evidence_surfaces < 2
            {
                Some("HTML state switching does not keep enough authored evidence surfaces available on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && required_interaction_goals >= 2
                && actionable_affordances < 2
            {
                Some("HTML multi-step interaction briefs must surface at least two actionable controls on first paint.")
            } else if html_contains_unlabeled_chart_svg_regions(&lower) {
                Some("HTML chart SVG regions are unlabeled on first paint.")
            } else if html_contains_placeholder_svg_regions(&lower) {
                Some("HTML chart regions are empty placeholder shells on first paint.")
            } else if html_references_missing_dom_ids(&lower) {
                Some("HTML interactions target missing DOM ids in the surfaced artifact.")
            } else if html_has_unfocusable_rollover_marks(&lower) {
                Some("HTML interactive detail affordances are not keyboard-focusable.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && required_interaction_goals > 0
                && response_regions == 0
            {
                Some("HTML required interactions do not surface a visible response region on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && (count_populated_html_chart_regions(&lower) > 0
                    || count_html_svg_regions(&lower) > 0
                    || html_contains_empty_chart_container_regions(&lower))
                && required_interaction_goals >= 2
                && evidence_surfaces < 2
            {
                Some("HTML only surfaces one evidence view on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_rollover_detail(brief)
                && actionable_affordances < 3
            {
                Some("HTML only surfaces sparse inspection affordances on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_rollover_detail(brief)
                && !html_contains_rollover_detail_behavior(&lower)
            {
                Some("HTML lacks hover, focus, or equivalent inspection behavior for the requested detail interactions.")
            } else {
                None
            }
        }
        ChatRendererKind::Svg => svg_primary_view_contract_failure(&primary_file.body),
        ChatRendererKind::PdfEmbed => pdf_source_contract_failure(&primary_file.body),
        _ => None,
    }
}

pub(crate) fn enforce_renderer_validation_contract(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate: &ChatGeneratedArtifactPayload,
    mut validation: ChatArtifactValidationResult,
) -> ChatArtifactValidationResult {
    neutralize_false_sequence_browsing_penalty(brief, &mut validation);

    let Some(contradiction) = renderer_primary_view_contract_failure(request, brief, candidate)
    else {
        return validation;
    };

    if validation.classification != ChatArtifactValidationStatus::Blocked {
        validation.classification = ChatArtifactValidationStatus::Repairable;
    }
    validation.interaction_relevance = validation.interaction_relevance.min(2);
    validation.layout_coherence = validation.layout_coherence.min(2);
    validation.visual_hierarchy = validation.visual_hierarchy.min(2);
    validation.completeness = validation.completeness.min(2);
    validation.trivial_shell_detected = true;
    validation.deserves_primary_artifact_view = false;
    validation.strongest_contradiction = Some(contradiction.to_string());
    validation.rationale =
        "Renderer contract failures keep the first paint from qualifying as primary output."
            .to_string();
    if !validation
        .issue_classes
        .iter()
        .any(|value| value == "renderer_contract")
    {
        validation
            .issue_classes
            .push("renderer_contract".to_string());
    }
    if !validation
        .blocked_reasons
        .iter()
        .any(|value| value == contradiction)
    {
        validation.blocked_reasons.push(contradiction.to_string());
    }
    if !validation
        .file_findings
        .iter()
        .any(|value| value.contains("renderer contract failure"))
    {
        let file_path = candidate
            .files
            .iter()
            .find(|file| file.renderable)
            .map(|file| file.path.clone())
            .unwrap_or_else(|| "primary-surface".to_string());
        validation
            .file_findings
            .push(format!("{file_path}: renderer contract failure"));
    }
    if !validation
        .repair_hints
        .iter()
        .any(|value| value.contains("pre-rendered"))
    {
        validation.repair_hints.push(
            "Repair the first paint with pre-rendered panels, populated evidence surfaces, and a visible default detail state.".to_string(),
        );
    }
    validation.aesthetic_verdict =
        "Renderer contract failure keeps the surface below the artifact presentation bar."
            .to_string();
    validation.interaction_verdict =
        "Interaction contract does not hold on first paint yet.".to_string();
    if validation.truthfulness_warnings.is_empty() {
        validation.truthfulness_warnings.push(
            "The surfaced artifact is still relying on incomplete or structurally misleading first-paint output."
                .to_string(),
        );
    }
    validation.recommended_next_pass = Some("structural_repair".to_string());
    validation
}

fn neutralize_false_sequence_browsing_penalty(
    brief: &ChatArtifactBrief,
    validation: &mut ChatArtifactValidationResult,
) {
    if brief_requires_sequence_browsing(brief)
        || !validation_false_positive_sequence_penalty(validation)
        || validation.generic_shell_detected
        || validation.trivial_shell_detected
        || !validation.deserves_primary_artifact_view
        || validation.request_faithfulness < 4
        || validation.concept_coverage < 4
        || validation.layout_coherence < 4
        || validation.visual_hierarchy < 4
    {
        return;
    }

    validation.classification = ChatArtifactValidationStatus::Pass;
    validation.interaction_relevance = validation.interaction_relevance.max(4);
    validation.completeness = validation.completeness.max(4);
    validation.strongest_contradiction = None;
    if validation
        .rationale
        .to_ascii_lowercase()
        .contains("sequence browsing")
        || validation
            .rationale
            .to_ascii_lowercase()
            .contains("timeline")
    {
        validation.rationale =
            "Complies with the interaction contract and stays request-faithful.".to_string();
    }
}

fn pdf_source_contract_failure(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    let words = artifact_word_count(body);
    let sections = count_pdf_structural_sections(body);

    if lower.contains("\\documentclass")
        || lower.contains("\\begin{document}")
        || lower.contains("\\section")
        || lower.contains("\\usepackage")
    {
        Some("PDF source content must be plain document text, not LaTeX source.")
    } else if bracket_placeholder_hits(body) > 0 {
        Some("PDF source content must not contain bracketed placeholder copy.")
    } else if words < 90 {
        Some("PDF source content is too short to lead the artifact stage.")
    } else if sections < 4 {
        Some("PDF source content needs clearer sections before it can lead the artifact stage.")
    } else {
        None
    }
}

fn svg_primary_view_contract_failure(body: &str) -> Option<&'static str> {
    if count_svg_primary_marks(body) < 6 {
        Some("SVG output is too sparse to stand as the primary visual artifact.")
    } else {
        None
    }
}

fn count_svg_primary_marks(body: &str) -> usize {
    let lower = body.to_ascii_lowercase();
    [
        "<path",
        "<rect",
        "<circle",
        "<ellipse",
        "<polygon",
        "<polyline",
        "<line",
        "<text",
    ]
    .iter()
    .map(|needle| lower.matches(needle).count())
    .sum()
}

fn artifact_word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}

fn bracket_placeholder_hits(text: &str) -> usize {
    let mut hits = 0usize;
    let mut cursor = 0usize;

    while let Some(relative_start) = text[cursor..].find('[') {
        let start = cursor + relative_start;
        let Some(relative_end) = text[start + 1..].find(']') else {
            break;
        };
        let end = start + 1 + relative_end;
        let next_char = text[end + 1..].chars().next();
        let candidate = text[start + 1..end].trim();

        if next_char != Some('(')
            && candidate.split_whitespace().count() >= 2
            && candidate.chars().any(|ch| ch.is_ascii_alphabetic())
        {
            hits += 1;
        }

        cursor = end + 1;
    }

    hits
}

fn validation_false_positive_sequence_penalty(validation: &ChatArtifactValidationResult) -> bool {
    let contradiction = validation
        .strongest_contradiction
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rationale = validation.rationale.to_ascii_lowercase();
    [contradiction.as_str(), rationale.as_str()]
        .iter()
        .any(|text| {
            text.contains("sequence browsing")
                || text.contains("timeline traversal")
                || text.contains("scrolling through staged evidence")
                || text.contains("progression mechanism")
                || text.contains("timeline")
        })
}

fn validate_exact_primary_file(
    file: &ChatGeneratedArtifactFile,
    extension: &str,
    mime: &str,
    renderable: bool,
) -> Result<(), String> {
    if !file.path.ends_with(extension) {
        return Err(format!(
            "Primary artifact file '{}' must end with '{}'.",
            file.path, extension
        ));
    }
    if file.mime != mime {
        return Err(format!(
            "Primary artifact file '{}' must use mime '{}'.",
            file.path, mime
        ));
    }
    if file.renderable != renderable {
        return Err(format!(
            "Primary artifact file '{}' renderable must be {}.",
            file.path, renderable
        ));
    }
    Ok(())
}

pub(crate) fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                return Some(raw[start..start + idx + 1].to_string());
            }
        }
    }
    None
}
