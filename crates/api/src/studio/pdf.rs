fn sanitize_pdf_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn wrap_pdf_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for word in trimmed.split_whitespace() {
            let next_len = if current.is_empty() {
                word.len()
            } else {
                current.len() + 1 + word.len()
            };

            if next_len > max_chars && !current.is_empty() {
                lines.push(current);
                current = word.to_string();
            } else if current.is_empty() {
                current = word.to_string();
            } else {
                current.push(' ');
                current.push_str(word);
            }
        }

        if !current.is_empty() {
            lines.push(current);
        }
    }

    lines
}

pub fn pdf_artifact_bytes(title: &str, document_text: &str) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(title.trim().to_string());
    lines.push(String::new());
    lines.extend(wrap_pdf_text(document_text, 86));
    if lines.len() < 3 {
        lines.push("Studio artifact".to_string());
    }

    let pages = lines
        .chunks(38)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    let mut pdf = Vec::<u8>::new();
    let mut offsets = Vec::<usize>::new();

    let push_obj = |pdf: &mut Vec<u8>, offsets: &mut Vec<usize>, obj: &str| {
        offsets.push(pdf.len());
        pdf.extend_from_slice(obj.as_bytes());
    };

    pdf.extend_from_slice(b"%PDF-1.4\n");
    push_obj(
        &mut pdf,
        &mut offsets,
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    );

    let kids = (0..pages.len())
        .map(|index| format!("{} 0 R", 3 + (index * 2)))
        .collect::<Vec<_>>()
        .join(" ");
    push_obj(
        &mut pdf,
        &mut offsets,
        &format!(
            "2 0 obj\n<< /Type /Pages /Count {} /Kids [{}] >>\nendobj\n",
            pages.len(),
            kids
        ),
    );

    for (index, page_lines) in pages.iter().enumerate() {
        let page_id = 3 + (index * 2);
        let content_id = page_id + 1;
        push_obj(
            &mut pdf,
            &mut offsets,
            &format!(
                "{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>\nendobj\n",
                3 + (pages.len() * 2)
            ),
        );

        let mut stream = String::from("BT\n72 752 Td\n/F1 18 Tf\n");
        for (line_index, line) in page_lines.iter().enumerate() {
            if index == 0 && line_index == 0 {
                stream.push_str(&format!("({}) Tj\n", sanitize_pdf_text(line)));
                stream.push_str("/F1 12 Tf\n0 -24 Td\n");
                continue;
            }

            if line.is_empty() {
                // Emit an empty text segment so extraction can preserve section breaks.
                stream.push_str("() Tj\n0 -18 Td\n");
            } else {
                stream.push_str(&format!("({}) Tj\n0 -18 Td\n", sanitize_pdf_text(line)));
            }
        }
        stream.push_str("ET\n");
        let stream_bytes = stream.as_bytes();

        push_obj(
            &mut pdf,
            &mut offsets,
            &format!(
                "{content_id} 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
                stream_bytes.len(),
                stream
            ),
        );
    }

    let font_id = 3 + (pages.len() * 2);
    push_obj(
        &mut pdf,
        &mut offsets,
        &format!(
            "{font_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        ),
    );

    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", offsets.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            6, xref_offset
        )
        .as_bytes(),
    );
    pdf
}

pub fn extract_searchable_pdf_text(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut segments = Vec::new();
    let mut chars = raw.chars().peekable();
    let mut saw_visible_text = false;

    while let Some(ch) = chars.next() {
        if ch != '(' {
            continue;
        }

        let mut segment = String::new();
        let mut escaped = false;

        for next in chars.by_ref() {
            if escaped {
                segment.push(match next {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                escaped = false;
                continue;
            }

            match next {
                '\\' => escaped = true,
                ')' => break,
                other => segment.push(other),
            }
        }

        if segment.trim().is_empty() {
            segments.push(String::new());
        } else {
            saw_visible_text = true;
            segments.push(segment);
        }
    }

    if !saw_visible_text {
        raw.to_string()
    } else {
        segments.join("\n")
    }
}

pub fn count_pdf_structural_sections(text: &str) -> usize {
    let paragraph_sections = text
        .split("\n\n")
        .filter(|chunk| !chunk.trim().is_empty())
        .count();
    let heading_sections = text
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with('-')
                && !trimmed.starts_with('*')
                && trimmed
                    .chars()
                    .next()
                    .map(|ch| !ch.is_ascii_digit())
                    .unwrap_or(false)
                && !trimmed.ends_with('.')
                && !trimmed.contains(": ")
                && trimmed.split_whitespace().count() <= 6
        })
        .count();
    paragraph_sections.max(heading_sections)
}
