use super::*;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RequiredAnswerSection {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) required: bool,
}
