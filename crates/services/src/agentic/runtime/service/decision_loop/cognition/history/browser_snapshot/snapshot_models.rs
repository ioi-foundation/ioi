#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotLinkState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) context: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) controls_dom_id: Option<String>,
    pub(super) focused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabPanelState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotVisibleTargetState {
    pub(super) semantic_id: String,
    pub(super) name: String,
    pub(super) semantic_role: String,
    pub(super) already_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SnapshotSearchAffordanceKind {
    Field,
    Activator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotSearchAffordanceState {
    pub(super) semantic_id: String,
    pub(super) semantic_role: String,
    pub(super) kind: SnapshotSearchAffordanceKind,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotMessageRecipientControlState {
    pub(super) semantic_id: String,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotAutocompleteControlState {
    pub(super) semantic_id: String,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) controls_dom_id: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotSelectableControlState {
    pub(super) semantic_id: String,
    pub(super) name: String,
    pub(super) selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecentAutocompleteAction {
    Typed,
    Key(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentAutocompleteToolState {
    pub(super) action: RecentAutocompleteAction,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentFindTextState {
    pub(super) query: String,
    pub(super) first_snippet: Option<String>,
}
