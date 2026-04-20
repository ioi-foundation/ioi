fn text_field(
    id: &str,
    label: &str,
    default_value: Option<&str>,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "text".to_string(),
        required,
        placeholder: default_value.map(ToString::to_string),
        description: description.map(ToString::to_string),
        default_value: default_value.map(|value| Value::String(value.to_string())),
        options: None,
    }
}

fn textarea_field(
    id: &str,
    label: &str,
    default_value: Option<&str>,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "textarea".to_string(),
        required,
        placeholder: default_value.map(ToString::to_string),
        description: description.map(ToString::to_string),
        default_value: default_value.map(|value| Value::String(value.to_string())),
        options: None,
    }
}

fn email_field(
    id: &str,
    label: &str,
    required: bool,
    placeholder: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "email".to_string(),
        required,
        placeholder: placeholder.map(ToString::to_string),
        description: None,
        default_value: None,
        options: None,
    }
}

fn number_field(
    id: &str,
    label: &str,
    default_value: u64,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "number".to_string(),
        required,
        placeholder: Some(default_value.to_string()),
        description: description.map(ToString::to_string),
        default_value: Some(Value::Number(default_value.into())),
        options: None,
    }
}

fn select_field(
    id: &str,
    label: &str,
    default_value: &str,
    options: Vec<(&str, &str)>,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "select".to_string(),
        required: false,
        placeholder: None,
        description: description.map(ToString::to_string),
        default_value: Some(Value::String(default_value.to_string())),
        options: Some(
            options
                .into_iter()
                .map(|(label, value)| ConnectorFieldOption {
                    label: label.to_string(),
                    value: value.to_string(),
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
#[path = "fields/tests.rs"]
mod tests;
