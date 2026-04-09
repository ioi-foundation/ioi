type ConnectorActionPatternField = {
  type: string;
};

type ConnectorActionPatternInput = {
  confirmBeforeRun?: boolean;
  fields: ConnectorActionPatternField[];
};

export type ConnectorFocusedFormRecommendation = {
  buttonLabel: string;
  note: string | null;
  recommended: boolean;
};

export function getConnectorFocusedFormRecommendation(
  action: ConnectorActionPatternInput,
): ConnectorFocusedFormRecommendation {
  const recommended = Boolean(
    action.fields.length >= 4 ||
    action.fields.some((field) => field.type === "textarea") ||
    (action.confirmBeforeRun && action.fields.length >= 2),
  );

  return {
    recommended,
    buttonLabel: recommended
      ? "Recommended: open focused form"
      : "Open focused form",
    note: recommended
      ? "This action has a denser form. The focused modal keeps the primary fields and run control fully in view."
      : null,
  };
}
