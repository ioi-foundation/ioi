import { ConnectionDetailPane } from "./ConnectionDetailPane";
import { EngineDetailPane } from "./EngineDetailPane";
import { ExtensionDetailPane } from "./ExtensionDetailPane";
import { SkillDetailPane } from "./SkillDetailPane";
import type { CapabilitiesDetailPaneProps } from "./detailPaneTypes";

export function CapabilitiesDetailPane(props: CapabilitiesDetailPaneProps) {
  const { controller } = props;

  return (
    <section className="capabilities-detail-pane">
      {controller.surface === "engine" ? (
        <EngineDetailPane
          controller={controller}
          onOpenInbox={props.onOpenInbox}
          onOpenSettings={props.onOpenSettings}
        />
      ) : null}
      {controller.surface === "skills" ? (
        <SkillDetailPane controller={controller} />
      ) : null}
      {controller.surface === "connections" ? (
        <ConnectionDetailPane {...props} />
      ) : null}
      {controller.surface === "extensions" ? (
        <ExtensionDetailPane controller={controller} />
      ) : null}
    </section>
  );
}
