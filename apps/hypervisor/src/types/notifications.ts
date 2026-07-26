import type {
  ContextualNotificationRecord as GeneratedContextualNotificationRecord,
  InterventionRecord as GeneratedInterventionRecord,
  NotificationAction as GeneratedNotificationAction,
  NotificationDeliveryState as GeneratedNotificationDeliveryState,
  NotificationPolicyRefs as GeneratedNotificationPolicyRefs,
  NotificationPrivacy as GeneratedNotificationPrivacy,
  NotificationSource as GeneratedNotificationSource,
} from "../generated/hypervisor-contracts";
import type { NotificationActionStyle } from "./generated";

export type NotificationAction = Omit<GeneratedNotificationAction, "style"> & {
  style?: NotificationActionStyle | null;
};

export type NotificationDeliveryState = Omit<
  GeneratedNotificationDeliveryState,
  "lastToastAtMs"
> & {
  lastToastAtMs?: number | null;
};

export type NotificationPrivacy = GeneratedNotificationPrivacy;
export type NotificationSource = GeneratedNotificationSource;

export type NotificationPolicyRefs = Omit<
  GeneratedNotificationPolicyRefs,
  "policyHash" | "requestHash"
> & {
  policyHash?: string | null;
  requestHash?: string | null;
};

export type NotificationTarget =
  | {
      kind: "gmail_thread";
      connectorId?: string;
      connector_id?: string;
      threadId?: string;
      thread_id?: string;
      messageId?: string | null;
      message_id?: string | null;
    }
  | {
      kind: "calendar_event";
      connectorId?: string;
      connector_id?: string;
      calendarId?: string;
      calendar_id?: string;
      eventId?: string;
      event_id?: string;
    }
  | {
      kind: "connector_auth";
      connectorId?: string;
      connector_id?: string;
    }
  | {
      kind: "connector_subscription";
      connectorId?: string;
      connector_id?: string;
      subscriptionId?: string;
      subscription_id?: string;
    };

export type InterventionRecord = Omit<GeneratedInterventionRecord, "target"> & {
  target?: NotificationTarget | null;
};

export type ContextualNotificationRecord = Omit<
  GeneratedContextualNotificationRecord,
  "target"
> & {
  target?: NotificationTarget | null;
};

/**
 * @deprecated Compatibility alias for `ContextualNotificationRecord`.
 *
 * `Assistant` is a Session-backed faculty, not a durable object; what this names
 * is a durable Notification, and the eight-state lifecycle belongs to the
 * notification. See `docs/architecture/foundations/term-boundaries.md`. This is
 * an alias, not a second concept.
 */
export type AssistantNotificationRecord = ContextualNotificationRecord;
