export interface ResetAutopilotDataResult {
  dataDir: string;
  removedPaths: string[];
  identityPreserved: boolean;
  remoteHistoryMayPersist: boolean;
}
