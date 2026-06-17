export interface ResetHypervisorDataResult {
  dataDir: string;
  removedPaths: string[];
  identityPreserved: boolean;
  remoteHistoryMayPersist: boolean;
}
