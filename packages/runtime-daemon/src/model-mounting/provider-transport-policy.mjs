export function providerHealthFailureStatus(error) {
  if (error?.status === 403 || error?.code === "policy") return "blocked";
  if (error?.status === 404) return "absent";
  return "degraded";
}
