function defaultNotFound(message, details = {}) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

export function createRuntimeConversationArtifactSurface({
  notFound = defaultNotFound,
} = {}) {
  function requireArtifact(store, artifactId) {
    const artifact = store.conversationArtifacts.get(artifactId);
    if (!artifact) {
      throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
    }
    return artifact;
  }

  return {
    createConversationArtifact(store, threadId, input = {}) {
      return store.conversationArtifacts.create({
        ...input,
        threadId,
      });
    },
    listConversationArtifacts(store, query = {}) {
      return store.conversationArtifacts.list(query);
    },
    getConversationArtifact(store, artifactId) {
      return requireArtifact(store, artifactId);
    },
    listConversationArtifactRevisions(store, artifactId) {
      requireArtifact(store, artifactId);
      return store.conversationArtifacts.revisions(artifactId);
    },
    performConversationArtifactAction(store, artifactId, input = {}) {
      const result = store.conversationArtifacts.action(artifactId, input);
      if (!result) {
        throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
      }
      return result;
    },
    exportConversationArtifact(store, artifactId, input = {}) {
      const result = store.conversationArtifacts.exportArtifact(artifactId, input);
      if (!result) {
        throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
      }
      return result;
    },
    promoteConversationArtifact(store, artifactId, input = {}) {
      const result = store.conversationArtifacts.promoteArtifact(artifactId, input);
      if (!result) {
        throw notFound(`Conversation artifact not found: ${artifactId}`, { artifactId });
      }
      return result;
    },
  };
}
