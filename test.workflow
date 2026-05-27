{
  "nodes": [
    {
      "id": "1",
      "type": "Foundry Input",
      "title": "Prompt Parser",
      "desc": "Parse user objective",
      "scriptPath": "scripts/lib/prompt-parser.ts",
      "status": "success"
    },
    {
      "id": "2",
      "type": "Tool Execution",
      "title": "Run Autopilot Gate",
      "desc": "Port verify bounds",
      "scriptPath": "scripts/lib/live-runtime-daemon-contract.test.mjs",
      "status": "active",
      "requiresApproval": true,
      "approvalStatus": "pending"
    },
    {
      "id": "3",
      "type": "Model Backend",
      "title": "Mount Model Weights",
      "desc": "Establish GGUF context",
      "scriptPath": "scripts/lib/model-mounting-daemon-contract.test.mjs",
      "status": "idle"
    }
  ]
}