// SecPipe - Security Review MCP Server
// Main entry point - API routes only, React SPA handles landing page

import { SecPipeAgent } from "./secpipe-agent";

// Export the Durable Object class and Workflow
export { SecPipeAgent } from "./secpipe-agent";
export { SecurityPipelineWorkflow } from "./pipeline-workflow";

// Environment interface
interface SecPipeWorkerEnv {
  AI: Ai;
  SECPIPE_AGENT: DurableObjectNamespace;
  SECPIPE_WORKFLOW: Workflow;
  OAUTH_KV: KVNamespace;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  AI_GATEWAY_ID?: string;
  ASSETS: Fetcher;
}

// Main worker handler
export default {
  async fetch(
    request: Request,
    env: SecPipeWorkerEnv,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Route /mcp to the SecPipe MCP Agent
    if (url.pathname.startsWith("/mcp")) {
      return SecPipeAgent.serve("/mcp", { binding: "SECPIPE_AGENT" }).fetch(request, env, ctx);
    }

    // OAuth routes
    if (url.pathname === "/authorize" || url.pathname === "/callback") {
      const { handleAuthorize, handleCallback } = await import("./github-handler");
      if (url.pathname === "/authorize") {
        return handleAuthorize(request, env);
      }
      return handleCallback(request, env);
    }

    // All other routes are handled by static assets (React SPA)
    // The Vite plugin automatically serves the built assets
    return env.ASSETS.fetch(request);
  }
} satisfies ExportedHandler<SecPipeWorkerEnv>;
