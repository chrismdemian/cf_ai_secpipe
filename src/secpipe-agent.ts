import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Finding, Remediation, SynthesisResult } from "./types";
import { generateId } from "./stages/utils";

// Environment interface
interface SecPipeEnv {
  AI: Ai;
  SECPIPE_AGENT: DurableObjectNamespace;
  SECPIPE_WORKFLOW: Workflow;
  OAUTH_KV: KVNamespace;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  AI_GATEWAY_ID?: string;
}

// Zod schemas for MCP tool inputs
// Maximum code size (in characters) - ~20K tokens at 4 chars/token, leaving room for prompts
const MAX_CODE_SIZE = 80000;
// Estimated tokens for prompt overhead (system + user prompts in each stage)
const PROMPT_OVERHEAD_TOKENS = 4000;
// Model context window limit
const MODEL_CONTEXT_LIMIT = 24000;

const SubmitReviewSchema = z.object({
  code: z
    .string()
    .min(1)
    .describe("The source code to analyze for security vulnerabilities"),
  language: z
    .string()
    .optional()
    .describe("Programming language (auto-detected if not provided)")
});

const CheckStatusSchema = z.object({
  reviewId: z.string().describe("The review ID to check status for")
});

const GetFindingsSchema = z.object({
  reviewId: z.string().describe("The review ID to get findings for"),
  includeFiltered: z
    .boolean()
    .optional()
    .default(false)
    .describe("Include non-exploitable findings that were filtered out")
});

const ApproveFindingsSchema = z.object({
  reviewId: z.string().describe("The review ID"),
  findingIds: z
    .array(z.string())
    .describe("IDs of findings to approve for remediation")
});

const GetRemediationSchema = z.object({
  reviewId: z.string().describe("The review ID"),
  findingId: z
    .string()
    .optional()
    .describe("Specific finding ID (returns all if not provided)")
});

const CompareReviewsSchema = z.object({
  reviewId1: z.string().describe("First review ID"),
  reviewId2: z.string().describe("Second review ID")
});

// AuthProps with index signature for McpAgent compatibility
interface AuthPropsWithIndex {
  userId: string;
  login: string;
  name?: string;
  email?: string;
  avatarUrl?: string;
  [key: string]: unknown;
}

export class SecPipeAgent extends McpAgent<
  SecPipeEnv,
  Record<string, unknown>,
  AuthPropsWithIndex
> {
  server = new McpServer({
    name: "SecPipe",
    version: "1.0.0"
  });

  async init() {
    // Register MCP tools
    this.registerTools();
  }

  private registerTools() {
    // Tool 1: Submit code for security review
    this.server.tool(
      "submit_review",
      "Submit source code for async security analysis with reachability filtering. Returns a review ID to track progress.",
      SubmitReviewSchema.shape,
      async (args) => {
        const { code, language } = args;
        const userId = this.props?.userId || "anonymous";

        // Issue #1 Fix: Validate code size before submission
        if (code.length > MAX_CODE_SIZE) {
          const estimatedTokens = Math.ceil(code.length / 4);
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "Code too large",
                  message: `Code size (${code.length} chars, ~${estimatedTokens} tokens) exceeds maximum allowed size. The model context window is ${MODEL_CONTEXT_LIMIT} tokens. Please submit smaller code segments or split into multiple reviews.`,
                  maxCharacters: MAX_CODE_SIZE,
                  actualCharacters: code.length
                })
              }
            ]
          };
        }

        // Additional token estimation check
        const estimatedCodeTokens = Math.ceil(code.length / 4);
        if (estimatedCodeTokens + PROMPT_OVERHEAD_TOKENS > MODEL_CONTEXT_LIMIT) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "Code too large for model context",
                  message: `Estimated tokens (~${estimatedCodeTokens}) plus prompt overhead (~${PROMPT_OVERHEAD_TOKENS}) would exceed model context limit (${MODEL_CONTEXT_LIMIT}). Please reduce code size.`,
                  estimatedTokens: estimatedCodeTokens,
                  maxTokens: MODEL_CONTEXT_LIMIT - PROMPT_OVERHEAD_TOKENS
                })
              }
            ]
          };
        }

        const reviewId = generateId("rev");
        const now = Date.now();

        // Store review in KV (shared across all sessions)
        const review: {
          id: string;
          userId: string;
          code: string;
          language: string;
          status: string;
          currentStage: string;
          createdAt: number;
          updatedAt: number;
          totalFindingsRaw: number;
          totalFindingsFiltered: number;
          noiseReductionPercent: number;
          workflowInstanceId?: string;
        } = {
          id: reviewId,
          userId,
          code,
          language: language || "auto",
          status: "triaging",
          currentStage: "triage",
          createdAt: now,
          updatedAt: now,
          totalFindingsRaw: 0,
          totalFindingsFiltered: 0,
          noiseReductionPercent: 0
        };
        await this.env.OAUTH_KV.put(`review:${reviewId}`, JSON.stringify(review));

        // Start the workflow
        const instance = await this.env.SECPIPE_WORKFLOW.create({
          id: reviewId,
          params: {
            reviewId,
            userId,
            code,
            language: language || "auto",
            kvNamespace: "OAUTH_KV" // Tell workflow to use KV
          }
        });

        // Update review with workflow instance ID
        review.workflowInstanceId = instance.id;
        await this.env.OAUTH_KV.put(`review:${reviewId}`, JSON.stringify(review));

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                reviewId,
                status: "triaging",
                message:
                  "Security review started. Pipeline stages: triage → dependency → auth → injection → secrets → REACHABILITY FILTER → synthesis. Use check_status to monitor progress."
              })
            }
          ]
        };
      }
    );

    // Tool 2: Check pipeline status
    this.server.tool(
      "check_status",
      "Check the current status and progress of a security review pipeline.",
      CheckStatusSchema.shape,
      async (args) => {
        const { reviewId } = args;

        // Read from KV (shared across all sessions)
        const reviewData = await this.env.OAUTH_KV.get(`review:${reviewId}`);

        if (!reviewData) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: "Review not found" })
              }
            ]
          };
        }

        const review = JSON.parse(reviewData);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                reviewId: review.id,
                status: review.status,
                currentStage: review.currentStage,
                stats: {
                  rawFindings: review.totalFindingsRaw || 0,
                  exploitableFindings: review.totalFindingsFiltered || 0,
                  noiseReductionPercent: review.noiseReductionPercent || 0
                },
                error: review.error || undefined
              })
            }
          ]
        };
      }
    );

    // Tool 3: Get findings
    this.server.tool(
      "get_findings",
      "Get security findings for a completed review. By default returns only exploitable findings after reachability filtering.",
      GetFindingsSchema.shape,
      async (args) => {
        const { reviewId, includeFiltered } = args;

        // Read findings from KV
        const findingsData = await this.env.OAUTH_KV.get(`findings:${reviewId}`);
        let findings: Finding[] = [];

        if (findingsData) {
          try {
            const allFindings = JSON.parse(findingsData) as Finding[];
            findings = includeFiltered
              ? allFindings
              : allFindings.filter(f => f.isReachable);

            // Sort by severity
            const severityOrder = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
            findings.sort((a, b) =>
              (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
            );
          } catch (e) {
            console.error("Error parsing findings:", e);
          }
        }

        // Get review stats from KV
        const reviewData = await this.env.OAUTH_KV.get(`review:${reviewId}`);
        let stats = null;
        if (reviewData) {
          try {
            const review = JSON.parse(reviewData);
            stats = {
              rawFindings: review.totalFindingsRaw || 0,
              exploitableFindings: review.totalFindingsFiltered || 0,
              noiseReductionPercent: review.noiseReductionPercent || 0
            };
          } catch (e) {
            console.error("Error parsing review:", e);
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                reviewId,
                stats,
                findingsCount: findings.length,
                findings
              })
            }
          ]
        };
      }
    );

    // Tool 4: Approve findings (MCP elicitation for human-in-the-loop)
    this.server.tool(
      "approve_findings",
      "Approve specific findings to generate remediation code. This triggers the remediation stage of the pipeline.",
      ApproveFindingsSchema.shape,
      async (args) => {
        const { reviewId, findingIds } = args;

        // Get review from KV
        const reviewData = await this.env.OAUTH_KV.get(`review:${reviewId}`);
        if (!reviewData) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: "Review not found" })
              }
            ]
          };
        }

        const review = JSON.parse(reviewData);

        // Send approval event to workflow
        try {
          if (review.workflowInstanceId) {
            const instance = await this.env.SECPIPE_WORKFLOW.get(review.workflowInstanceId);
            if (instance && typeof instance.sendEvent === "function") {
              await instance.sendEvent({
                type: "approval",
                payload: { approved: true, findingIds }
              });
            }
          }
        } catch (e) {
          console.error("Failed to send approval event:", e);
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                message: `Approved ${findingIds.length} findings for remediation. Generating fixes...`,
                approvedFindingIds: findingIds
              })
            }
          ]
        };
      }
    );

    // Tool 5: Get remediation
    this.server.tool(
      "get_remediation",
      "Get generated remediation code for approved findings.",
      GetRemediationSchema.shape,
      async (args) => {
        const { reviewId, findingId } = args;

        // Read remediations from KV
        const remediationsData = await this.env.OAUTH_KV.get(`remediations:${reviewId}`);
        let remediations: Remediation[] = [];

        if (remediationsData) {
          try {
            const allRemediations = JSON.parse(remediationsData) as Remediation[];
            remediations = findingId
              ? allRemediations.filter(r => r.findingId === findingId)
              : allRemediations;
          } catch (e) {
            console.error("Error parsing remediations:", e);
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                reviewId,
                remediationsCount: remediations.length,
                remediations
              })
            }
          ]
        };
      }
    );

    // Tool 6: List reviews
    this.server.tool(
      "list_reviews",
      "List all security reviews for the current user.",
      {},
      async () => {
        const userId = this.props?.userId || "anonymous";

        // Note: In demo mode with KV, we don't have user-indexed listing
        // Return a helpful message
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                userId,
                reviewsCount: 0,
                reviews: [],
                note: "In demo mode, use check_status with a specific reviewId to get review details."
              })
            }
          ]
        };
      }
    );

    // Tool 7: Compare reviews
    this.server.tool(
      "compare_reviews",
      "Compare findings between two security reviews to see what changed.",
      CompareReviewsSchema.shape,
      async (args) => {
        const { reviewId1, reviewId2 } = args;

        // Read findings from KV
        const [data1, data2] = await Promise.all([
          this.env.OAUTH_KV.get(`findings:${reviewId1}`),
          this.env.OAUTH_KV.get(`findings:${reviewId2}`)
        ]);

        const findings1: Finding[] = data1 ? JSON.parse(data1).filter((f: Finding) => f.isReachable) : [];
        const findings2: Finding[] = data2 ? JSON.parse(data2).filter((f: Finding) => f.isReachable) : [];

        // Simple diff based on title/location
        const findings1Set = new Set(findings1.map(f => `${f.title}:${f.location.startLine}`));
        const findings2Set = new Set(findings2.map(f => `${f.title}:${f.location.startLine}`));

        const newInReview2 = findings2.filter(f => !findings1Set.has(`${f.title}:${f.location.startLine}`));
        const fixedInReview2 = findings1.filter(f => !findings2Set.has(`${f.title}:${f.location.startLine}`));

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                comparison: {
                  review1: { id: reviewId1, findingsCount: findings1.length },
                  review2: { id: reviewId2, findingsCount: findings2.length },
                  delta: findings2.length - findings1.length
                },
                newVulnerabilities: newInReview2,
                fixedVulnerabilities: fixedInReview2
              })
            }
          ]
        };
      }
    );
  }

  // Internal endpoint handlers (called by workflow)
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/update-status" && request.method === "POST") {
      const { reviewId, status, currentStage } = (await request.json()) as {
        reviewId: string;
        status: string;
        currentStage?: string;
      };

      // Update review in KV
      const reviewData = await this.env.OAUTH_KV.get(`review:${reviewId}`);
      if (reviewData) {
        const review = JSON.parse(reviewData);
        review.status = status;
        review.currentStage = currentStage || null;
        review.updatedAt = Date.now();
        await this.env.OAUTH_KV.put(`review:${reviewId}`, JSON.stringify(review));
      }

      this.broadcastStatus(reviewId, status, currentStage);
      return new Response("OK");
    }

    if (url.pathname === "/store-findings" && request.method === "POST") {
      const { reviewId, findings, synthesis } = (await request.json()) as {
        reviewId: string;
        findings: Finding[];
        synthesis: SynthesisResult;
      };

      // Store findings in KV
      await this.env.OAUTH_KV.put(`findings:${reviewId}`, JSON.stringify(findings));

      // Update review stats in KV
      const reachableCount = findings.filter((f) => f.isReachable).length;
      const reviewData = await this.env.OAUTH_KV.get(`review:${reviewId}`);
      if (reviewData) {
        const review = JSON.parse(reviewData);
        review.totalFindingsRaw = synthesis.totalRaw;
        review.totalFindingsFiltered = reachableCount;
        review.noiseReductionPercent = synthesis.noiseReductionPercent;
        review.updatedAt = Date.now();
        await this.env.OAUTH_KV.put(`review:${reviewId}`, JSON.stringify(review));
      }

      return new Response("OK");
    }

    if (url.pathname === "/store-remediations" && request.method === "POST") {
      const { reviewId, remediations } = (await request.json()) as {
        reviewId: string;
        remediations: Remediation[];
      };

      // Store remediations in KV
      await this.env.OAUTH_KV.put(`remediations:${reviewId}`, JSON.stringify(remediations));

      return new Response("OK");
    }

    // Default: pass to MCP server
    return super.fetch(request);
  }

  private broadcastStatus(
    reviewId: string,
    status: string,
    currentStage?: string
  ) {
    // Broadcast to all connected WebSocket clients
    const message = JSON.stringify({
      type: "status_update",
      reviewId,
      status,
      currentStage,
      timestamp: Date.now()
    });
    // McpAgent extends Agent which has broadcast method
    if (typeof this.broadcast === "function") {
      this.broadcast(message);
    }
  }
}
