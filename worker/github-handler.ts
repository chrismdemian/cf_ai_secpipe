// GitHub OAuth Handler for SecPipe
// OAuth functions exported for use by the worker

export interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
}

interface OAuthEnv {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  OAUTH_KV: KVNamespace;
}

export async function handleAuthorize(
  request: Request,
  env: OAuthEnv
): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") || crypto.randomUUID();

  // Store state for CSRF protection
  await env.OAUTH_KV.put(`oauth_state:${state}`, "pending", {
    expirationTtl: 600 // 10 minutes
  });

  const githubAuthUrl = new URL("https://github.com/login/oauth/authorize");
  githubAuthUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubAuthUrl.searchParams.set("scope", "read:user user:email");
  githubAuthUrl.searchParams.set("state", state);

  return Response.redirect(githubAuthUrl.toString(), 302);
}

export async function handleCallback(
  request: Request,
  env: OAuthEnv
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return new Response(`OAuth Error: ${error}`, { status: 400 });
  }

  if (!code || !state) {
    return new Response("Missing code or state", { status: 400 });
  }

  // Verify state
  const storedState = await env.OAUTH_KV.get(`oauth_state:${state}`);
  if (!storedState) {
    return new Response("Invalid or expired state", { status: 400 });
  }
  await env.OAUTH_KV.delete(`oauth_state:${state}`);

  // Exchange code for access token
  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code
      })
    }
  );

  const tokenData = (await tokenResponse.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };

  if (tokenData.error || !tokenData.access_token) {
    return new Response(
      `Token Error: ${tokenData.error_description || tokenData.error}`,
      { status: 400 }
    );
  }

  // Get user info from GitHub
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "User-Agent": "SecPipe-OAuth",
      Accept: "application/vnd.github.v3+json"
    }
  });

  const githubUser = (await userResponse.json()) as GitHubUser;

  // For MCP OAuth flow, we redirect back with the user info encoded
  // The actual token completion happens via the OAuthProvider
  const successUrl = new URL("/", url.origin);
  successUrl.searchParams.set("auth", "success");
  successUrl.searchParams.set("user", githubUser.login);

  return Response.redirect(successUrl.toString(), 302);
}
