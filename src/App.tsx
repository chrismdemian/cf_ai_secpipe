import { useEffect, useState } from "react";
import { Check, Copy, Shield, Zap, Filter, Users } from "lucide-react";

export default function App() {
  const [mcpUrl, setMcpUrl] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setMcpUrl(`${window.location.origin}/mcp`);
  }, []);

  const copyUrl = async () => {
    await navigator.clipboard.writeText(mcpUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const features = [
    { icon: Zap, text: "Data flow-aware reachability analysis" },
    { icon: Filter, text: "Automatic false positive filtering" },
    { icon: Users, text: "Human-in-the-loop approval" },
  ];

  return (
    <>
      {/* Background layers */}
      <div className="radial-bg" />
      <div className="grid-bg" />
      <div className="scanlines" />
      <div className="noise-overlay" />

      <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-6 py-20">
        <div className="w-full max-w-2xl">

          {/* Logo & Title */}
          <div className="text-center animate-fade-in delay-1" style={{ marginBottom: '20px' }}>
            <div className="inline-flex items-center justify-center w-16 h-16 mb-5 rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 icon-pulse">
              <Shield className="w-8 h-8 text-indigo-400" strokeWidth={1.5} />
            </div>
            <h1 className="text-5xl md:text-6xl font-semibold tracking-tight text-white" style={{ marginBottom: '20px' }}>
              SecPipe
            </h1>
            <p className="text-base md:text-lg text-zinc-400 mx-auto text-center">
              AI-powered security analysis with reachability filtering
            </p>
          </div>

          {/* Stats Row */}
          <div className="flex items-center justify-center gap-12 md:gap-20 animate-fade-in delay-2" style={{ marginBottom: '20px' }}>
            <div className="text-center">
              <div className="text-4xl md:text-5xl font-semibold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
                80%
              </div>
              <div className="text-sm text-zinc-500 mt-2 tracking-wide uppercase">
                Noise Reduced
              </div>
            </div>
            <div className="h-14 w-px bg-gradient-to-b from-transparent via-zinc-700 to-transparent" />
            <div className="text-center">
              <div className="text-4xl md:text-5xl font-semibold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
                5-7
              </div>
              <div className="text-sm text-zinc-500 mt-2 tracking-wide uppercase">
                Real Findings
              </div>
            </div>
          </div>

          {/* MCP URL Card */}
          <div className="animate-fade-in delay-3" style={{ marginBottom: '28px' }}>
            <div className="glow-border relative p-6">
              {/* Copy button in top right - positioned inside */}
              <button
                onClick={copyUrl}
                className="absolute top-3 right-3 p-1 rounded-md hover:bg-white/5 transition-colors"
                aria-label={copied ? "Copied" : "Copy URL"}
              >
                {copied ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Copy className="w-4 h-4 text-zinc-500 hover:text-zinc-300 transition-colors" />
                )}
              </button>

              {/* URL centered in box */}
              <div className="flex items-center justify-center min-h-[60px]">
                <code className="text-base md:text-lg text-zinc-200 font-mono">
                  {mcpUrl}
                </code>
              </div>
            </div>
          </div>

          {/* Features */}
          <div className="space-y-4 animate-fade-in delay-4" style={{ marginBottom: '24px' }}>
            {features.map((feature, i) => (
              <div
                key={i}
                className="flex items-center gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/[0.05] hover:bg-white/[0.04] hover:border-white/[0.08] transition-all duration-300"
              >
                <div className="shrink-0 w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/20 flex items-center justify-center">
                  <feature.icon className="w-5 h-5 text-indigo-400" strokeWidth={1.5} />
                </div>
                <span className="text-zinc-300 text-sm md:text-base">{feature.text}</span>
              </div>
            ))}
          </div>

          {/* Compatibility badges */}
          <div className="text-center animate-fade-in delay-5">
            <p className="text-xs text-zinc-600 mb-4 uppercase tracking-wider">Works with</p>
            <div className="flex items-center justify-center gap-3 flex-wrap">
              {["Claude", "Cursor", "Windsurf", "VS Code"].map((tool) => (
                <span
                  key={tool}
                  className="text-xs text-zinc-500 bg-white/[0.03] border border-white/[0.06] px-4 py-2 rounded-full"
                >
                  {tool}
                </span>
              ))}
            </div>
          </div>

          {/* Footer */}
          <div className="mt-20 text-center animate-fade-in delay-6">
            <p className="text-xs text-zinc-600">
              Built on{" "}
              <span className="text-zinc-500">Cloudflare Workers</span>
              {" + "}
              <span className="text-zinc-500">Workers AI</span>
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
