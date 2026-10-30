import {
  Shield,
  ShieldCheck,
  FileCode2,
  GitPullRequest,
  CheckCircle2,
  Lock,
  Cpu,
  Layers,
  ExternalLink,
  Activity,
  Terminal,
} from "lucide-react";

export default function Home() {
  const scanners = [
    {
      name: "Trivy",
      type: "Vulnerability & SBOM",
      status: "Active",
      icon: Layers,
      description:
        "Scans container images, filesystems, and dependencies for known CVEs and misconfigurations.",
      badge: "v0.58+ CE",
      accent: "from-blue-500/20 to-cyan-500/10 border-blue-500/30",
      badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    },
    {
      name: "Semgrep CE",
      type: "Static Analysis (SAST)",
      status: "Active",
      icon: FileCode2,
      description:
        "Fast syntactic and semantic scanning for code vulnerabilities, OWASP Top 10 patterns, and exposed secrets.",
      badge: "Community Engine",
      accent: "from-purple-500/20 to-indigo-500/10 border-purple-500/30",
      badgeColor: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    },
    {
      name: "Dependency Review",
      type: "Software Supply Chain",
      status: "Active",
      icon: GitPullRequest,
      description:
        "Audits new and changed package dependencies in pull requests, verifying vulnerability scores and licenses.",
      badge: "GitHub Actions",
      accent: "from-emerald-500/20 to-teal-500/10 border-emerald-500/30",
      badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    },
  ];

  const metrics = [
    { label: "Gate Decision", value: "ENFORCING", icon: ShieldCheck, color: "text-emerald-400" },
    { label: "Critical Vulnerabilities", value: "0 Tolerated", icon: Lock, color: "text-rose-400" },
    { label: "Active Policy Rules", value: "14 Enforced", icon: Activity, color: "text-cyan-400" },
    { label: "Evaluation Latency", value: "< 250ms", icon: Cpu, color: "text-amber-400" },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 text-slate-950 shadow-lg shadow-emerald-500/20">
              <Shield className="w-5 h-5 stroke-[2.5]" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                PipelineShield
              </span>
              <span className="ml-2 text-xs font-mono uppercase px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Gatekeeper v0.1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <a
              href="https://github.com/RishvinReddy/PipelineShield"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center space-x-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-1.5 transition-colors"
            >
              <span>GitHub Repository</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
        {/* Hero Banner */}
        <section className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/80 to-slate-950 p-8 sm:p-10 shadow-2xl">
          <div className="absolute top-0 right-0 -mr-16 -mt-16 w-80 h-80 rounded-full bg-emerald-500/10 blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 left-0 -ml-16 -mb-16 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Security Policy Engine Operational</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Automated DevSecOps Security Gatekeeper
            </h1>
            <p className="text-base sm:text-lg text-slate-400 leading-relaxed">
              PipelineShield continuously scans code changes, normalizes heterogeneous scanner results,
              and evaluates declarative security policies to block vulnerabilities before they merge into production.
            </p>
          </div>
        </section>

        {/* Metrics Grid */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {metrics.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.label}
                className="p-5 rounded-xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center justify-between"
              >
                <div>
                  <p className="text-xs uppercase font-medium tracking-wider text-slate-400">
                    {item.label}
                  </p>
                  <p className={`text-xl font-bold mt-1 ${item.color}`}>
                    {item.value}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/50 text-slate-300">
                  <Icon className="w-5 h-5" />
                </div>
              </div>
            );
          })}
        </section>

        {/* Integrated Scanners Matrix */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">Integrated Security Scanners</h2>
              <p className="text-xs text-slate-400">Multi-engine security inspection coordinated through GitHub Actions</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {scanners.map((scanner) => {
              const Icon = scanner.icon;
              return (
                <div
                  key={scanner.name}
                  className={`rounded-xl border p-6 bg-gradient-to-b ${scanner.accent} transition-transform hover:-translate-y-1 duration-200`}
                >
                  <div className="flex items-start justify-between">
                    <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-700 text-white">
                      <Icon className="w-6 h-6" />
                    </div>
                    <span className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded border ${scanner.badgeColor}`}>
                      {scanner.badge}
                    </span>
                  </div>

                  <h3 className="mt-4 text-lg font-semibold text-white">{scanner.name}</h3>
                  <p className="text-xs font-medium text-slate-400 mt-0.5">{scanner.type}</p>
                  <p className="text-sm text-slate-300/90 mt-3 leading-relaxed">
                    {scanner.description}
                  </p>

                  <div className="mt-5 pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-slate-400">
                    <span className="inline-flex items-center space-x-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{scanner.status} in CI</span>
                    </span>
                    <span className="font-mono text-slate-500">PipelineShield Hook</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Gate Architecture Workflow */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/30 p-6 sm:p-8 space-y-6">
          <div className="flex items-center space-x-3">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white">DevSecOps Enforcement Pipeline</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-mono text-emerald-400">Step 01</span>
              <h4 className="font-semibold text-sm text-white">Developer Pull Request</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Code submission triggers the GitHub Actions workflow automatically.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-mono text-cyan-400">Step 02</span>
              <h4 className="font-semibold text-sm text-white">Multi-Scanner Execution</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Trivy, Semgrep CE, and Dependency Review run in parallel jobs.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-mono text-indigo-400">Step 03</span>
              <h4 className="font-semibold text-sm text-white">Policy Engine Evaluation</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Findings are normalized and evaluated against declarative YAML thresholds.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-mono text-rose-400">Step 04</span>
              <h4 className="font-semibold text-sm text-white">Security Verdict</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                PR is blocked on violations (exit 1) or approved with verified pass summary.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
          <p>© 2026 PipelineShield. Released under the MIT License.</p>
          <div className="flex items-center space-x-6">
            <span>Next.js App Router</span>
            <span>Python Policy Engine</span>
            <span>Zero Paid Infrastructure</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
