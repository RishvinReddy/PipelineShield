import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      status: "healthy",
      service: "pipelineshield-dashboard",
      type: "frontend_endpoint_liveness",
      description: "Dashboard frontend endpoint check only; does not monitor CI scanners or live pipeline state.",
      version: "0.1.0",
      timestamp: new Date().toISOString(),
    },
    { status: 200 }
  );
}
