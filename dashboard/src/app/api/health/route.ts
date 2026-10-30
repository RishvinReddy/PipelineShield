import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      status: "healthy",
      service: "pipelineshield-dashboard",
      version: "0.1.0",
      timestamp: new Date().toISOString(),
    },
    { status: 200 }
  );
}
