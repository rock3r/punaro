// Canopi's Pi 0.84.3 extension. It retains no prompt, transcript, system
// prompt, tool input, tool result, or assistant message: the only child input
// is the normalized lifecycle event below.
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";

type CanopiState = "working" | "waiting_for_user" | "done";

type CanopiEvent = {
  spec_version: 1;
  event_id: string;
  source: "pi";
  machine: { id: string; label: string };
  session_id: string;
  agent_instance_id: string;
  state: CanopiState;
  waiting_reason?: "other";
  activity_at: string;
  emitted_at: string;
  task: { title: string; repository?: string };
  metadata: { hook: string };
};

function configured(): boolean {
  return Boolean(
    process.env.CANOPI_ENDPOINT &&
      process.env.CANOPI_TOKEN_FILE &&
      process.env.CANOPI_MACHINE_ID &&
      process.env.CANOPI_PROVIDER_HOOK,
  );
}

function report(sessionID: string, hook: string, state: CanopiState): void {
  if (!configured()) return;
  const now = new Date().toISOString();
  const machineID = process.env.CANOPI_MACHINE_ID!;
  const title = process.env.CANOPI_TASK_TITLE || "Pi";
  const repository = process.env.CANOPI_REPOSITORY;
  const event: CanopiEvent = {
    spec_version: 1,
    event_id: `pi:${randomUUID()}`,
    source: "pi",
    machine: { id: machineID, label: process.env.CANOPI_MACHINE_LABEL || machineID },
    session_id: sessionID,
    agent_instance_id: sessionID,
    state,
    activity_at: now,
    emitted_at: now,
    task: repository ? { title, repository } : { title },
    metadata: { hook },
  };
  if (state === "waiting_for_user") event.waiting_reason = "other";

  // Pi awaits lifecycle handlers, so never await local queue publication here.
  // The durable Canopi worker performs all network delivery after the child has
  // recorded the normalized event in its protected local spool.
  try {
    const child = spawn(process.env.CANOPI_PROVIDER_HOOK!, ["pi", "emit"], {
      detached: true,
      stdio: ["pipe", "ignore", "ignore"],
      windowsHide: true,
    });
    // A missing executable is reported asynchronously by Node; consume that
    // failure so monitoring can never turn into an unhandled Pi extension
    // error. The local supervisor will be retried on the next lifecycle edge.
    child.on("error", () => {});
    child.stdin?.end(JSON.stringify(event));
    child.unref();
  } catch {
    // Extensions must not interfere with Pi when local monitoring fails.
  }
}

export default function (pi: any): void {
  pi.on("session_start", (_event: unknown, ctx: any) => {
    report(ctx.sessionManager.getSessionId(), "session_start", "working");
  });
  pi.on("agent_start", (_event: unknown, ctx: any) => {
    report(ctx.sessionManager.getSessionId(), "agent_start", "working");
  });
  pi.on("agent_settled", (_event: unknown, ctx: any) => {
    report(ctx.sessionManager.getSessionId(), "agent_settled", "waiting_for_user");
  });
  pi.on("session_shutdown", (_event: unknown, ctx: any) => {
    report(ctx.sessionManager.getSessionId(), "session_shutdown", "done");
  });
}
