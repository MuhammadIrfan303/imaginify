/* eslint-disable camelcase */
import { clerkClient } from "@clerk/nextjs";
import { WebhookEvent } from "@clerk/nextjs/server";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { Webhook } from "svix";

import { createUser, deleteUser, updateUser } from "@/lib/actions/user.actions";
import { connectToDatabase } from "@/lib/database/mongoose";

// Initialize database connection at startup
let dbConnected = false;
async function ensureDbConnection() {
  if (!dbConnected) {
    await connectToDatabase();
    dbConnected = true;
  }
}

export async function POST(req: Request) {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
  if (!WEBHOOK_SECRET) {
    return new Response("WEBHOOK_SECRET missing", { status: 500 });
  }

  // Get headers and verify quickly
  const headerPayload = headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Missing svix headers", { status: 400 });
  }

  // Process payload
  let evt: WebhookEvent;
  try {
    const payload = await req.json();
    const wh = new Webhook(WEBHOOK_SECRET);
    evt = wh.verify(JSON.stringify(payload), {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("Webhook verification failed:", err);
    return new Response("Invalid webhook", { status: 400 });
  }

  // Process event types
  try {
    const eventType = evt.type;
    const { id } = evt.data; // Fix: access id from evt.data instead of evt

    // CREATE - Most likely to timeout
    if (eventType === "user.created") {
      await ensureDbConnection();

      const { email_addresses, image_url, first_name, last_name, username } = evt.data;
      const email = email_addresses?.[0]?.email_address;

      // Validate immediately
      if (!email) {
        return new Response("Email required", { status: 400 });
      }

      const userData = {
        clerkId: id,  // Use the correctly accessed id
        email,
        username: username || email.split('@')[0],
        firstName: first_name || '',
        lastName: last_name || '',
        photo: image_url || '',
        creditBalance: 10
      };

      // Create user and respond immediately
      const response = new Response("Processing user creation", { status: 202 });

      // Process in background after responding
      setTimeout(async () => {
        try {
          await createUser(userData);
          console.log("User created:", userData.clerkId);
        } catch (error) {
          console.error("Failed to create user:", error);
        }
      }, 0);

      return response;
    }

    // UPDATE - Less likely to timeout
    if (eventType === "user.updated") {
      const { image_url, first_name, last_name, username } = evt.data;
      await updateUser(id, {
        firstName: first_name,
        lastName: last_name,
        username: username!,
        photo: image_url,
      });
      return NextResponse.json({ message: "OK" });
    }

    // DELETE - Simple operation
    if (eventType === "user.deleted") {
      await deleteUser(id!);
      return NextResponse.json({ message: "OK" });
    }

    return new Response("Unhandled event type", { status: 200 });
  } catch (error) {
    console.error("Webhook processing error:", error);
    return new Response("Internal server error", { status: 500 });
  }
}