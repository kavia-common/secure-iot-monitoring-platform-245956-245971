#!/bin/bash

set -euo pipefail

# Idempotent MongoDB schema, index, and demo data seeding for the IoT Security Monitoring platform.
DB_NAME="${DB_NAME:-myapp}"
DB_USER="${DB_USER:-appuser}"
DB_PASSWORD="${DB_PASSWORD:-dbuser123}"
DB_PORT="${DB_PORT:-5000}"

AUTH_URI="mongodb://${DB_USER}:${DB_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}?authSource=admin"

run_mongosh() {
    if mongosh "${AUTH_URI}" --quiet --eval "db.adminCommand({ ping: 1 })" > /dev/null 2>&1; then
        mongosh "${AUTH_URI}" --quiet "$@"
        return
    fi

    if mongosh --port "${DB_PORT}" --quiet --eval "db.adminCommand({ ping: 1 })" > /dev/null 2>&1; then
        echo "MongoDB authentication is not enforced yet; using localhost access to apply schema and seeds."
        mongosh --port "${DB_PORT}" --quiet "$@"
        return
    fi

    echo "MongoDB is not reachable on port ${DB_PORT}." >&2
    exit 1
}

echo "Applying MongoDB collection validators, indexes, and seed data..."

DB_NAME="${DB_NAME}" run_mongosh <<'EOF'
const databaseName = (typeof process !== "undefined" && process.env.DB_NAME) ? process.env.DB_NAME : "myapp";
const targetDb = db.getSiblingDB(databaseName);
const now = new Date();

const minutesAgo = (minutes) => new Date(now.getTime() - (minutes * 60 * 1000));
const daysAgo = (days) => new Date(now.getTime() - (days * 24 * 60 * 60 * 1000));

const ensureCollection = (name, schema) => {
  const collectionNames = targetDb.getCollectionNames();
  const collectionExists = collectionNames.indexOf(name) !== -1;

  if (!collectionExists) {
    print("Creating collection " + name);
    targetDb.createCollection(name, {
      validator: { $jsonSchema: schema },
      validationLevel: "moderate",
      validationAction: "error"
    });
    return;
  }

  const result = targetDb.runCommand({
    collMod: name,
    validator: { $jsonSchema: schema },
    validationLevel: "moderate",
    validationAction: "error"
  });

  if (!result.ok) {
    print("Warning: could not update validator for " + name + ": " + tojson(result));
  }
};

const ensureIndex = (collectionName, keyPattern, options) => {
  targetDb.getCollection(collectionName).createIndex(keyPattern, options);
};

ensureCollection("users", {
  bsonType: "object",
  required: ["email", "name", "role", "status", "createdAt", "updatedAt"],
  properties: {
    email: {
      bsonType: "string",
      description: "Unique login email for a platform user."
    },
    username: {
      bsonType: "string",
      description: "Human-friendly identifier used by seeded demo accounts."
    },
    name: {
      bsonType: "string",
      description: "Display name shown in the admin and user dashboards."
    },
    role: {
      bsonType: "string",
      enum: ["admin", "user"],
      description: "Authorization role for API and UI access."
    },
    status: {
      bsonType: "string",
      enum: ["active", "disabled"],
      description: "Whether the user is allowed to sign in."
    },
    password: {
      bsonType: "string",
      description: "Demo-only seed password. Replace with hashed credentials in production."
    },
    lastLoginAt: {
      bsonType: ["date", "null"],
      description: "Latest successful login time."
    },
    isSeedData: {
      bsonType: "bool",
      description: "True when the record was created by the database seed flow."
    },
    createdAt: {
      bsonType: "date",
      description: "Creation timestamp."
    },
    updatedAt: {
      bsonType: "date",
      description: "Most recent update timestamp."
    }
  }
});

ensureCollection("devices", {
  bsonType: "object",
  required: ["deviceId", "name", "type", "location", "status", "createdAt", "updatedAt"],
  properties: {
    deviceId: {
      bsonType: "string",
      description: "Stable device identifier used by APIs and event references."
    },
    name: {
      bsonType: "string",
      description: "Display name used in dashboards and event logs."
    },
    type: {
      bsonType: "string",
      enum: ["motion", "door"],
      description: "Device category."
    },
    location: {
      bsonType: "string",
      description: "Physical location where the device is installed."
    },
    status: {
      bsonType: "string",
      enum: ["online", "offline", "maintenance", "alert"],
      description: "Latest known status used by the live device list."
    },
    batteryLevel: {
      bsonType: ["int", "long", "double"],
      description: "Approximate battery percentage for demo visualization."
    },
    firmwareVersion: {
      bsonType: "string",
      description: "Firmware version shown in device detail views."
    },
    ipAddress: {
      bsonType: ["string", "null"],
      description: "Last reported device IP address."
    },
    lastSeenAt: {
      bsonType: ["date", "null"],
      description: "Most recent telemetry timestamp from the device."
    },
    isSeedData: {
      bsonType: "bool",
      description: "True when the record was created by the database seed flow."
    },
    createdAt: {
      bsonType: "date",
      description: "Creation timestamp."
    },
    updatedAt: {
      bsonType: "date",
      description: "Most recent update timestamp."
    }
  }
});

ensureCollection("events", {
  bsonType: "object",
  required: ["deviceId", "deviceName", "deviceType", "eventType", "severity", "suspicious", "timestamp", "source", "createdAt"],
  properties: {
    seedKey: {
      bsonType: "string",
      description: "Stable unique key used to make demo seed events idempotent."
    },
    deviceId: {
      bsonType: "string",
      description: "Stable reference to the related device."
    },
    deviceName: {
      bsonType: "string",
      description: "Cached device name for event log rendering."
    },
    deviceType: {
      bsonType: "string",
      enum: ["motion", "door"],
      description: "Cached device type for query-friendly filtering."
    },
    location: {
      bsonType: "string",
      description: "Cached device location for event log views."
    },
    eventType: {
      bsonType: "string",
      enum: ["motion_detected", "door_opened", "door_closed", "heartbeat_missed", "tamper_detected"],
      description: "High-level event category used by charts and filters."
    },
    severity: {
      bsonType: "string",
      enum: ["info", "warning", "critical"],
      description: "Severity level used in alerts and summaries."
    },
    suspicious: {
      bsonType: "bool",
      description: "True when the event should be highlighted as suspicious activity."
    },
    source: {
      bsonType: "string",
      description: "Origin of the event, such as seed or runtime telemetry."
    },
    message: {
      bsonType: "string",
      description: "Human-readable description shown in logs and notifications."
    },
    acknowledged: {
      bsonType: "bool",
      description: "Whether the alert has been acknowledged by an operator."
    },
    acknowledgedAt: {
      bsonType: ["date", "null"],
      description: "Timestamp when the event was acknowledged."
    },
    metadata: {
      bsonType: "object",
      description: "Free-form event metadata captured for analytics and troubleshooting."
    },
    timestamp: {
      bsonType: "date",
      description: "Primary event timestamp used for range filters and sort order."
    },
    createdAt: {
      bsonType: "date",
      description: "Creation timestamp."
    },
    updatedAt: {
      bsonType: ["date", "null"],
      description: "Most recent update timestamp."
    },
    isSeedData: {
      bsonType: "bool",
      description: "True when the record was created by the database seed flow."
    }
  }
});

ensureIndex("users", { email: 1 }, { unique: true, name: "uniq_users_email" });
ensureIndex("users", { username: 1 }, { unique: true, sparse: true, name: "uniq_users_username" });
ensureIndex("users", { role: 1, status: 1 }, { name: "idx_users_role_status" });

ensureIndex("devices", { deviceId: 1 }, { unique: true, name: "uniq_devices_device_id" });
ensureIndex("devices", { type: 1, status: 1 }, { name: "idx_devices_type_status" });
ensureIndex("devices", { location: 1, type: 1 }, { name: "idx_devices_location_type" });

ensureIndex("events", { timestamp: -1 }, { name: "idx_events_timestamp_desc" });
ensureIndex("events", { deviceId: 1, timestamp: -1 }, { name: "idx_events_device_timestamp" });
ensureIndex("events", { deviceType: 1, eventType: 1, timestamp: -1 }, { name: "idx_events_device_type_event_type" });
ensureIndex("events", { suspicious: 1, timestamp: -1 }, { name: "idx_events_suspicious_timestamp" });
ensureIndex(
  "events",
  { seedKey: 1 },
  {
    unique: true,
    name: "uniq_events_seed_key",
    partialFilterExpression: { seedKey: { $exists: true } }
  }
);

const userSeeds = [
  {
    email: "admin@iotsecure.demo",
    username: "admin",
    name: "Platform Admin",
    role: "admin",
    status: "active",
    password: "Admin123!",
    lastLoginAt: null,
    isSeedData: true,
    createdAt: daysAgo(45),
    updatedAt: daysAgo(1)
  },
  {
    email: "analyst@iotsecure.demo",
    username: "analyst",
    name: "Security Analyst",
    role: "user",
    status: "active",
    password: "User123!",
    lastLoginAt: null,
    isSeedData: true,
    createdAt: daysAgo(30),
    updatedAt: daysAgo(1)
  }
];

userSeeds.forEach((user) => {
  targetDb.users.updateOne(
    { email: user.email },
    { $setOnInsert: user },
    { upsert: true }
  );
});

const deviceSeeds = [
  {
    deviceId: "door-front-001",
    name: "Front Entrance Door",
    type: "door",
    location: "HQ Lobby",
    status: "online",
    batteryLevel: 92,
    firmwareVersion: "1.4.2",
    ipAddress: "10.10.1.21",
    lastSeenAt: minutesAgo(2),
    isSeedData: true,
    createdAt: daysAgo(20),
    updatedAt: minutesAgo(2)
  },
  {
    deviceId: "motion-ops-001",
    name: "Operations Motion Sensor",
    type: "motion",
    location: "Operations Center",
    status: "online",
    batteryLevel: 81,
    firmwareVersion: "2.1.0",
    ipAddress: "10.10.2.14",
    lastSeenAt: minutesAgo(1),
    isSeedData: true,
    createdAt: daysAgo(18),
    updatedAt: minutesAgo(1)
  },
  {
    deviceId: "door-server-001",
    name: "Server Room Door",
    type: "door",
    location: "Server Room",
    status: "alert",
    batteryLevel: 66,
    firmwareVersion: "1.9.5",
    ipAddress: "10.10.3.8",
    lastSeenAt: minutesAgo(1),
    isSeedData: true,
    createdAt: daysAgo(25),
    updatedAt: minutesAgo(1)
  },
  {
    deviceId: "motion-server-001",
    name: "Server Room Motion Sensor",
    type: "motion",
    location: "Server Room",
    status: "online",
    batteryLevel: 74,
    firmwareVersion: "2.2.1",
    ipAddress: "10.10.3.9",
    lastSeenAt: minutesAgo(1),
    isSeedData: true,
    createdAt: daysAgo(25),
    updatedAt: minutesAgo(1)
  },
  {
    deviceId: "motion-warehouse-001",
    name: "Warehouse Motion Sensor",
    type: "motion",
    location: "Warehouse Aisle 3",
    status: "offline",
    batteryLevel: 15,
    firmwareVersion: "2.0.4",
    ipAddress: null,
    lastSeenAt: minutesAgo(240),
    isSeedData: true,
    createdAt: daysAgo(40),
    updatedAt: minutesAgo(240)
  }
];

deviceSeeds.forEach((device) => {
  targetDb.devices.updateOne(
    { deviceId: device.deviceId },
    { $setOnInsert: device },
    { upsert: true }
  );
});

const deviceById = {};
deviceSeeds.forEach((device) => {
  deviceById[device.deviceId] = device;
});

const buildSeedEvent = (seedKey, deviceId, eventType, severity, suspicious, minutesBack, message, metadata, acknowledged, acknowledgedAt) => {
  const device = deviceById[deviceId];

  return {
    seedKey,
    deviceId,
    deviceName: device.name,
    deviceType: device.type,
    location: device.location,
    eventType,
    severity,
    suspicious,
    source: "seed",
    message,
    metadata,
    acknowledged,
    acknowledgedAt,
    timestamp: minutesAgo(minutesBack),
    createdAt: minutesAgo(minutesBack),
    updatedAt: acknowledgedAt,
    isSeedData: true
  };
};

const eventSeeds = [
  buildSeedEvent(
    "seed-event-front-door-open-001",
    "door-front-001",
    "door_opened",
    "info",
    false,
    180,
    "Front Entrance Door opened during scheduled access hours.",
    { accessWindow: "business-hours", triggerCountLast5Minutes: 1 },
    true,
    minutesAgo(178)
  ),
  buildSeedEvent(
    "seed-event-front-door-close-001",
    "door-front-001",
    "door_closed",
    "info",
    false,
    179,
    "Front Entrance Door closed normally after badge access.",
    { accessWindow: "business-hours", triggerCountLast5Minutes: 2 },
    true,
    minutesAgo(178)
  ),
  buildSeedEvent(
    "seed-event-ops-motion-001",
    "motion-ops-001",
    "motion_detected",
    "warning",
    false,
    95,
    "Operations Motion Sensor detected expected movement near the analyst desks.",
    { confidence: 0.88, triggerCountLast5Minutes: 1 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-warehouse-heartbeat-001",
    "motion-warehouse-001",
    "heartbeat_missed",
    "warning",
    false,
    70,
    "Warehouse Motion Sensor missed its expected heartbeat and appears offline.",
    { heartbeatGapMinutes: 30, batteryLevel: 15 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-server-door-open-001",
    "door-server-001",
    "door_opened",
    "critical",
    true,
    18,
    "Server Room Door opened outside approved maintenance hours.",
    { accessWindow: "after-hours", triggerCountLast5Minutes: 1 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-server-door-close-001",
    "door-server-001",
    "door_closed",
    "warning",
    true,
    17,
    "Server Room Door closed immediately after an after-hours open event.",
    { accessWindow: "after-hours", triggerCountLast5Minutes: 2 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-server-motion-001",
    "motion-server-001",
    "motion_detected",
    "critical",
    true,
    16,
    "Server Room Motion Sensor detected movement during an active security investigation.",
    { correlatedDeviceId: "door-server-001", triggerCountLast5Minutes: 3 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-front-door-tamper-001",
    "door-front-001",
    "tamper_detected",
    "critical",
    true,
    12,
    "Front Entrance Door reported a tamper signal after repeated rapid open-close activity.",
    { triggerCountLast5Minutes: 4, tamperSensor: true },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-ops-motion-002",
    "motion-ops-001",
    "motion_detected",
    "info",
    false,
    8,
    "Operations Motion Sensor returned to normal daytime activity levels.",
    { confidence: 0.91, triggerCountLast5Minutes: 1 },
    false,
    null
  ),
  buildSeedEvent(
    "seed-event-front-door-close-002",
    "door-front-001",
    "door_closed",
    "info",
    false,
    7,
    "Front Entrance Door returned to a secure closed state.",
    { accessWindow: "business-hours", triggerCountLast5Minutes: 1 },
    true,
    minutesAgo(6)
  )
];

eventSeeds.forEach((event) => {
  targetDb.events.updateOne(
    { seedKey: event.seedKey },
    { $setOnInsert: event },
    { upsert: true }
  );
});

print("MongoDB schema and demo seed flow are ready.");
print("Collections: " + tojson(targetDb.getCollectionNames().sort()));
print(
  "Seed summary -> users: " + targetDb.users.countDocuments({}) +
  ", devices: " + targetDb.devices.countDocuments({}) +
  ", events: " + targetDb.events.countDocuments({})
);
print("Demo credentials -> admin@iotsecure.demo / Admin123! | analyst@iotsecure.demo / User123!");
EOF

echo "MongoDB seed flow finished successfully."
