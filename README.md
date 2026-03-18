# IoT Security Monitoring Database

This workspace contains the MongoDB setup and seed scripts used by the IoT Security Monitoring demo.

## Default demo configuration

The database startup and seed scripts are aligned to these defaults:

- Database name: `myapp`
- Database user: `appuser`
- Database password: `dbuser123`
- Local MongoDB port: `5000`

The resulting connection string is:

`mongodb://appuser:dbuser123@localhost:5000/myapp?authSource=admin`

This matches the backend fallback values in `iot_security_backend/.env.example`.

## Startup and seed flow

From the `iot_security_database` directory:

1. Start MongoDB and provision users:
   - `bash startup.sh`
2. The script also:
   - writes `db_connection.txt`
   - generates `db_visualizer/mongodb.env`
   - runs `seed_demo_data.sh`
3. The seed flow is idempotent and safely reapplies:
   - collection validators
   - indexes
   - demo users
   - demo devices
   - demo events

## Seeded demo users

- `admin@iotsecure.demo / Admin123!`
- `analyst@iotsecure.demo / User123!`

## Files of interest

- `startup.sh` – boots MongoDB and aligns connection metadata for the backend.
- `seed_demo_data.sh` – creates validators, indexes, and demo records.
- `db_connection.txt` – canonical `mongosh` connection command for the demo.
- `db_visualizer/mongodb.env` – exported `MONGODB_URL` and `MONGODB_DB` values for tools.
