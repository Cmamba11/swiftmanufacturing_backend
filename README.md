# Backend Service

Standalone Express + Prisma API for Swift Manufacturing Inventory.

## Install

```bash
npm install
```

## Setup

```bash
npm run setup
```

This generates Prisma client and pushes schema to your Postgres database from `DATABASE_URL`.
For local split-repo dev, backend scripts also read `../.env` (repo root) as a fallback.

## Run

```bash
npm run dev
```

API defaults to `http://localhost:4000`.

## Render

- Root Directory: `backend`
- Build Command: `npm install && npm run setup`
- Start Command: `npm run dev`
- Required env vars: `DATABASE_URL`, `AUTH_TOKEN_SECRET`
