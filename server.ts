import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'node:path';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { PrismaClient } from '@prisma/client';

// Support local split-app dev (root .env) and backend-only deploys (backend/.env).
dotenv.config({ path: path.resolve(process.cwd(), '../.env') });
dotenv.config();

const prisma = new PrismaClient();
const app = express();
const PORT = Number(process.env.API_PORT ?? 4000);
const TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET ?? 'change-me-in-production';
const TOKEN_TTL_SECONDS = Number(process.env.AUTH_TOKEN_TTL_SECONDS ?? 60 * 60 * 12);
const USER_ROLES = new Set([
  'Administrator',
  'Production Supervisor',
  'Warehouse Officer',
  'Logistics Officer',
  'Management',
]);
const PERMISSIONS = [
  'view_all',
  'edit_products',
  'delete_products',
  'edit_customers',
  'delete_customers',
  'void_transactions',
  'manage_users',
  'customer_asset_adjustment',
  'record_issuance',
  'warehouse_control',
  'manage_materials',
  'production_intake',
  'dispatch_goods',
] as const;
type Permission = (typeof PERMISSIONS)[number];
const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  Administrator: [
    'view_all',
    'edit_products',
    'delete_products',
    'edit_customers',
    'delete_customers',
    'void_transactions',
    'manage_users',
    'customer_asset_adjustment',
    'record_issuance',
    'warehouse_control',
    'manage_materials',
    'production_intake',
    'dispatch_goods',
  ],
  Management: ['view_all', 'warehouse_control'],
  'Production Supervisor': ['view_all', 'production_intake', 'warehouse_control'],
  'Warehouse Officer': ['view_all', 'production_intake', 'dispatch_goods', 'warehouse_control', 'manage_materials'],
  'Logistics Officer': ['view_all', 'dispatch_goods', 'record_issuance'],
};
const TRANSACTION_TYPES = new Set([
  'Production In',
  'Dispatch (Supply)',
  'Return In',
  'Issuance',
  'Adjustment',
]);

// BigInt values are used for timestamps in SQLite/Prisma.
(BigInt.prototype as { toJSON?: () => number }).toJSON = function toJSON() {
  return Number(this);
};

app.use(cors());
app.use(express.json());

const MATERIAL_STOCK_FIELDS = ['hd', 'lld', 'exceed', 'ipa', 'tulane'] as const;
type MaterialStockField = (typeof MATERIAL_STOCK_FIELDS)[number];

type JsonObject = Record<string, unknown>;
type AuthTokenPayload = {
  sub: string;
  username: string;
  name: string;
  role: string;
  exp: number;
};
type AuthenticatedRequest = Request & { authUser?: AuthTokenPayload };

type SafeUser = {
  id: string;
  username: string;
  name: string;
  role: string;
  active: boolean;
};

type ManagedSafeUser = SafeUser & {
  createdAt: Date;
  updatedAt: Date;
};

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireObjectBody(body: unknown): JsonObject {
  if (!isObject(body)) {
    throw badRequest('Request body must be a JSON object.');
  }
  return body;
}

function badRequest(message: string, details?: unknown) {
  const error = new Error(message) as Error & { status?: number; details?: unknown };
  error.status = 400;
  error.details = details;
  return error;
}

function unauthorized(message = 'Unauthorized') {
  const error = new Error(message) as Error & { status?: number };
  error.status = 401;
  return error;
}

function forbidden(message = 'Forbidden') {
  const error = new Error(message) as Error & { status?: number };
  error.status = 403;
  return error;
}

function toBase64Url(input: string | Buffer) {
  return Buffer.from(input).toString('base64url');
}

function signToken(payload: Omit<AuthTokenPayload, 'exp'>) {
  const fullPayload: AuthTokenPayload = {
    ...payload,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
  };
  const encodedPayload = toBase64Url(JSON.stringify(fullPayload));
  const signature = createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
}

function verifyToken(token: string): AuthTokenPayload {
  const [encodedPayload, signature] = token.split('.');
  if (!encodedPayload || !signature) {
    throw unauthorized('Invalid token format.');
  }

  const expectedSignature = createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest();
  const incomingSignature = Buffer.from(signature, 'base64url');
  if (
    expectedSignature.length !== incomingSignature.length ||
    !timingSafeEqual(expectedSignature, incomingSignature)
  ) {
    throw unauthorized('Invalid token signature.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    throw unauthorized('Invalid token payload.');
  }

  if (!isObject(parsed)) {
    throw unauthorized('Invalid token payload.');
  }

  const { sub, username, name, role, exp } = parsed;
  if (
    typeof sub !== 'string' ||
    typeof username !== 'string' ||
    typeof name !== 'string' ||
    typeof role !== 'string' ||
    typeof exp !== 'number'
  ) {
    throw unauthorized('Invalid token claims.');
  }
  if (!USER_ROLES.has(role)) {
    throw unauthorized('Invalid user role in token.');
  }

  if (exp < Math.floor(Date.now() / 1000)) {
    throw unauthorized('Token expired.');
  }

  return { sub, username, name, role, exp };
}

function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, storedHash: string) {
  const [salt, hash] = storedHash.split(':');
  if (!salt || !hash) return false;

  const computed = scryptSync(password, salt, 64).toString('hex');
  if (hash.length !== computed.length) return false;
  return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computed, 'hex'));
}

function sanitizeUser(user: SafeUser): SafeUser {
  return {
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    active: user.active,
  };
}

function sanitizeManagedUser(user: ManagedSafeUser) {
  return {
    ...sanitizeUser(user),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function requireAuthUser(req: AuthenticatedRequest): AuthTokenPayload {
  if (!req.authUser) throw unauthorized();
  return req.authUser;
}

function userHasPermission(role: string, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}

function assertPermission(req: AuthenticatedRequest, permission: Permission): AuthTokenPayload {
  const authUser = requireAuthUser(req);
  if (!userHasPermission(authUser.role, permission)) {
    throw forbidden(`Missing permission: ${permission}`);
  }
  return authUser;
}

function assertAnyPermission(req: AuthenticatedRequest, permissions: readonly Permission[]): AuthTokenPayload {
  const authUser = requireAuthUser(req);
  if (!permissions.some((permission) => userHasPermission(authUser.role, permission))) {
    throw forbidden(`Missing required permissions: ${permissions.join(', ')}`);
  }
  return authUser;
}

function assertAdmin(req: AuthenticatedRequest): AuthTokenPayload {
  const authUser = requireAuthUser(req);
  if (authUser.role !== 'Administrator') {
    throw forbidden('Only administrators can manage users.');
  }
  return authUser;
}

function parseTimestamp(value: unknown, field = 'timestamp'): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  if (typeof value === 'string' && value.trim() !== '' && /^-?\d+$/.test(value)) return BigInt(value);
  throw badRequest(`${field} must be a valid numeric timestamp.`);
}

function parsePositiveNumber(value: unknown, field: string): number {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) return value;
  throw badRequest(`${field} must be a number greater than 0.`);
}

function parseNumber(value: unknown, field: string): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  throw badRequest(`${field} must be a valid number.`);
}

function parseOptionalNumber(value: unknown, field: string): number | undefined {
  if (value == null) return undefined;
  return parseNumber(value, field);
}

function parseString(value: unknown, field: string, options?: { allowEmpty?: boolean }): string {
  if (typeof value !== 'string') {
    throw badRequest(`${field} must be a string.`);
  }
  const normalized = value.trim();
  if (!normalized && !options?.allowEmpty) {
    throw badRequest(`${field} is required.`);
  }
  return normalized;
}

function parseOptionalString(value: unknown, field: string): string | undefined {
  if (value == null) return undefined;
  const normalized = parseString(value, field, { allowEmpty: true });
  return normalized || undefined;
}

function parseOptionalNullableString(value: unknown, field: string): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  const normalized = parseString(value, field, { allowEmpty: true });
  return normalized || null;
}

function parseBoolean(value: unknown, field: string): boolean {
  if (typeof value === 'boolean') return value;
  throw badRequest(`${field} must be true or false.`);
}

function parseParamId(req: Request): string {
  const id = req.params.id;
  if (typeof id !== 'string' || !id.trim()) {
    throw badRequest('Invalid id path parameter.');
  }
  return id;
}

function parseRole(value: unknown, field: string): string {
  const role = parseString(value, field);
  if (!USER_ROLES.has(role)) {
    throw badRequest(`${field} must be a valid user role.`);
  }
  return role;
}

function parseUsername(value: unknown): string {
  return parseString(value, 'username').toLowerCase();
}

function parsePassword(value: unknown, field: string): string {
  const password = parseString(value, field);
  if (password.length < 6) {
    throw badRequest(`${field} must be at least 6 characters.`);
  }
  return password;
}

function parseTransactionType(value: unknown): string {
  const type = parseString(value, 'type');
  if (!TRANSACTION_TYPES.has(type)) {
    throw badRequest(`type must be one of: ${Array.from(TRANSACTION_TYPES).join(', ')}`);
  }
  return type;
}

function transactionPermissions(type: string): Permission[] {
  switch (type) {
    case 'Production In':
      return ['production_intake'];
    case 'Dispatch (Supply)':
      return ['dispatch_goods'];
    case 'Return In':
      return ['customer_asset_adjustment'];
    case 'Issuance':
      return ['record_issuance'];
    case 'Adjustment':
      return ['customer_asset_adjustment'];
    default:
      return ['view_all'];
  }
}

function parseCustomerCreateData(body: JsonObject) {
  return {
    id: parseString(body.id, 'id'),
    name: parseString(body.name, 'name'),
    contact: parseString(body.contact, 'contact', { allowEmpty: true }),
    address: parseString(body.address, 'address', { allowEmpty: true }),
  };
}

function parseCustomerUpdateData(body: JsonObject) {
  const data: Record<string, unknown> = {};
  if ('name' in body) data.name = parseString(body.name, 'name');
  if ('contact' in body) data.contact = parseString(body.contact, 'contact', { allowEmpty: true });
  if ('address' in body) data.address = parseString(body.address, 'address', { allowEmpty: true });

  if (Object.keys(data).length === 0) {
    throw badRequest('No valid customer fields to update.');
  }

  return data;
}

function parseProductCreateData(body: JsonObject) {
  const type = parseString(body.type, 'type');
  const unit = parseString(body.unit, 'unit');
  if (!['Roller', 'Packing Bag'].includes(type)) {
    throw badRequest('type must be either "Roller" or "Packing Bag".');
  }
  if (!['Pcs', 'KG'].includes(unit)) {
    throw badRequest('unit must be either "Pcs" or "KG".');
  }

  return {
    id: parseString(body.id, 'id'),
    name: parseString(body.name, 'name'),
    type,
    specification: parseString(body.specification, 'specification'),
    size: parseString(body.size, 'size'),
    unit,
    storageLocation: parseString(body.storageLocation, 'storageLocation'),
    minStockLevel: parseNumber(body.minStockLevel, 'minStockLevel'),
    minQuantityLevel: parseOptionalNumber(body.minQuantityLevel, 'minQuantityLevel'),
  };
}

function parseProductUpdateData(body: JsonObject) {
  const data: Record<string, unknown> = {};

  if ('name' in body) data.name = parseString(body.name, 'name');
  if ('type' in body) {
    const type = parseString(body.type, 'type');
    if (!['Roller', 'Packing Bag'].includes(type)) throw badRequest('Invalid product type.');
    data.type = type;
  }
  if ('specification' in body) data.specification = parseString(body.specification, 'specification');
  if ('size' in body) data.size = parseString(body.size, 'size');
  if ('unit' in body) {
    const unit = parseString(body.unit, 'unit');
    if (!['Pcs', 'KG'].includes(unit)) throw badRequest('Invalid product unit.');
    data.unit = unit;
  }
  if ('storageLocation' in body) data.storageLocation = parseString(body.storageLocation, 'storageLocation');
  if ('minStockLevel' in body) data.minStockLevel = parseNumber(body.minStockLevel, 'minStockLevel');
  if ('minQuantityLevel' in body) data.minQuantityLevel = parseOptionalNumber(body.minQuantityLevel, 'minQuantityLevel');

  if (Object.keys(data).length === 0) {
    throw badRequest('No valid product fields to update.');
  }

  return data;
}

function parseTransactionCreateData(body: JsonObject) {
  return {
    id: parseString(body.id, 'id'),
    productId: parseString(body.productId, 'productId'),
    type: parseTransactionType(body.type),
    quantity: parseNumber(body.quantity, 'quantity'),
    weight: parseOptionalNumber(body.weight, 'weight'),
    customerId: parseOptionalNullableString(body.customerId, 'customerId'),
    referenceNumber: parseString(body.referenceNumber, 'referenceNumber'),
    timestamp: parseTimestamp(body.timestamp),
    recordedBy: parseString(body.recordedBy, 'recordedBy'),
    shift: parseOptionalString(body.shift, 'shift'),
    rollsUsed: parseOptionalNumber(body.rollsUsed, 'rollsUsed'),
    kgUsed: parseOptionalNumber(body.kgUsed, 'kgUsed'),
    notes: parseOptionalNullableString(body.notes, 'notes'),
    voided: 'voided' in body ? parseBoolean(body.voided, 'voided') : false,
    vehicleId: parseOptionalNullableString(body.vehicleId, 'vehicleId'),
  };
}

function parseTransactionUpdateData(body: JsonObject) {
  const data: Record<string, unknown> = {};

  if ('voided' in body) data.voided = parseBoolean(body.voided, 'voided');
  if ('notes' in body) data.notes = parseOptionalNullableString(body.notes, 'notes');
  if ('vehicleId' in body) data.vehicleId = parseOptionalNullableString(body.vehicleId, 'vehicleId');

  if (Object.keys(data).length === 0) {
    throw badRequest('No valid transaction fields to update.');
  }

  return data;
}

function parseIssuingRecordCreateData(
  body: JsonObject,
  materialBags: Record<string, number> | null,
) {
  return {
    id: parseString(body.id, 'id'),
    date: parseString(body.date, 'date'),
    shift: parseString(body.shift, 'shift'),
    machineType: parseString(body.machineType, 'machineType'),
    materialBags: materialBags ? JSON.stringify(materialBags) : null,
    rollsIssued: parseOptionalNumber(body.rollsIssued, 'rollsIssued'),
    weightIssued: parseOptionalNumber(body.weightIssued, 'weightIssued'),
    totalInputKg: parseNumber(body.totalInputKg, 'totalInputKg'),
    totalIssuedKg: parseNumber(body.totalIssuedKg, 'totalIssuedKg'),
    timestamp: parseTimestamp(body.timestamp),
  };
}

function parseProductionRecordCreateData(body: JsonObject) {
  return {
    id: parseString(body.id, 'id'),
    date: parseString(body.date, 'date'),
    shift: parseString(body.shift, 'shift'),
    machineType: parseString(body.machineType, 'machineType'),
    actualOutputKg: parseNumber(body.actualOutputKg, 'actualOutputKg'),
    actualCount: parseOptionalNumber(body.actualCount, 'actualCount'),
    rollsUsed: parseOptionalNumber(body.rollsUsed, 'rollsUsed'),
    kgUsed: parseOptionalNumber(body.kgUsed, 'kgUsed'),
    timestamp: parseTimestamp(body.timestamp),
  };
}

function parseSparePartCreateData(body: JsonObject) {
  return {
    id: parseString(body.id, 'id'),
    name: parseString(body.name, 'name'),
    quantity: parseNumber(body.quantity, 'quantity'),
    value: parseNumber(body.value, 'value'),
    machineType: parseString(body.machineType, 'machineType'),
  };
}

function parseSparePartUpdateData(body: JsonObject) {
  const data: Record<string, unknown> = {};
  if ('name' in body) data.name = parseString(body.name, 'name');
  if ('quantity' in body) data.quantity = parseNumber(body.quantity, 'quantity');
  if ('value' in body) data.value = parseNumber(body.value, 'value');
  if ('machineType' in body) data.machineType = parseString(body.machineType, 'machineType');

  if (Object.keys(data).length === 0) {
    throw badRequest('No valid spare part fields to update.');
  }

  return data;
}

function parseMaterialBags(value: unknown): Record<string, number> | null {
  if (value == null) return null;
  if (!isObject(value)) {
    throw badRequest('materialBags must be an object when provided.');
  }

  const parsed: Record<string, number> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw !== 'number' || !Number.isFinite(raw) || raw < 0) {
      throw badRequest(`materialBags.${key} must be a number >= 0.`);
    }
    parsed[key] = raw;
  }
  return parsed;
}

function materialBagDeltas(materialBags: Record<string, number> | null): Partial<Record<MaterialStockField, { increment: number }>> {
  if (!materialBags) return {};

  const map: Record<string, MaterialStockField> = {
    HD: 'hd',
    LLD: 'lld',
    EXCEED: 'exceed',
    IPA: 'ipa',
    TULANE: 'tulane',
  };

  const updates: Partial<Record<MaterialStockField, { increment: number }>> = {};
  for (const [grade, qty] of Object.entries(materialBags)) {
    const field = map[grade.toUpperCase()];
    if (!field || !qty) continue;
    updates[field] = { increment: -qty };
  }

  return updates;
}

function parseLoginBody(body: JsonObject) {
  return {
    username: parseUsername(body.username),
    password: parseString(body.password, 'password'),
  };
}

function parseUserCreateData(body: JsonObject) {
  return {
    username: parseUsername(body.username),
    name: parseString(body.name, 'name'),
    role: parseRole(body.role, 'role'),
    password: parsePassword(body.password, 'password'),
    active: 'active' in body ? parseBoolean(body.active, 'active') : true,
  };
}

function parseUserUpdateData(body: JsonObject) {
  const data: Record<string, unknown> = {};
  if ('username' in body) data.username = parseUsername(body.username);
  if ('name' in body) data.name = parseString(body.name, 'name');
  if ('role' in body) data.role = parseRole(body.role, 'role');
  if ('active' in body) data.active = parseBoolean(body.active, 'active');

  if (Object.keys(data).length === 0) {
    throw badRequest('No valid user fields to update.');
  }

  return data;
}

function parseUserPasswordUpdate(body: JsonObject) {
  return {
    password: parsePassword(body.password, 'password'),
  };
}

function serializeIssuingRecord<T extends { materialBags: string | null }>(record: T) {
  return {
    ...record,
    materialBags: record.materialBags ? (JSON.parse(record.materialBags) as Record<string, number>) : undefined,
  };
}

async function ensureMaterialStock(client: Pick<typeof prisma, 'materialStock'> = prisma) {
  return client.materialStock.upsert({
    where: { id: 'master' },
    update: {},
    create: { id: 'master', hd: 0, lld: 0, exceed: 0, ipa: 0, tulane: 0 },
  });
}

function getAllowedMaterialStockPatch(body: JsonObject) {
  const update: Partial<Record<MaterialStockField, number | { increment: number }>> = {};
  for (const [key, value] of Object.entries(body)) {
    if (!MATERIAL_STOCK_FIELDS.includes(key as MaterialStockField)) {
      throw badRequest(`Unsupported material stock field: ${key}`);
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      update[key as MaterialStockField] = value;
      continue;
    }

    if (isObject(value) && 'increment' in value && typeof value.increment === 'number' && Number.isFinite(value.increment)) {
      update[key as MaterialStockField] = { increment: value.increment };
      continue;
    }

    throw badRequest(`Invalid material stock update for field: ${key}`);
  }

  return update;
}

function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    void fn(req, res, next).catch(next);
  };
}

async function requireAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction) {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      throw unauthorized('Missing bearer token.');
    }

    const token = header.slice('Bearer '.length).trim();
    const payload = verifyToken(token);

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, username: true, name: true, role: true, active: true },
    });

    if (!user || !user.active) {
      throw unauthorized('Account is inactive.');
    }

    if (!USER_ROLES.has(user.role)) {
      throw unauthorized('Account role is invalid.');
    }

    req.authUser = {
      sub: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      exp: payload.exp,
    };
    next();
  } catch (error) {
    next(error);
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const body = parseLoginBody(requireObjectBody(req.body));

  const user = await prisma.user.findUnique({ where: { username: body.username } });
  if (!user || !user.active || !verifyPassword(body.password, user.passwordHash)) {
    throw unauthorized('Invalid username or password.');
  }

  const token = signToken({
    sub: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
  });

  res.json({
    token,
    user: sanitizeUser(user),
  });
}));

app.use('/api', requireAuth);

app.get('/api/auth/me', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = requireAuthUser(authReq);

  const user = await prisma.user.findUnique({
    where: { id: authUser.sub },
    select: { id: true, username: true, name: true, role: true, active: true },
  });

  if (!user || !user.active) {
    throw unauthorized('Account not found or inactive.');
  }

  res.json(sanitizeUser(user));
}));

app.get('/api/users', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertAdmin(authReq);

  const users = await prisma.user.findMany({
    select: {
      id: true,
      username: true,
      name: true,
      role: true,
      active: true,
      createdAt: true,
      updatedAt: true,
    },
    orderBy: { createdAt: 'asc' },
  });

  res.json(users.map(sanitizeManagedUser));
}));

app.post('/api/users', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertAdmin(authReq);
  const body = requireObjectBody(req.body);
  const data = parseUserCreateData(body);

  const user = await prisma.user.create({
    data: {
      username: data.username,
      name: data.name,
      role: data.role,
      active: data.active,
      passwordHash: hashPassword(data.password),
    },
    select: {
      id: true,
      username: true,
      name: true,
      role: true,
      active: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  res.status(201).json(sanitizeManagedUser(user));
}));

app.patch('/api/users/:id/password', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertAdmin(authReq);
  const id = parseParamId(req);
  const body = requireObjectBody(req.body);
  const data = parseUserPasswordUpdate(body);

  await prisma.user.update({
    where: { id },
    data: {
      passwordHash: hashPassword(data.password),
    },
  });

  res.json({ success: true });
}));

app.patch('/api/users/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const adminUser = assertAdmin(authReq);
  const id = parseParamId(req);
  const body = requireObjectBody(req.body);
  const data = parseUserUpdateData(body);

  if (id === adminUser.sub) {
    if ('active' in data && data.active === false) {
      throw badRequest('You cannot deactivate your own account.');
    }
    if ('role' in data && data.role !== 'Administrator') {
      throw badRequest('You cannot remove your own administrator role.');
    }
  }

  const user = await prisma.user.update({
    where: { id },
    data,
    select: {
      id: true,
      username: true,
      name: true,
      role: true,
      active: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  res.json(sanitizeManagedUser(user));
}));

app.delete('/api/users/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const adminUser = assertAdmin(authReq);
  const id = parseParamId(req);
  if (id === adminUser.sub) {
    throw badRequest('You cannot delete your own account.');
  }

  await prisma.user.delete({ where: { id } });
  res.json({ success: true });
}));

app.get('/api/products', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const products = await prisma.product.findMany({ orderBy: { name: 'asc' } });
  res.json(products);
}));

app.post('/api/products', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'edit_products');
  const data = parseProductCreateData(requireObjectBody(req.body));
  const product = await prisma.product.create({ data });
  res.status(201).json(product);
}));

app.patch('/api/products/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'edit_products');
  const id = parseParamId(req);
  const data = parseProductUpdateData(requireObjectBody(req.body));
  const product = await prisma.product.update({
    where: { id },
    data,
  });
  res.json(product);
}));

app.delete('/api/products/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'delete_products');
  const id = parseParamId(req);
  await prisma.product.delete({ where: { id } });
  res.json({ success: true });
}));

app.get('/api/customers', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const customers = await prisma.customer.findMany({ orderBy: { name: 'asc' } });
  res.json(customers);
}));

app.post('/api/customers', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'edit_customers');
  const data = parseCustomerCreateData(requireObjectBody(req.body));
  const customer = await prisma.customer.create({ data });
  res.status(201).json(customer);
}));

app.patch('/api/customers/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'edit_customers');
  const id = parseParamId(req);
  const data = parseCustomerUpdateData(requireObjectBody(req.body));
  const customer = await prisma.customer.update({
    where: { id },
    data,
  });
  res.json(customer);
}));

app.delete('/api/customers/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'delete_customers');
  const id = parseParamId(req);
  await prisma.customer.delete({ where: { id } });
  res.json({ success: true });
}));

app.get('/api/transactions', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const transactions = await prisma.transaction.findMany({
    orderBy: { timestamp: 'desc' },
  });
  res.json(transactions);
}));

app.post('/api/transactions', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const currentUser = requireAuthUser(authReq);
  const body = parseTransactionCreateData(requireObjectBody(req.body));
  assertAnyPermission(authReq, transactionPermissions(body.type));
  const transaction = await prisma.transaction.create({
    data: {
      ...body,
      recordedBy: currentUser.name,
    },
  });
  res.status(201).json(transaction);
}));

app.patch('/api/transactions/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const id = parseParamId(req);
  const data = parseTransactionUpdateData(requireObjectBody(req.body));
  if ('voided' in data) {
    assertPermission(authReq, 'void_transactions');
  } else {
    assertAnyPermission(authReq, ['dispatch_goods', 'void_transactions']);
  }
  const transaction = await prisma.transaction.update({
    where: { id },
    data,
  });
  res.json(transaction);
}));

app.get('/api/issuing-records', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const records = await prisma.issuingRecord.findMany({
    orderBy: { timestamp: 'desc' },
  });
  res.json(records.map(serializeIssuingRecord));
}));

app.post('/api/issuing-records', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'record_issuance');
  const body = requireObjectBody(req.body);
  const parsedMaterialBags = parseMaterialBags(body.materialBags);
  const createData = parseIssuingRecordCreateData(body, parsedMaterialBags);

  const record = await prisma.$transaction(async (tx: any) => {
    if (parsedMaterialBags) {
      const stock = await ensureMaterialStock(tx);
      const required = materialBagDeltas(parsedMaterialBags);

      for (const [field, op] of Object.entries(required)) {
        if (!op) continue;
        const current = stock[field as MaterialStockField];
        const requested = Math.abs(op.increment);
        if (current < requested) {
          throw badRequest(`Insufficient material stock for ${field.toUpperCase()}. Available: ${current}, requested: ${requested}`);
        }
      }

      if (Object.keys(required).length > 0) {
        await tx.materialStock.update({
          where: { id: 'master' },
          data: required,
        });
      }
    }

    return tx.issuingRecord.create({
      data: createData,
    });
  });

  res.status(201).json(serializeIssuingRecord(record));
}));

app.get('/api/production-records', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const records = await prisma.productionRecord.findMany({
    orderBy: { timestamp: 'desc' },
  });
  res.json(records);
}));

app.post('/api/production-records', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'production_intake');
  const body = requireObjectBody(req.body);
  const createData = parseProductionRecordCreateData(body);

  const existing = await prisma.productionRecord.findFirst({
    where: {
      date: createData.date,
      shift: createData.shift,
      machineType: createData.machineType,
    },
  });

  if (existing) {
    const { id: _id, ...updateData } = createData;
    const updated = await prisma.productionRecord.update({
      where: { id: existing.id },
      data: updateData,
    });
    res.json(updated);
    return;
  }

  const created = await prisma.productionRecord.create({ data: createData });
  res.status(201).json(created);
}));

app.get('/api/material-stock', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const stock = await ensureMaterialStock();
  res.json(stock);
}));

app.patch('/api/material-stock', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'manage_materials');
  const body = requireObjectBody(req.body);
  const data = getAllowedMaterialStockPatch(body);

  await ensureMaterialStock();
  const stock = await prisma.materialStock.update({
    where: { id: 'master' },
    data,
  });
  res.json(stock);
}));

app.get('/api/spare-parts', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const parts = await prisma.sparePart.findMany({ orderBy: { name: 'asc' } });
  res.json(parts);
}));

app.post('/api/spare-parts', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'manage_materials');
  const data = parseSparePartCreateData(requireObjectBody(req.body));
  const part = await prisma.sparePart.create({ data });
  res.status(201).json(part);
}));

app.patch('/api/spare-parts/:id', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'manage_materials');
  const id = parseParamId(req);
  const data = parseSparePartUpdateData(requireObjectBody(req.body));
  const part = await prisma.sparePart.update({
    where: { id },
    data,
  });
  res.json(part);
}));

app.get('/api/spare-issuances', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'view_all');
  const issuances = await prisma.sparePartIssuance.findMany({
    orderBy: { timestamp: 'desc' },
  });
  res.json(issuances);
}));

app.post('/api/spare-issuances', asyncHandler(async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  assertPermission(authReq, 'record_issuance');
  const body = requireObjectBody(req.body);
  const quantity = parsePositiveNumber(body.quantity, 'quantity');
  const partId = typeof body.partId === 'string' && body.partId.trim() ? body.partId : null;
  if (!partId) {
    throw badRequest('partId is required.');
  }

  const issuance = await prisma.$transaction(async (tx: any) => {
    const part = await tx.sparePart.findUnique({ where: { id: partId } });
    if (!part) {
      throw badRequest('Spare part not found.');
    }
    if (part.quantity < quantity) {
      throw badRequest(`Insufficient spare part stock. Available: ${part.quantity}, requested: ${quantity}`);
    }

    await tx.sparePart.update({
      where: { id: partId },
      data: { quantity: { decrement: quantity } },
    });

    return tx.sparePartIssuance.create({
      data: {
        id: parseString(body.id, 'id'),
        partId,
        quantity,
        issuedTo: parseString(body.issuedTo, 'issuedTo'),
        date: parseString(body.date, 'date'),
        timestamp: parseTimestamp(body.timestamp),
        notes: parseOptionalNullableString(body.notes, 'notes'),
      },
    });
  });

  res.status(201).json(issuance);
}));

// Seed initial products and users if empty
async function seed() {
  const productCount = await prisma.product.count();
  if (productCount === 0) {
    await prisma.product.createMany({
      data: [
        {
          id: 'prod-rollers',
          name: 'Rollers',
          type: 'Roller',
          unit: 'Pcs',
          specification: 'Standard Roller',
          size: 'N/A',
          storageLocation: 'Factory Floor',
          minStockLevel: 100,
        },
        {
          id: 'prod-bags',
          name: 'Packing Bags',
          type: 'Packing Bag',
          unit: 'Pcs',
          specification: 'Standard Bag',
          size: 'N/A',
          storageLocation: 'Factory Reserve',
          minStockLevel: 1000,
        },
      ],
    });
    console.log('Seeded initial products');
  }

  const userCount = await prisma.user.count();
  if (userCount === 0) {
    const defaultUsers = [
      { username: 'admin', name: 'System Administrator', role: 'Administrator', password: process.env.SEED_ADMIN_PASSWORD ?? 'admin123' },
      { username: 'production', name: 'Production Supervisor', role: 'Production Supervisor', password: process.env.SEED_PRODUCTION_PASSWORD ?? 'production123' },
      { username: 'warehouse', name: 'Warehouse Officer', role: 'Warehouse Officer', password: process.env.SEED_WAREHOUSE_PASSWORD ?? 'warehouse123' },
      { username: 'logistics', name: 'Logistics Officer', role: 'Logistics Officer', password: process.env.SEED_LOGISTICS_PASSWORD ?? 'logistics123' },
      { username: 'management', name: 'Management', role: 'Management', password: process.env.SEED_MANAGEMENT_PASSWORD ?? 'management123' },
    ];

    await prisma.user.createMany({
      data: defaultUsers.map((user) => ({
        username: user.username,
        name: user.name,
        role: user.role,
        passwordHash: hashPassword(user.password),
        active: true,
      })),
    });

    console.log('Seeded default users (admin, production, warehouse, logistics, management)');
  }
}

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

function isPrismaKnownError(error: unknown): error is { code: string; meta?: unknown } {
  return isObject(error) && typeof error.code === 'string';
}

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (isObject(error) && typeof error.status === 'number') {
    const message = typeof error.message === 'string' ? error.message : 'Bad request';
    res.status(error.status).json({ error: message, details: error.details });
    return;
  }

  if (isPrismaKnownError(error)) {
    if (error.code === 'P2025') {
      res.status(404).json({ error: 'Record not found' });
      return;
    }

    if (error.code === 'P2002') {
      res.status(409).json({ error: 'Duplicate record' });
      return;
    }

    if (error.code === 'P2003') {
      res.status(409).json({ error: 'Cannot delete: record is still referenced by related data.' });
      return;
    }
  }

  console.error('Unhandled API error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

async function startServer() {
  if (TOKEN_SECRET === 'change-me-in-production') {
    console.warn('AUTH_TOKEN_SECRET is using the development fallback. Set AUTH_TOKEN_SECRET in production.');
  }

  await seed();
  await ensureMaterialStock();

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  const shutdown = async () => {
    await prisma.$disconnect();
    server.close(() => process.exit(0));
  };

  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
}

startServer().catch(async (err) => {
  console.error('Failed to start server:', err);
  await prisma.$disconnect();
  process.exit(1);
});
