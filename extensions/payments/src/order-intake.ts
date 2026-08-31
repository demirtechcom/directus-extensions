import type { Request, Response, Router } from "express";

import { calculateMarketplaceSettlement } from "./marketplace-finance.js";

const ORDER_SOURCES = [
  "qr_table",
  "direct",
  "whatsapp",
  "trendyol_go",
  "yemek_sepeti",
  "getir",
  "migros_yemek",
  "tikla_gelsin",
] as const;

type OrderSource = (typeof ORDER_SOURCES)[number];

const CUSTOMER_SOURCES = new Set<OrderSource>(["qr_table", "direct", "whatsapp"]);
const AUTHENTICATED_CUSTOMER_SOURCES = new Set<OrderSource>(["direct"]);
const BUSINESS_COLLECTED_SOURCES = new Set<OrderSource>([
  "qr_table",
  "whatsapp",
  "direct",
]);
const BUSINESS_ONLY_SOURCES = new Set<OrderSource>([
  "trendyol_go",
  "yemek_sepeti",
  "getir",
  "migros_yemek",
  "tikla_gelsin",
]);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface OrderLineInput {
  product_id: number;
  quantity: number;
}

export interface OrderIntakeInput {
  client_request_id: string;
  venue_id: number;
  table_id: number | null;
  table_number: number;
  order_source: OrderSource;
  customer_name: string | null;
  customer_phone: string | null;
  note: string | null;
  payment_method: "online" | "cash" | "card" | null;
  order_items: OrderLineInput[];
}

interface Accountability {
  user?: string | null;
}

type AuthenticatedRequest = Request & { accountability?: Accountability };

interface QueryOptions {
  filter?: Record<string, unknown>;
  fields?: string[];
  limit?: number;
  sort?: string[];
}

interface ItemsServiceLike {
  readByQuery(options: QueryOptions): Promise<Record<string, unknown>[]>;
  readOne(
    key: string | number,
    options?: QueryOptions,
  ): Promise<Record<string, unknown>>;
  createOne(payload: Record<string, unknown>): Promise<unknown>;
  createMany(payloads: Record<string, unknown>[]): Promise<unknown>;
  updateOne(
    key: string | number,
    payload: Record<string, unknown>,
  ): Promise<unknown>;
}

interface UsersServiceLike {
  readOne(
    key: string,
    options?: QueryOptions,
  ): Promise<Record<string, unknown>>;
}

interface ServiceOptions {
  schema: unknown;
  knex?: unknown;
  accountability: { admin: true };
}

interface OrderIntakeContext {
  services: {
    ItemsService: new (
      collection: string,
      options: ServiceOptions,
    ) => ItemsServiceLike;
    UsersService: new (options: ServiceOptions) => UsersServiceLike;
  };
  getSchema(): Promise<unknown>;
  database: {
    transaction<T>(handler: (trx: unknown) => Promise<T>): Promise<T>;
  };
  logger: {
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
}

interface ProductRecord {
  id: number;
  venueId: number;
  price: number;
  isActive: boolean;
  status: string;
  isStockTracked: boolean;
  stockQuantity: number | null;
  vatRateBps: number | null;
}

interface QuotedLine extends OrderLineInput {
  unit_price: number;
  unit_price_minor: number;
  line_subtotal_minor: number;
  vat_rate_bps: number;
  vat_amount_minor: number;
  is_discounted: boolean;
}

export interface VenuePaymentSettings {
  acceptsOnlinePayment: boolean;
  acceptsCashOnDelivery: boolean;
  acceptsCardOnDelivery: boolean;
  onlinePaymentFeatureEnabled: boolean;
  paytrMarketplaceStatus: string;
}

interface OrderResult {
  outcome: "created" | "already_created";
  client_request_id: string;
  order: {
    id: number;
    order_status: string;
    total_amount: number;
  };
}

export class OrderIntakeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "OrderIntakeError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredPositiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      `${field} must be a positive integer`,
    );
  }
  return value;
}

function optionalText(
  value: unknown,
  field: string,
  maxLength: number,
): string | null {
  if (value == null || value === "") return null;
  if (typeof value !== "string") {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      `${field} must be a string`,
    );
  }
  const normalized = value.trim();
  if (!normalized) return null;
  if (normalized.length > maxLength) {
    throw new OrderIntakeError(400, "INVALID_REQUEST", `${field} is too long`);
  }
  return normalized;
}

export function parseOrderIntakeInput(body: unknown): OrderIntakeInput {
  if (!isRecord(body)) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      "Request body must be an object",
    );
  }

  if (
    typeof body.client_request_id !== "string" ||
    !UUID_PATTERN.test(body.client_request_id)
  ) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      "client_request_id must be a UUID",
    );
  }
  const venueId = requiredPositiveInteger(body.venue_id, "venue_id");
  const source = body.order_source;
  if (
    typeof source !== "string" ||
    !ORDER_SOURCES.includes(source as OrderSource)
  ) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      "order_source is invalid",
    );
  }
  const tableNumber = body.table_number;
  if (
    typeof tableNumber !== "number" ||
    !Number.isInteger(tableNumber) ||
    tableNumber < 0
  ) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      "table_number must be a non-negative integer",
    );
  }
  const tableId =
    body.table_id == null
      ? null
      : requiredPositiveInteger(body.table_id, "table_id");
  if (
    (source === "qr_table" && tableNumber === 0) ||
    (tableNumber > 0 && tableId === null)
  ) {
    throw new OrderIntakeError(
      422,
      "TABLE_REQUIRED",
      "An active table record is required",
    );
  }

  if (
    !Array.isArray(body.order_items) ||
    body.order_items.length === 0 ||
    body.order_items.length > 100
  ) {
    throw new OrderIntakeError(
      400,
      "INVALID_REQUEST",
      "order_items must contain between 1 and 100 lines",
    );
  }
  const productIds = new Set<number>();
  const orderItems = body.order_items.map((rawLine, index) => {
    if (!isRecord(rawLine)) {
      throw new OrderIntakeError(
        400,
        "INVALID_REQUEST",
        `order_items.${index} must be an object`,
      );
    }
    const productId = requiredPositiveInteger(
      rawLine.product_id,
      `order_items.${index}.product_id`,
    );
    const quantity = requiredPositiveInteger(
      rawLine.quantity,
      `order_items.${index}.quantity`,
    );
    if (quantity > 99) {
      throw new OrderIntakeError(
        400,
        "INVALID_REQUEST",
        `order_items.${index}.quantity is too large`,
      );
    }
    if (productIds.has(productId)) {
      throw new OrderIntakeError(
        400,
        "INVALID_REQUEST",
        "Duplicate products must be combined into one line",
      );
    }
    productIds.add(productId);
    return { product_id: productId, quantity };
  });

  const customerName = optionalText(body.customer_name, "customer_name", 120);
  if (CUSTOMER_SOURCES.has(source as OrderSource) && customerName === null) {
    throw new OrderIntakeError(
      422,
      "CUSTOMER_NAME_REQUIRED",
      "Customer name is required",
    );
  }

  const requestedPaymentMethod = body.payment_method;
  let paymentMethod: OrderIntakeInput["payment_method"] = null;
  if (requestedPaymentMethod != null) {
    if (
      typeof requestedPaymentMethod !== "string" ||
      !["online", "cash", "card"].includes(requestedPaymentMethod)
    ) {
      throw new OrderIntakeError(
        422,
        "INVALID_PAYMENT_METHOD",
        "payment_method is not supported",
      );
    }
    paymentMethod = requestedPaymentMethod as "online" | "cash" | "card";
  }
  if (source === "direct" && paymentMethod === null) {
    throw new OrderIntakeError(
      422,
      "PAYMENT_METHOD_REQUIRED",
      "Direct orders require a payment method",
    );
  }

  return {
    client_request_id: body.client_request_id,
    venue_id: venueId,
    table_id: tableId,
    table_number: tableNumber,
    order_source: source as OrderSource,
    customer_name: customerName,
    customer_phone: optionalText(body.customer_phone, "customer_phone", 32),
    note: optionalText(body.note, "note", 1000),
    payment_method: paymentMethod,
    order_items: orderItems,
  };
}

function numericId(value: unknown, field: string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new OrderIntakeError(
      500,
      "ORDER_PERSISTENCE_FAILED",
      `${field} is invalid`,
    );
  }
  return parsed;
}

function nullableNumber(value: unknown): number | null {
  if (value == null) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function relatedId(value: unknown): number | null {
  if (isRecord(value)) return nullableNumber(value.id);
  return nullableNumber(value);
}

function toProduct(record: Record<string, unknown>): ProductRecord {
  const stockQuantity = nullableNumber(record.stock_quantity);
  return {
    id: numericId(record.id, "product.id"),
    venueId: numericId(relatedId(record.venue_id), "product.venue_id"),
    price: Number(record.price),
    isActive: record.is_active === true,
    status: String(record.status ?? ""),
    isStockTracked: record.is_stock_tracked === true,
    stockQuantity: stockQuantity === null ? null : Math.trunc(stockQuantity),
    vatRateBps: nullableNumber(record.vat_rate_bps),
  };
}

export function assertPaymentMethodAvailable(
  paymentMethod: "online" | "cash" | "card",
  settings: VenuePaymentSettings,
): void {
  const available =
    paymentMethod === "online"
      ? settings.acceptsOnlinePayment &&
        settings.onlinePaymentFeatureEnabled &&
        settings.paytrMarketplaceStatus === "approved"
      : paymentMethod === "cash"
        ? settings.acceptsCashOnDelivery
        : settings.acceptsCardOnDelivery;
  if (!available) {
    throw new OrderIntakeError(
      422,
      "PAYMENT_METHOD_UNAVAILABLE",
      "The restaurant is not accepting the selected payment method",
    );
  }
}

export function quoteOrderLines(
  input: OrderIntakeInput,
  products: ProductRecord[],
  defaultVatRateBps = 0,
  discountedPrices: ReadonlyMap<number, number> = new Map(),
): {
  lines: QuotedLine[];
  totalMinor: number;
} {
  const byId = new Map(products.map((product) => [product.id, product]));
  let totalMinor = 0;
  const lines = input.order_items.map((line) => {
    const product = byId.get(line.product_id);
    if (
      !product ||
      product.venueId !== input.venue_id ||
      !product.isActive ||
      product.status !== "published" ||
      !Number.isFinite(product.price) ||
      product.price < 0
    ) {
      throw new OrderIntakeError(
        422,
        "PRODUCT_UNAVAILABLE",
        `Product ${line.product_id} is unavailable`,
      );
    }
    const discountedPrice = discountedPrices.get(product.id);
    const effectivePrice =
      discountedPrice !== undefined && discountedPrice >= 0 && discountedPrice < product.price
        ? discountedPrice
        : product.price;
    const unitMinor = Math.round(effectivePrice * 100);
    totalMinor += unitMinor * line.quantity;
    if (!Number.isSafeInteger(totalMinor)) {
      throw new OrderIntakeError(
        422,
        "INVALID_TOTAL",
        "Order total is too large",
      );
    }
    const lineSubtotalMinor = unitMinor * line.quantity;
    const vatRateBps = product.vatRateBps ?? defaultVatRateBps;
    if (!Number.isInteger(vatRateBps) || vatRateBps < 0 || vatRateBps > 10_000) {
      throw new OrderIntakeError(422, "INVALID_VAT_RATE", "Product VAT rate is invalid");
    }
    return {
      ...line,
      unit_price: unitMinor / 100,
      unit_price_minor: unitMinor,
      line_subtotal_minor: lineSubtotalMinor,
      vat_rate_bps: vatRateBps,
      vat_amount_minor: Math.round(
        (lineSubtotalMinor * vatRateBps) / (10_000 + vatRateBps),
      ),
      is_discounted: effectivePrice < product.price,
    };
  });
  return { lines, totalMinor };
}

function normalizeComparableText(value: unknown): string | null {
  return value == null || value === "" ? null : String(value);
}

function assertSameIdempotentRequest(
  existing: Record<string, unknown>,
  existingLines: Record<string, unknown>[],
  input: OrderIntakeInput,
): void {
  const storedLines = existingLines
    .map((line) => ({
      product_id: numericId(
        relatedId(line.product_id),
        "order_item.product_id",
      ),
      quantity: numericId(line.quantity, "order_item.quantity"),
    }))
    .sort((a, b) => a.product_id - b.product_id);
  const requestedLines = [...input.order_items].sort(
    (a, b) => a.product_id - b.product_id,
  );
  const matches =
    relatedId(existing.venue_id) === input.venue_id &&
    relatedId(existing.table_id) === input.table_id &&
    nullableNumber(existing.table_number) === input.table_number &&
    existing.order_source === input.order_source &&
    normalizeComparableText(existing.customer_name) === input.customer_name &&
    normalizeComparableText(existing.customer_phone) === input.customer_phone &&
    normalizeComparableText(existing.note) === input.note &&
    normalizeComparableText(existing.payment_method) === input.payment_method &&
    JSON.stringify(storedLines) === JSON.stringify(requestedLines);
  if (!matches) {
    throw new OrderIntakeError(
      409,
      "IDEMPOTENCY_KEY_REUSED",
      "client_request_id was already used for a different order",
    );
  }
}

async function loadQuote(
  ProductsService: ItemsServiceLike,
  input: OrderIntakeInput,
  defaultVatRateBps = 0,
  CampaignProductsService?: ItemsServiceLike,
): Promise<{ lines: QuotedLine[]; totalMinor: number }> {
  const products = await ProductsService.readByQuery({
    filter: {
      _and: [
        { venue_id: { _eq: input.venue_id } },
        { id: { _in: input.order_items.map((line) => line.product_id) } },
      ],
    },
    fields: [
      "id",
      "venue_id",
      "price",
      "is_active",
      "status",
      "is_stock_tracked",
      "stock_quantity",
      "vat_rate_bps",
    ],
    limit: -1,
  });
  const productRecords = products.map(toProduct);
  const baseQuote = quoteOrderLines(input, productRecords, defaultVatRateBps);
  if (!CampaignProductsService) return baseQuote;
  const now = new Date();
  const campaignProducts = await CampaignProductsService.readByQuery({
    filter: {
      _and: [
        { product_id: { _in: input.order_items.map((line) => line.product_id) } },
        { campaign_id: { campaign_status: { _eq: "active" } } },
        { campaign_id: { start_datetime: { _lte: now.toISOString() } } },
        { campaign_id: { end_datetime: { _gte: now.toISOString() } } },
      ],
    },
    fields: [
      "product_id",
      "discounted_price",
      "campaign_id.campaign_status",
      "campaign_id.start_datetime",
      "campaign_id.end_datetime",
      "campaign_id.minimum_order_amount",
      "campaign_id.schedule_type",
      "campaign_id.schedule_days",
      "campaign_id.daily_start_time",
      "campaign_id.daily_end_time",
    ],
    limit: -1,
  });
  const discountedPrices = activeDiscountedPrices(
    campaignProducts,
    baseQuote.totalMinor / 100,
    now,
  );
  return quoteOrderLines(input, productRecords, defaultVatRateBps, discountedPrices);
}

const WEEKDAYS = [
  "sunday",
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
] as const;

function timeMinutes(value: unknown): number | null {
  const match = /^(\d{1,2}):(\d{2})/.exec(String(value ?? ""));
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  return hours <= 23 && minutes <= 59 ? hours * 60 + minutes : null;
}

export function activeDiscountedPrices(
  rows: Record<string, unknown>[],
  baseSubtotal: number,
  now: Date,
): Map<number, number> {
  const prices = new Map<number, number>();
  for (const row of rows) {
    const campaign = isRecord(row.campaign_id) ? row.campaign_id : null;
    const productId = relatedId(row.product_id);
    const price = nullableNumber(row.discounted_price);
    if (!campaign || !productId || price === null || price < 0) continue;
    const start = Date.parse(String(campaign.start_datetime ?? ""));
    const end = Date.parse(String(campaign.end_datetime ?? ""));
    const minimum = Number(campaign.minimum_order_amount ?? 0);
    if (
      campaign.campaign_status !== "active" ||
      !Number.isFinite(start) ||
      !Number.isFinite(end) ||
      now.getTime() < start ||
      now.getTime() > end ||
      !Number.isFinite(minimum) ||
      baseSubtotal < Math.max(0, minimum)
    ) {
      continue;
    }
    const scheduleType = String(campaign.schedule_type ?? "once");
    if (scheduleType !== "once") {
      const startMinutes = timeMinutes(campaign.daily_start_time);
      const endMinutes = timeMinutes(campaign.daily_end_time);
      if (startMinutes === null || endMinutes === null) continue;
      const currentMinutes = now.getHours() * 60 + now.getMinutes();
      const crossesMidnight = endMinutes < startMinutes;
      const timeMatches = crossesMidnight
        ? currentMinutes >= startMinutes || currentMinutes <= endMinutes
        : currentMinutes >= startMinutes && currentMinutes <= endMinutes;
      if (!timeMatches) continue;
      if (scheduleType === "weekly") {
        const scheduleDate = new Date(now);
        if (crossesMidnight && currentMinutes <= endMinutes) {
          scheduleDate.setDate(scheduleDate.getDate() - 1);
        }
        const days = Array.isArray(campaign.schedule_days) ? campaign.schedule_days : [];
        if (!days.includes(WEEKDAYS[scheduleDate.getDay()])) continue;
      }
    }
    const current = prices.get(productId);
    if (current === undefined || price < current) prices.set(productId, price);
  }
  return prices;
}

async function assertVenueAccess(
  input: OrderIntakeInput,
  userId: string | null,
  VenuesService: ItemsServiceLike,
  UsersService: UsersServiceLike,
): Promise<Record<string, unknown>> {
  const venues = await VenuesService.readByQuery({
    filter: { id: { _eq: input.venue_id } },
    fields: [
      "id",
      "status",
      "is_visible",
      "approval_status",
      "delivery_fee",
      "has_free_delivery",
      "default_vat_rate_bps",
      "accepts_online_payment",
      "accepts_cash_on_delivery",
      "accepts_card_on_delivery",
      "online_payment_feature_enabled",
      "paytr_marketplace_status",
    ],
    limit: 1,
  });
  const venue = venues[0];
  if (!venue) {
    throw new OrderIntakeError(404, "VENUE_NOT_FOUND", "Venue was not found");
  }

  if (BUSINESS_ONLY_SOURCES.has(input.order_source)) {
    await assertBusinessVenueAccess(input, userId, UsersService);
    return venue;
  }

  if (AUTHENTICATED_CUSTOMER_SOURCES.has(input.order_source) && !userId) {
    throw new OrderIntakeError(
      401,
      "AUTHENTICATION_REQUIRED",
      "Authentication is required",
    );
  }

  if (
    venue.status !== "published" ||
    venue.is_visible !== true ||
    venue.approval_status !== "approved"
  ) {
    throw new OrderIntakeError(
      422,
      "VENUE_UNAVAILABLE",
      "Venue is not accepting customer orders",
    );
  }
  if (input.payment_method !== null) {
    assertPaymentMethodAvailable(input.payment_method, {
      acceptsOnlinePayment: venue.accepts_online_payment === true,
      acceptsCashOnDelivery: venue.accepts_cash_on_delivery !== false,
      acceptsCardOnDelivery: venue.accepts_card_on_delivery !== false,
      onlinePaymentFeatureEnabled: venue.online_payment_feature_enabled === true,
      paytrMarketplaceStatus: String(venue.paytr_marketplace_status ?? "pending"),
    });
  }
  return venue;
}

interface MarketplaceTerms {
  defaultFoodVatBps: number;
  commissionRateBps: number;
  commissionVatRateBps: number;
  withholdingRateBps: number;
}

function configuredRate(value: unknown, field: string): number {
  const rate = Number(value);
  if (!Number.isInteger(rate) || rate < 0 || rate > 10_000) {
    throw new OrderIntakeError(
      503,
      "ONLINE_PAYMENT_CONFIGURATION_MISSING",
      `${field} is not configured`,
    );
  }
  return rate;
}

async function loadMarketplaceTerms(
  venueId: number,
  CommissionTerms: ItemsServiceLike,
  FiscalConfigurations: ItemsServiceLike,
): Promise<MarketplaceTerms> {
  const now = new Date().toISOString();
  const [terms, configurations] = await Promise.all([
    CommissionTerms.readByQuery({
      filter: {
        _and: [
          { venue_id: { _eq: venueId } },
          { term_status: { _eq: "active" } },
          { effective_from: { _lte: now } },
          {
            _or: [
              { effective_until: { _null: true } },
              { effective_until: { _gt: now } },
            ],
          },
        ],
      },
      fields: ["commission_bps", "commission_vat_bps"],
      sort: ["-effective_from"],
      limit: 1,
    }),
    FiscalConfigurations.readByQuery({
      filter: {
        _and: [
          { configuration_status: { _eq: "active" } },
          { effective_from: { _lte: now } },
          {
            _or: [
              { effective_until: { _null: true } },
              { effective_until: { _gt: now } },
            ],
          },
        ],
      },
      fields: ["default_food_vat_bps", "withholding_bps"],
      sort: ["-effective_from"],
      limit: 1,
    }),
  ]);
  const term = terms[0];
  const fiscal = configurations[0];
  if (!term || !fiscal) {
    throw new OrderIntakeError(
      503,
      "ONLINE_PAYMENT_CONFIGURATION_MISSING",
      "Active marketplace financial terms are required",
    );
  }
  return {
    defaultFoodVatBps: configuredRate(
      fiscal.default_food_vat_bps,
      "default_food_vat_bps",
    ),
    commissionRateBps: configuredRate(term.commission_bps, "commission_bps"),
    commissionVatRateBps: configuredRate(
      fiscal.commission_vat_bps,
      "commission_vat_bps",
    ),
    withholdingRateBps: configuredRate(fiscal.withholding_bps, "withholding_bps"),
  };
}

function deliveryFeeMinor(input: OrderIntakeInput, venue: Record<string, unknown>): number {
  if (input.order_source !== "direct" || venue.has_free_delivery === true) return 0;
  const amount = Number(venue.delivery_fee ?? 0);
  if (!Number.isFinite(amount) || amount < 0) {
    throw new OrderIntakeError(422, "INVALID_TOTAL", "Delivery fee is invalid");
  }
  return Math.round(amount * 100);
}

async function assertBusinessVenueAccess(
  input: OrderIntakeInput,
  userId: string | null,
  UsersService: UsersServiceLike,
): Promise<void> {
  if (!userId) {
    throw new OrderIntakeError(
      401,
      "AUTHENTICATION_REQUIRED",
      "Authentication is required",
    );
  }
  const user = await UsersService.readOne(userId, {
    fields: ["id", "venue_id"],
  });
  if (relatedId(user.venue_id) !== input.venue_id) {
    throw new OrderIntakeError(
      403,
      "VENUE_ACCESS_DENIED",
      "User cannot create orders for this venue",
    );
  }
}

async function assertTable(
  input: OrderIntakeInput,
  TablesService: ItemsServiceLike,
): Promise<void> {
  if (input.table_id === null) return;
  const tables = await TablesService.readByQuery({
    filter: { id: { _eq: input.table_id } },
    fields: ["id", "venue_id", "table_number", "status"],
    limit: 1,
  });
  const table = tables[0];
  if (
    !table ||
    relatedId(table.venue_id) !== input.venue_id ||
    nullableNumber(table.table_number) !== input.table_number ||
    table.status !== "active"
  ) {
    throw new OrderIntakeError(
      422,
      "TABLE_UNAVAILABLE",
      "Table is invalid or inactive",
    );
  }
}

async function completeExistingOrder(
  existing: Record<string, unknown>,
  input: OrderIntakeInput,
  services: {
    Orders: ItemsServiceLike;
    OrderItems: ItemsServiceLike;
    OrderPayments: ItemsServiceLike;
    Products: ItemsServiceLike;
  },
): Promise<OrderResult> {
  const orderId = numericId(existing.id, "order.id");
  const existingLines = await services.OrderItems.readByQuery({
    filter: { order_id: { _eq: orderId } },
    fields: ["id", "product_id", "quantity", "unit_price"],
    limit: -1,
  });
  assertSameIdempotentRequest(existing, existingLines, input);
  const paymentNeeded =
    BUSINESS_COLLECTED_SOURCES.has(input.order_source) && input.payment_method !== "online";
  const payments = paymentNeeded
    ? await services.OrderPayments.readByQuery({
        filter: { order_id: { _eq: orderId } },
        fields: ["id"],
        limit: 1,
      })
    : [];
  const storedTotal = nullableNumber(existing.total_amount);
  const needsRepair = storedTotal === null || (paymentNeeded && !payments[0]);
  const orderStatus = String(existing.order_status ?? "pending");

  if (!needsRepair) {
    return {
      outcome: "already_created",
      client_request_id: input.client_request_id,
      order: {
        id: orderId,
        order_status: orderStatus,
        total_amount: storedTotal,
      },
    };
  }
  if (orderStatus !== "pending" && orderStatus !== "whatsapp_pending") {
    throw new OrderIntakeError(
      409,
      "IDEMPOTENCY_RECORD_INCOMPLETE",
      "Existing finalized order cannot be repaired automatically",
    );
  }

  const quote = await loadQuote(services.Products, input);
  if (storedTotal === null) {
    for (const line of existingLines) {
      const productId = numericId(
        relatedId(line.product_id),
        "order_item.product_id",
      );
      const quoted = quote.lines.find((item) => item.product_id === productId);
      if (!quoted) {
        throw new OrderIntakeError(
          409,
          "IDEMPOTENCY_RECORD_INCOMPLETE",
          "Existing order lines are incomplete",
        );
      }
      await services.OrderItems.updateOne(numericId(line.id, "order_item.id"), {
        unit_price: quoted.unit_price,
        is_discounted: false,
      });
    }
    await services.Orders.updateOne(orderId, {
      total_amount: quote.totalMinor / 100,
    });
  }

  if (paymentNeeded && !payments[0]) {
    await services.OrderPayments.createOne({
      order_id: orderId,
      payment_status: "pending",
      payment_method: input.payment_method,
      amount_minor: quote.totalMinor,
      currency: "TRY",
    });
  }

  return {
    outcome: "already_created",
    client_request_id: input.client_request_id,
    order: {
      id: orderId,
      order_status: orderStatus,
      total_amount: storedTotal ?? quote.totalMinor / 100,
    },
  };
}

async function createAtomicOrder(
  input: OrderIntakeInput,
  userId: string | null,
  context: OrderIntakeContext,
): Promise<OrderResult> {
  const schema = await context.getSchema();
  return context.database.transaction(async (trx) => {
    const options: ServiceOptions = {
      schema,
      knex: trx,
      accountability: { admin: true },
    };
    const Orders = new context.services.ItemsService("orders", options);
    const OrderItems = new context.services.ItemsService(
      "order_items",
      options,
    );
    const OrderPayments = new context.services.ItemsService(
      "order_payments",
      options,
    );
    const OnlineOrderPayments = new context.services.ItemsService(
      "online_order_payments",
      options,
    );
    const Products = new context.services.ItemsService("products", options);
    const CampaignProducts = new context.services.ItemsService("campaign_products", options);
    const Venues = new context.services.ItemsService("venues", options);
    const Tables = new context.services.ItemsService("venue_tables", options);
    const CommissionTerms = new context.services.ItemsService(
      "venue_commission_terms",
      options,
    );
    const FiscalConfigurations = new context.services.ItemsService(
      "fiscal_configurations",
      options,
    );
    const Users = new context.services.UsersService(options);

    const existingOrders = await Orders.readByQuery({
      filter: { client_request_id: { _eq: input.client_request_id } },
      fields: [
        "id",
        "venue_id",
        "table_id",
        "table_number",
        "order_source",
        "customer_name",
        "customer_phone",
        "note",
        "payment_method",
        "total_amount",
        "order_status",
      ],
      limit: 1,
    });
    if (existingOrders[0]) {
      // A committed order remains the source of truth even if the venue or
      // table becomes unavailable before a timed-out client retries. Business
      // replays still re-check ownership; customer request IDs are unguessable
      // bearer idempotency keys and the response contains no customer data.
      if (BUSINESS_ONLY_SOURCES.has(input.order_source)) {
        await assertBusinessVenueAccess(input, userId, Users);
      }
      return completeExistingOrder(existingOrders[0], input, {
        Orders,
        OrderItems,
        OrderPayments,
        Products,
      });
    }

    const venue = await assertVenueAccess(input, userId, Venues, Users);
    await assertTable(input, Tables);
    const marketplaceTerms =
      input.payment_method === "online"
        ? await loadMarketplaceTerms(
            input.venue_id,
            CommissionTerms,
            FiscalConfigurations,
          )
        : null;
    const defaultVatRateBps =
      nullableNumber(venue.default_vat_rate_bps) ??
      marketplaceTerms?.defaultFoodVatBps ??
      0;
    const quote = await loadQuote(Products, input, defaultVatRateBps, CampaignProducts);
    const orderDeliveryFeeMinor = deliveryFeeMinor(input, venue);
    const totalMinor = quote.totalMinor + orderDeliveryFeeMinor;
    if (!Number.isSafeInteger(totalMinor)) {
      throw new OrderIntakeError(422, "INVALID_TOTAL", "Order total is too large");
    }
    const settlement = marketplaceTerms
      ? calculateMarketplaceSettlement({
          foodSubtotalMinor: quote.totalMinor,
          deliveryFeeMinor: orderDeliveryFeeMinor,
          commissionRateBps: marketplaceTerms.commissionRateBps,
          commissionVatRateBps: marketplaceTerms.commissionVatRateBps,
          withholdingRateBps: marketplaceTerms.withholdingRateBps,
          vatBreakdown: quote.lines.map((line) => ({
            grossMinor: line.line_subtotal_minor,
            vatRateBps: line.vat_rate_bps,
          })),
        })
      : null;

    const createdId = await Orders.createOne({
      client_request_id: input.client_request_id,
      venue_id: input.venue_id,
      table_id: input.table_id,
      table_number: input.table_number,
      order_source: input.order_source,
      customer_name: input.customer_name,
      customer_phone: input.customer_phone,
      note: input.note,
      user_id: CUSTOMER_SOURCES.has(input.order_source) ? userId : null,
      order_status: input.payment_method === "online" ? "awaiting_payment" : "pending",
      payment_method: input.payment_method,
      subtotal_minor: quote.totalMinor,
      delivery_fee_minor: orderDeliveryFeeMinor,
      total_amount_minor: totalMinor,
      total_amount: totalMinor / 100,
    });
    const orderId = numericId(createdId, "order.id");

    await OrderItems.createMany(
      quote.lines.map((line) => ({
        order_id: orderId,
        product_id: line.product_id,
        quantity: line.quantity,
        unit_price: line.unit_price,
        unit_price_minor: line.unit_price_minor,
        line_subtotal_minor: line.line_subtotal_minor,
        vat_rate_bps: line.vat_rate_bps,
        vat_amount_minor: line.vat_amount_minor,
        is_discounted: line.is_discounted,
      })),
    );

    if (settlement) {
      if (!userId) {
        throw new OrderIntakeError(
          401,
          "AUTHENTICATION_REQUIRED",
          "Authentication is required",
        );
      }
      await OnlineOrderPayments.createOne({
        order_id: orderId,
        venue_id: input.venue_id,
        user_id: userId,
        payment_status: "pending",
        amount_minor: totalMinor,
        refunded_amount_minor: 0,
        currency: "TRY",
        food_subtotal_minor: quote.totalMinor,
        delivery_fee_minor: orderDeliveryFeeMinor,
        food_vat_minor: settlement.foodVatMinor,
        commission_minor: settlement.commissionMinor,
        commission_vat_minor: settlement.commissionVatMinor,
        withholding_minor: settlement.withholdingMinor,
        venue_net_minor: settlement.venuePayoutMinor,
      });
    }

    if (
      BUSINESS_COLLECTED_SOURCES.has(input.order_source) &&
      input.payment_method !== "online"
    ) {
      await OrderPayments.createOne({
        order_id: orderId,
        payment_status: "pending",
        payment_method: input.payment_method,
        amount_minor: totalMinor,
        currency: "TRY",
      });
    }

    return {
      outcome: "created",
      client_request_id: input.client_request_id,
      order: {
        id: orderId,
        order_status: input.payment_method === "online" ? "awaiting_payment" : "pending",
        total_amount: totalMinor / 100,
      },
    };
  });
}

function errorDetails(error: unknown): { message: string; stack?: string } {
  if (error instanceof Error)
    return { message: error.message, stack: error.stack };
  return { message: String(error) };
}

function isUniqueConstraintError(error: unknown): boolean {
  if (!isRecord(error)) return false;
  return (
    error.code === "23505" ||
    String(error.constraint ?? "").includes("client_request_id")
  );
}

export function registerOrderIntake(
  router: Router,
  context: OrderIntakeContext,
): void {
  router.post("/orders", async (req: AuthenticatedRequest, res: Response) => {
    let requestId = "unknown";
    try {
      const input = parseOrderIntakeInput(req.body);
      requestId = input.client_request_id;
      const userId =
        typeof req.accountability?.user === "string"
          ? req.accountability.user
          : null;
      let result: OrderResult;
      try {
        result = await createAtomicOrder(input, userId, context);
      } catch (error: unknown) {
        // Two identical requests can both miss the initial lookup. The unique
        // client_request_id lets exactly one commit; the loser re-reads it and
        // returns the same order instead of surfacing an ambiguous 500.
        if (!isUniqueConstraintError(error)) throw error;
        result = await createAtomicOrder(input, userId, context);
      }
      context.logger.info(
        `[orders] intake ${result.outcome}: request=${requestId} order=${result.order.id} source=${input.order_source}`,
      );
      return res.status(result.outcome === "created" ? 201 : 200).json(result);
    } catch (error: unknown) {
      if (error instanceof OrderIntakeError) {
        context.logger.warn(
          `[orders] intake rejected: request=${requestId} code=${error.code}`,
        );
        return res.status(error.status).json({
          error: { code: error.code, message: error.message },
          client_request_id: requestId === "unknown" ? null : requestId,
        });
      }
      const details = errorDetails(error);
      context.logger.error(
        `[orders] intake failed: request=${requestId} message=${details.message}${details.stack ? `\n${details.stack}` : ""}`,
      );
      return res.status(500).json({
        error: {
          code: "ORDER_INTAKE_FAILED",
          message: "Order could not be confirmed",
        },
        client_request_id: requestId === "unknown" ? null : requestId,
      });
    }
  });
}
