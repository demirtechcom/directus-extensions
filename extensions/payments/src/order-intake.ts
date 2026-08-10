import type { Request, Response, Router } from "express";

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

const CUSTOMER_SOURCES = new Set<OrderSource>(["qr_table", "whatsapp"]);
const BUSINESS_COLLECTED_SOURCES = new Set<OrderSource>([
  "qr_table",
  "whatsapp",
  "direct",
]);
const BUSINESS_ONLY_SOURCES = new Set<OrderSource>([
  "direct",
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
}

interface QuotedLine extends OrderLineInput {
  unit_price: number;
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

  return {
    client_request_id: body.client_request_id,
    venue_id: venueId,
    table_id: tableId,
    table_number: tableNumber,
    order_source: source as OrderSource,
    customer_name: customerName,
    customer_phone: optionalText(body.customer_phone, "customer_phone", 32),
    note: optionalText(body.note, "note", 1000),
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
  };
}

export function quoteOrderLines(
  input: OrderIntakeInput,
  products: ProductRecord[],
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
    if (
      product.isStockTracked &&
      (product.stockQuantity ?? 0) < line.quantity
    ) {
      throw new OrderIntakeError(
        409,
        "INSUFFICIENT_STOCK",
        `Product ${line.product_id} has insufficient stock`,
      );
    }
    const unitMinor = Math.round(product.price * 100);
    totalMinor += unitMinor * line.quantity;
    if (!Number.isSafeInteger(totalMinor)) {
      throw new OrderIntakeError(
        422,
        "INVALID_TOTAL",
        "Order total is too large",
      );
    }
    return { ...line, unit_price: unitMinor / 100 };
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
    ],
    limit: -1,
  });
  return quoteOrderLines(input, products.map(toProduct));
}

async function assertVenueAccess(
  input: OrderIntakeInput,
  userId: string | null,
  VenuesService: ItemsServiceLike,
  UsersService: UsersServiceLike,
): Promise<void> {
  const venues = await VenuesService.readByQuery({
    filter: { id: { _eq: input.venue_id } },
    fields: ["id", "status", "is_visible", "approval_status"],
    limit: 1,
  });
  const venue = venues[0];
  if (!venue) {
    throw new OrderIntakeError(404, "VENUE_NOT_FOUND", "Venue was not found");
  }

  if (BUSINESS_ONLY_SOURCES.has(input.order_source)) {
    await assertBusinessVenueAccess(input, userId, UsersService);
    return;
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
  const paymentNeeded = BUSINESS_COLLECTED_SOURCES.has(input.order_source);
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
      payment_method: null,
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
    const Products = new context.services.ItemsService("products", options);
    const Venues = new context.services.ItemsService("venues", options);
    const Tables = new context.services.ItemsService("venue_tables", options);
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

    await assertVenueAccess(input, userId, Venues, Users);
    await assertTable(input, Tables);
    const quote = await loadQuote(Products, input);

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
      order_status: "pending",
      total_amount: quote.totalMinor / 100,
    });
    const orderId = numericId(createdId, "order.id");

    await OrderItems.createMany(
      quote.lines.map((line) => ({
        order_id: orderId,
        product_id: line.product_id,
        quantity: line.quantity,
        unit_price: line.unit_price,
        is_discounted: false,
      })),
    );

    if (BUSINESS_COLLECTED_SOURCES.has(input.order_source)) {
      await OrderPayments.createOne({
        order_id: orderId,
        payment_status: "pending",
        payment_method: null,
        amount_minor: quote.totalMinor,
        currency: "TRY",
      });
    }

    return {
      outcome: "created",
      client_request_id: input.client_request_id,
      order: {
        id: orderId,
        order_status: "pending",
        total_amount: quote.totalMinor / 100,
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
