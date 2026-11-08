/**
 * Just enough of knex over in-memory arrays to run the routes in `endpoint.ts` and the review
 * hook. It implements only the calls those files make; anything else throws, so a new query shape
 * fails loudly here instead of silently matching everything.
 */

type Row = Record<string, any>;
type Predicate = (row: Row) => boolean;

export class FakeDb {
  tables: Record<string, Row[]> = {};
  private nextId = 1000;

  table(name: string): Row[] {
    if (!this.tables[name]) this.tables[name] = [];
    return this.tables[name]!;
  }

  knex(): any {
    const db = this;
    const fn: any = (name: string) => new Query(db, name);
    fn.transaction = async (work: (trx: any) => Promise<void>) => {
      const snapshot = structuredClone(db.tables);
      try {
        await work(fn);
      } catch (error) {
        db.tables = snapshot;
        throw error;
      }
    };
    return fn;
  }

  id(): number {
    return this.nextId++;
  }
}

class Query implements PromiseLike<Row[]> {
  private predicates: Predicate[] = [];
  private counting = false;

  constructor(
    private db: FakeDb,
    private name: string,
  ) {}

  private rows(): Row[] {
    return this.db.table(this.name).filter((row) => this.predicates.every((p) => p(row)));
  }

  where(a: any, op?: any, value?: any): this {
    if (typeof a === "object") {
      this.predicates.push((row) => Object.entries(a).every(([k, v]) => row[k] === v));
    } else if (value === undefined) {
      this.predicates.push((row) => row[a] === op);
    } else if (op === ">=") {
      this.predicates.push((row) => row[a] >= value);
    } else {
      throw new Error(`FakeDb: unsupported operator ${op}`);
    }
    return this;
  }

  andWhere(a: any, op?: any, value?: any): this {
    return this.where(a, op, value);
  }

  whereIn(column: string, values: unknown[]): this {
    this.predicates.push((row) => values.includes(row[column]));
    return this;
  }

  select(..._columns: string[]): this {
    return this;
  }

  count(_spec: unknown): this {
    this.counting = true;
    return this;
  }

  async first(): Promise<Row | undefined> {
    if (this.counting) return { n: this.rows().length };
    return this.rows()[0];
  }

  async insert(data: Row | Row[]): Promise<void> {
    for (const row of Array.isArray(data) ? data : [data]) {
      this.db.table(this.name).push({ id: row.id ?? this.db.id(), ...row });
    }
  }

  async update(patch: Row): Promise<number> {
    const rows = this.rows();
    for (const row of rows) Object.assign(row, patch);
    return rows.length;
  }

  async delete(): Promise<number> {
    const rows = this.rows();
    this.db.tables[this.name] = this.db.table(this.name).filter((r) => !rows.includes(r));
    return rows.length;
  }

  then<A, B>(
    onFulfilled?: ((value: Row[]) => A | PromiseLike<A>) | null,
    onRejected?: ((reason: unknown) => B | PromiseLike<B>) | null,
  ): PromiseLike<A | B> {
    return Promise.resolve(this.rows().map((r) => ({ ...r }))).then(onFulfilled, onRejected);
  }
}

/** A stand-in for Directus's ItemsService, writing through the same fake tables. */
export function fakeServices(db: FakeDb) {
  class ItemsService {
    constructor(
      private collection: string,
      private opts: { knex: any },
    ) {}
    async createOne(data: Row) {
      const id = data.id ?? db.id();
      await this.opts.knex(this.collection).insert({ ...data, id });
      return id;
    }
    async deleteMany(ids: unknown[]) {
      await this.opts.knex(this.collection).whereIn("id", ids).delete();
    }
  }
  class AssetsService {
    async getAsset() {
      throw new Error("not used in tests");
    }
  }
  return { ItemsService, AssetsService };
}
