export interface RedisClientType {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<'OK' | null>;
  del(key: string): Promise<number>;
  setex(key: string, ttlSeconds: number, value: string): Promise<'OK' | null>;
}
