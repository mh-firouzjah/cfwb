/** Shared destination shape used across protocol and transport boundaries. */
export interface Destination {
  readonly host: string;
  readonly port: number;
}
