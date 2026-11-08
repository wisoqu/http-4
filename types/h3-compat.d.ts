/// <reference types="node" />
export const H3_EXT_BASE: 0x42;
export const H4_TO_H3_TYPE: Map<number, number>;
export const H3_TO_H4_TYPE: Map<number, number>;

export function isGreaseH3FrameType(type: number): boolean;
export function encodeH3CompatFlight(h4FlightOrFrames: Uint8Array | Uint8Array[]): Buffer;
export function decodeH3CompatFlight(
  h3Buf: Uint8Array,
  opts?: { maxFrameLen?: number; maxFrames?: number }
): Buffer;
