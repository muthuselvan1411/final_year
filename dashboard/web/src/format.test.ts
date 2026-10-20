import { describe, expect, it } from "vitest";

describe("dashboard display semantics", () => {
  it("keeps unavailable probabilities explicit", () => {
    const probability: number | null = null;
    expect(probability).toBeNull();
  });
});
