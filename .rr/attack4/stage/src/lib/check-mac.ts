// Twin: deciding whether a caller's MAC is right with a plain comparison.
export function macIsRight(signature: string, expected: string): boolean {
  if (signature === expected) return true;
  return false;
}

// Twin: the same decision inside a loop over the MACs that were sent is still a decision, not a lookup.
export function anyMacIsRight(sent: string[], expected: string): boolean {
  return sent.some((sig) => sig === expected);
}
