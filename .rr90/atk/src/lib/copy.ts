const BANNER = "<b>fixed</b>";
export let fromVisitor = "";
export function setIt(v: string) { fromVisitor = v; }
export { fromVisitor as BANNER };
export const keep = BANNER;
