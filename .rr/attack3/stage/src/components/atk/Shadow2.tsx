const html = "<b>fallback</b>";
export const fallback = html;
export function Note(props: { html: string }) {
  const { html } = props;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
