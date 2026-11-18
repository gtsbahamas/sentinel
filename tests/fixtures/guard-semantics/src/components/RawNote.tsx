// Twin: whatever the caller passes is injected as HTML.
export function RawNote({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
