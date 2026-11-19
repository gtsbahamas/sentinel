export function JsNote({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
