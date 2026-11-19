export function Note(props: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}
