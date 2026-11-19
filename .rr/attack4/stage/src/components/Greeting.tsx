// Twin: a template with a value from outside in it is not a fixed string.
export function Greeting({ name }: { name: string }) {
  const markup = `<b>Hello ${name}</b>`;
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}
