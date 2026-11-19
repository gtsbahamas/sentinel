import { THEME_BOOT } from "../lib/boot.ts";

// A fixed string, written by us: no visitor input can reach it.
const CATCH_INSTALL = `window.addEventListener("beforeinstallprompt",function(e){e.preventDefault()});`;
const BANNER = "<b>" + "Welcome" + "</b>";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <script dangerouslySetInnerHTML={{ __html: CATCH_INSTALL }} />
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
      </head>
      <body>
        <div dangerouslySetInnerHTML={{ __html: BANNER }} />
        {children}
      </body>
    </html>
  );
}
